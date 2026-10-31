"""Opt-in Telegram controls: allowlisted chat AND operator, expiring buttons, confirmation."""

import asyncio
import hashlib
import logging
import re
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import httpx
from pymongo import ReturnDocument

from app.core.config import Settings, get_settings
from app.core.locks import device_lock
from app.models import Alert, Command, Device, Event
from app.models.telegram import TelegramAction, TelegramCursor
from app.services.commands import process_target, queue_command
from app.services.triage import change_alert

log = logging.getLogger(__name__)


class TelegramError(Exception):
    def __init__(self, message: str, retryable: bool = True):
        super().__init__(message)
        self.retryable = retryable


class TelegramAPI:
    def __init__(self, settings: Settings, transport=None):
        self.settings, self.transport = settings, transport

    async def call(self, method: str, payload: dict):
        # Never log a bot URL, payload, raw HTTP error or credential.
        logging.getLogger("httpx").setLevel(logging.WARNING)
        token = self.settings.telegram_bot_token.get_secret_value()
        if not token:
            raise TelegramError("Telegram credentials are not configured", retryable=False)
        try:
            async with httpx.AsyncClient(timeout=25, transport=self.transport) as client:
                response = await client.post(
                    f"https://api.telegram.org/bot{token}/{method}", json=payload
                )
            data = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise TelegramError("Telegram transport or response error") from exc
        if not isinstance(data, dict):
            raise TelegramError("Telegram returned an invalid response")
        if response.is_error or not data.get("ok"):
            code = data.get("error_code", response.status_code)
            if type(code) is not int:
                code = response.status_code
            if (
                method == "editMessageReplyMarkup"
                and code == 400
                and str(data.get("description", "")).startswith(
                    "Bad Request: message is not modified"
                )
            ):
                return True  # A replay after a lost response already has the requested keyboard.
            raise TelegramError(
                f"Telegram rejected request ({code})", retryable=code == 429 or code >= 500
            )
        return data.get("result")


async def keyboard_for_jobs(jobs: list[dict], settings: Settings) -> dict | None:
    if not (
        settings.telegram_controls_enabled
        and settings.telegram_allowed_user_ids
        and settings.telegram_chat_id
    ):
        return None
    keyboard = []
    for job in jobs:
        alert = await Alert.find_one(Alert.alert_id == job["alert_id"])
        if alert is None:
            continue
        device = await Device.find_one(Device.device_id == alert.device_id)
        actions = [("acknowledge", "Acknowledge", None)]
        if device and device.os == "windows":
            actions.append(("lock_workstation", "Lock PC", None))
            evidence = (
                Event.get_pymongo_collection()
                .find(
                    {
                        "device_id": alert.device_id,
                        "event_id": {"$in": alert.event_ids},
                        "category": "process",
                        "action": "process_started",
                    }
                )
                .sort("ts", -1)
            )
            async for event in evidence:
                try:
                    process_target(event)
                except ValueError:
                    continue
                actions.append(
                    ("kill_process", f"Kill PID {event['data']['pid']}", event["event_id"])
                )
                break
        buttons = []
        for action, label, event_id in actions:
            row = await TelegramAction.get_pymongo_collection().find_one_and_update(
                {"key": job["notification_id"] + ":" + action},
                {
                    "$setOnInsert": {
                        "callback_id": uuid4().hex,
                        "chat_id": settings.telegram_chat_id,
                        "alert_id": alert.alert_id,
                        "device_id": alert.device_id,
                        "event_id": event_id,
                        "action": action,
                        "label": label,
                        "expires_at": datetime.now(UTC)
                        + timedelta(minutes=settings.telegram_button_minutes),
                        "confirm_user_id": None,
                        "confirm_until": None,
                        "result": None,
                        "used_at": None,
                    }
                },
                upsert=True,
                return_document=ReturnDocument.AFTER,
            )
            # Retries retain the original evidence target and its matching label.
            buttons.append({"text": row["label"], "callback_data": "st:" + row["callback_id"]})
        keyboard.append(
            [
                {
                    "text": alert.rule_id + " · View alert",
                    "url": settings.public_url.rstrip("/") + "/#/alerts/" + alert.alert_id,
                }
            ]
        )
        keyboard.append(buttons)
    return {"inline_keyboard": keyboard} if keyboard else None


async def _answer(api: TelegramAPI, callback_id: str, text: str) -> None:
    try:
        await api.call(
            "answerCallbackQuery", {"callback_query_id": callback_id, "text": text[:190]}
        )
    except TelegramError as exc:
        if exc.retryable:
            raise
        # Telegram expires callback acknowledgements. Do not block the update cursor forever.
        log.info("Telegram callback acknowledgement expired or was rejected")


async def _refresh_keyboard(api: TelegramAPI, message: dict, action: TelegramAction) -> bool:
    """Rebuild this message's buttons from persisted state, keeping every digest row.

    Callback messages can contain an older keyboard. Looking up every action keeps a
    second operator's pending confirmation intact when another button is cancelled.
    Labels, targets and links come from our records, never callback-supplied data.
    """
    markup = message.get("reply_markup")
    source = markup.get("inline_keyboard") if isinstance(markup, dict) else None
    if not isinstance(source, list) or type(message.get("message_id")) is not int:
        return False
    callback_ids = set()
    for row in source[:100]:
        if not isinstance(row, list):
            continue
        for button in row[:8]:
            if not isinstance(button, dict):
                continue
            match = re.fullmatch(
                r"st:([a-f0-9]{32})(?::(?:yes|no))?", str(button.get("callback_data", ""))
            )
            if match:
                callback_ids.add(match[1])
    if action.callback_id not in callback_ids:
        return False
    records = {
        row.callback_id: row
        for row in await TelegramAction.find(
            {"callback_id": {"$in": list(callback_ids)}, "chat_id": action.chat_id}
        ).to_list()
    }
    alerts = {
        row.alert_id: row
        for row in await Alert.find(
            {"alert_id": {"$in": list({item.alert_id for item in records.values()})}}
        ).to_list()
    }
    links = {
        api.settings.public_url.rstrip("/") + "/#/alerts/" + row.alert_id: row
        for row in alerts.values()
    }
    keyboard, emitted = [], set()
    now = datetime.now(UTC)
    for row in source[:100]:
        if not isinstance(row, list):
            continue
        buttons = []
        for button in row[:8]:
            if not isinstance(button, dict):
                continue
            url = button.get("url")
            if isinstance(url, str) and url in links:
                buttons.append({"text": links[url].rule_id + " · View alert", "url": url})
                continue
            match = re.fullmatch(
                r"st:([a-f0-9]{32})(?::(?:yes|no))?", str(button.get("callback_data", ""))
            )
            item = records.get(match[1]) if match else None
            if item is None or item.callback_id in emitted:
                continue
            emitted.add(item.callback_id)
            data = "st:" + item.callback_id
            if item.expires_at <= now:
                buttons.append({"text": "Expired · " + item.label, "callback_data": data})
            elif item.result:
                buttons.append({"text": "✓ " + item.label, "callback_data": data})
            elif item.confirm_until and item.confirm_until > now:
                buttons.extend(
                    [
                        {"text": "Confirm " + item.label, "callback_data": data + ":yes"},
                        {"text": "Cancel", "callback_data": data + ":no"},
                    ]
                )
            else:
                buttons.append({"text": item.label, "callback_data": data})
        # Keep rows compact when multiple actions await confirmation.
        keyboard.extend(buttons[start : start + 8] for start in range(0, len(buttons), 8))
    try:
        await api.call(
            "editMessageReplyMarkup",
            {
                "chat_id": action.chat_id,
                "message_id": message["message_id"],
                "reply_markup": {"inline_keyboard": keyboard},
            },
        )
    except TelegramError as exc:
        if exc.retryable:
            raise
        # Deleted/inaccessible messages cannot be edited; the result stays durable.
        log.info("Telegram keyboard could not be updated")
        return False
    return True


async def handle_callback(callback: dict, api: TelegramAPI) -> None:
    if not isinstance(callback, dict):
        return
    settings = api.settings
    query_id = callback.get("id")
    if not isinstance(query_id, str):
        return
    sender = callback.get("from") or {}
    message = callback.get("message") or {}
    if not isinstance(sender, dict) or not isinstance(message, dict):
        await _answer(api, query_id, "Unknown action.")
        return
    chat = message.get("chat") or {}
    user_id = sender.get("id")
    chat_id = str(chat.get("id", "")) if isinstance(chat, dict) else ""
    if (
        not settings.telegram_controls_enabled
        or sender.get("is_bot")
        or type(user_id) is not int
        or user_id not in settings.telegram_allowed_user_ids
        or chat_id != settings.telegram_chat_id
    ):
        await _answer(api, query_id, "This operator or chat is not authorized.")
        return
    match = re.fullmatch(r"st:([a-f0-9]{32})(?::(yes|no))?", str(callback.get("data", "")))
    if not match:
        await _answer(api, query_id, "Unknown action.")
        return
    callback_id, stage = match.groups()
    async with device_lock("telegram:" + callback_id):
        action = await TelegramAction.find_one(TelegramAction.callback_id == callback_id)
        now = datetime.now(UTC)
        if action is None or action.chat_id != chat_id or action.expires_at <= now:
            await _answer(api, query_id, "This button expired. Open the dashboard to continue.")
            return
        if action.result:
            await _refresh_keyboard(api, message, action)
            await _answer(api, query_id, action.result)
            return
        command_id = "cmd_" + hashlib.sha256(callback_id.encode()).hexdigest()[:32]
        existing = (
            await Command.find_one(Command.command_id == command_id)
            if action.action != "acknowledge"
            else None
        )
        if existing:
            # A crash may happen after insertion and before recording the button result.
            # Recover the committed outcome even after the confirmation window elapsed.
            result = f"Queued {existing.command_id}. Track the endpoint result in the dashboard."
            await action.set(
                {
                    TelegramAction.result: result,
                    TelegramAction.used_at: existing.created_at,
                    TelegramAction.confirm_user_id: None,
                    TelegramAction.confirm_until: None,
                }
            )
            await _refresh_keyboard(api, message, action)
            await _answer(api, query_id, result)
            return
        actor = f"telegram:{user_id}"
        if action.action == "acknowledge":
            try:
                await change_alert(
                    action.alert_id,
                    actor,
                    status="acknowledged",
                    key="telegram:" + callback_id,
                    only_new=True,
                )
            except ValueError:
                await _answer(api, query_id, "Alert is unavailable.")
                return
            result = "Alert reviewed; its current triage state is preserved."
        elif stage == "no":
            if action.confirm_user_id not in {None, user_id}:
                await _answer(api, query_id, "This confirmation belongs to another operator.")
                return
            await action.set(
                {TelegramAction.confirm_user_id: None, TelegramAction.confirm_until: None}
            )
            await _refresh_keyboard(api, message, action)
            await _answer(api, query_id, "Cancelled. No command was queued.")
            return
        elif stage != "yes":
            if (
                action.confirm_user_id not in {None, user_id}
                and action.confirm_until
                and action.confirm_until > now
            ):
                await _answer(api, query_id, "Another operator is confirming this action.")
                return
            await action.set(
                {
                    TelegramAction.confirm_user_id: user_id,
                    TelegramAction.confirm_until: now + timedelta(seconds=60),
                }
            )
            if not await _refresh_keyboard(api, message, action):
                await action.set(
                    {TelegramAction.confirm_user_id: None, TelegramAction.confirm_until: None}
                )
                await _answer(api, query_id, "Unable to show confirmation. Open the dashboard.")
                return
            await _answer(api, query_id, "Confirm this endpoint action within 60 seconds.")
            return
        else:
            if (
                action.confirm_user_id != user_id
                or action.confirm_until is None
                or action.confirm_until <= now
            ):
                await _answer(api, query_id, "Confirmation expired or belongs to another operator.")
                return
            alert = await Alert.find_one(Alert.alert_id == action.alert_id)
            if alert is None or alert.status in {"resolved", "false_positive"}:
                await action.set(
                    {TelegramAction.confirm_user_id: None, TelegramAction.confirm_until: None}
                )
                await _refresh_keyboard(api, message, action)
                await _answer(api, query_id, "This alert is closed. Review it in the dashboard.")
                return
            try:
                command = await queue_command(
                    action.device_id,
                    action.action,
                    actor=actor,
                    reason=f"Telegram confirmation for alert {action.alert_id}",
                    event_id=action.event_id,
                    alert_id=action.alert_id,
                    command_id=command_id,
                )
            except ValueError:
                await _answer(api, query_id, "Command target is no longer valid. Review the alert.")
                return
            result = f"Queued {command.command_id}. Track the endpoint result in the dashboard."
        await action.set(
            {
                TelegramAction.result: result,
                TelegramAction.used_at: now,
                TelegramAction.confirm_user_id: None,
                TelegramAction.confirm_until: None,
            }
        )
        await _refresh_keyboard(api, message, action)
        await _answer(api, query_id, result)


async def poll_once(api: TelegramAPI) -> int:
    bot_key = hashlib.sha256(
        api.settings.telegram_bot_token.get_secret_value().encode()
    ).hexdigest()
    collection = TelegramCursor.get_pymongo_collection()
    row = await collection.find_one({"bot_key": bot_key})
    updates = await api.call(
        "getUpdates",
        {
            "offset": row["offset"] if row else 0,
            "timeout": 15,
            "allowed_updates": ["callback_query"],
            "limit": 100,
        },
    )
    if not isinstance(updates, list):
        raise TelegramError("Telegram returned an invalid update list")
    processed = 0
    for update in updates:
        if not isinstance(update, dict) or type(update.get("update_id")) is not int:
            continue
        if callback := update.get("callback_query"):
            try:
                await handle_callback(callback, api)
            except TelegramError as exc:
                if exc.retryable:
                    raise
                log.warning("Telegram callback operation rejected; no automatic replay")
        await collection.update_one(
            {"bot_key": bot_key}, {"$max": {"offset": update["update_id"] + 1}}, upsert=True
        )
        processed += 1
    return processed


async def telegram_loop(stop: asyncio.Event) -> None:
    api = TelegramAPI(get_settings())
    if not (
        api.settings.telegram_bot_token.get_secret_value()
        and api.settings.telegram_chat_id
        and api.settings.telegram_allowed_user_ids
    ):
        log.warning("Telegram controls need a bot token, chat ID and operator allowlist")
        return
    while not stop.is_set():
        try:
            await poll_once(api)
        except Exception as exc:
            log.warning("Telegram polling failed (%s); saved offset retained", type(exc).__name__)
        try:
            await asyncio.wait_for(stop.wait(), timeout=1)
        except TimeoutError:
            pass
