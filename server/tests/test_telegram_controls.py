from datetime import UTC, datetime, timedelta

import httpx
import pytest
from pydantic import SecretStr

from app.core.config import get_settings
from app.models import Alert, Command, Notification
from app.models.telegram import TelegramAction, TelegramCursor
from app.notify.telegram import (
    TelegramAPI,
    TelegramError,
    handle_callback,
    keyboard_for_jobs,
    poll_once,
)
from app.services import commands
from tests.conftest import enroll
from tests.test_ingest import make_event, upload


class FakeAPI:
    def __init__(self):
        self.settings = get_settings()
        self.settings.telegram_controls_enabled = True
        self.settings.telegram_allowed_user_ids = [123, 456]
        self.settings.telegram_chat_id = "-10042"
        self.settings.telegram_bot_token = SecretStr("test-token")
        self.calls = []
        self.updates = []
        self.fail_answer = False

    async def call(self, method, payload):
        self.calls.append((method, payload))
        if method == "getUpdates":
            return self.updates
        if method == "answerCallbackQuery" and self.fail_answer:
            raise TelegramError("Simulated lost acknowledgement")
        return True


async def prepare(api, fake):
    creds = await enroll(api)
    event = make_event(
        1,
        action="process_started",
        data={
            "pid": 45678,
            "name": "powershell.exe",
            "exe": r"C:\Lab\powershell.exe",
            "command_line": "powershell -enc ZGVtbw==",
            "create_time": datetime.now(UTC).isoformat(),
        },
    )
    assert (await upload(api, creds, [event])).status_code == 200
    alert = await Alert.find_one(Alert.device_id == creds["device_id"])
    job = await Notification.get_pymongo_collection().find_one(
        {"alert_id": alert.alert_id, "channel": "telegram"}
    )
    markup = await keyboard_for_jobs([job], fake.settings)
    return creds, alert, job, markup


def callback(action, stage="", user=123, chat="-10042", markup=None):
    return {
        "id": "callback-query-test",
        "from": {"id": user, "is_bot": False},
        "message": {
            "message_id": 42,
            "chat": {"id": chat},
            "reply_markup": markup
            or {
                "inline_keyboard": [
                    [{"text": action.label, "callback_data": "st:" + action.callback_id}]
                ]
            },
        },
        "data": "st:" + action.callback_id + (":" + stage if stage else ""),
    }


async def get_action(name):
    return await TelegramAction.find_one(TelegramAction.action == name)


async def test_buttons_are_opt_in_bounded_and_reused_after_delivery_retry(api):
    fake = FakeAPI()
    _, _, job, markup = await prepare(api, fake)
    assert markup == await keyboard_for_jobs([job], fake.settings)
    assert await TelegramAction.count() == 3
    buttons = [b for row in markup["inline_keyboard"] for b in row]
    assert any(b["text"].startswith("Kill PID") for b in buttons)
    assert all(len(b["callback_data"].encode()) <= 64 for b in buttons if "callback_data" in b)
    fake.settings.telegram_controls_enabled = False
    assert await keyboard_for_jobs([job], fake.settings) is None
    fake.settings.telegram_controls_enabled = True
    fake.settings.telegram_allowed_user_ids = []
    assert await keyboard_for_jobs([job], fake.settings) is None


@pytest.mark.parametrize(("user", "chat"), [(999, "-10042"), (123, "other-chat"), (True, "-10042")])
async def test_unapproved_operator_or_chat_cannot_act(api, user, chat):
    fake = FakeAPI()
    await prepare(api, fake)
    action = await get_action("lock_workstation")
    await handle_callback(callback(action, user=user, chat=chat), fake)
    assert await Command.count() == 0
    assert "not authorized" in fake.calls[-1][1]["text"]
    assert (await get_action("lock_workstation")).confirm_until is None


async def test_lock_requires_same_operator_confirmation_and_executes_once(api):
    fake = FakeAPI()
    _, alert, _, _ = await prepare(api, fake)
    action = await get_action("lock_workstation")
    await handle_callback(callback(action, "yes"), fake)
    assert await Command.count() == 0
    await handle_callback(callback(action), fake)
    assert await Command.count() == 0
    assert any(method == "editMessageReplyMarkup" for method, _ in fake.calls)
    await handle_callback(callback(action, "yes", user=456), fake)
    assert await Command.count() == 0
    await handle_callback(callback(action, "yes"), fake)
    await handle_callback(callback(action, "yes"), fake)
    assert await Command.count() == 1
    command = await Command.find_one({})
    assert command.actor == "telegram:123" and command.alert_id == alert.alert_id


async def test_kill_target_comes_from_evidence_not_callback_parameters(api):
    fake = FakeAPI()
    creds, _, _, _ = await prepare(api, fake)
    action = await get_action("kill_process")
    await handle_callback(callback(action), fake)
    await handle_callback(callback(action, "yes"), fake)
    command = await Command.find_one({})
    assert command.action == "kill_process" and command.params["pid"] == 45678
    assert command.device_id == creds["device_id"] and command.source_event_id == action.event_id


async def test_cancel_expired_confirmation_and_expired_button_are_safe(api):
    fake = FakeAPI()
    await prepare(api, fake)
    action = await get_action("lock_workstation")
    await handle_callback(callback(action), fake)
    await handle_callback(callback(action, "no"), fake)
    await handle_callback(callback(action, "yes"), fake)
    assert await Command.count() == 0
    await handle_callback(callback(action), fake)
    await TelegramAction.get_pymongo_collection().update_one(
        {"callback_id": action.callback_id},
        {"$set": {"confirm_until": datetime.now(UTC) - timedelta(seconds=1)}},
    )
    await handle_callback(callback(action, "yes"), fake)
    assert await Command.count() == 0
    await TelegramAction.get_pymongo_collection().update_one(
        {"callback_id": action.callback_id},
        {"$set": {"expires_at": datetime.now(UTC) - timedelta(seconds=1)}},
    )
    await handle_callback(callback(action), fake)
    assert "expired" in fake.calls[-1][1]["text"]


async def test_digest_keyboard_keeps_other_actions_and_restores_cancelled_button(api):
    fake = FakeAPI()
    _, _, first_job, _ = await prepare(api, fake)
    _, _, second_job, _ = await prepare(api, fake)
    markup = await keyboard_for_jobs([first_job, second_job], fake.settings)
    actions = await TelegramAction.find(TelegramAction.action == "lock_workstation").to_list()
    first, second = actions
    original_ids = {
        button["callback_data"]
        for row in markup["inline_keyboard"]
        for button in row
        if "callback_data" in button
    }
    await handle_callback(callback(first, markup=markup), fake)
    first_keyboard = fake.calls[-2][1]["reply_markup"]
    assert len(first_keyboard["inline_keyboard"]) == len(markup["inline_keyboard"])
    assert any(
        button.get("callback_data") == "st:" + first.callback_id + ":yes"
        for row in first_keyboard["inline_keyboard"]
        for button in row
    )
    # Telegram can supply an older message. Refresh every action from persisted state.
    await handle_callback(callback(second, user=456, markup=markup), fake)
    second_keyboard = fake.calls[-2][1]["reply_markup"]
    confirmations = {
        button.get("callback_data")
        for row in second_keyboard["inline_keyboard"]
        for button in row
        if str(button.get("callback_data", "")).endswith(":yes")
    }
    assert confirmations == {
        "st:" + first.callback_id + ":yes",
        "st:" + second.callback_id + ":yes",
    }
    await handle_callback(callback(first, "no", markup=first_keyboard), fake)
    restored = fake.calls[-2][1]["reply_markup"]
    restored_ids = {
        button["callback_data"].removesuffix(":yes").removesuffix(":no")
        for row in restored["inline_keyboard"]
        for button in row
        if "callback_data" in button
    }
    assert restored_ids == original_ids
    assert any(
        button.get("callback_data") == "st:" + first.callback_id
        for row in restored["inline_keyboard"]
        for button in row
    )
    assert any(
        button.get("callback_data") == "st:" + second.callback_id + ":yes"
        for row in restored["inline_keyboard"]
        for button in row
    )
    assert await Command.count() == 0


async def test_another_operator_cannot_replace_or_cancel_pending_confirmation(api):
    fake = FakeAPI()
    await prepare(api, fake)
    action = await get_action("lock_workstation")
    await handle_callback(callback(action), fake)
    await handle_callback(callback(action, user=456), fake)
    assert "Another operator" in fake.calls[-1][1]["text"]
    await handle_callback(callback(action, "no", user=456), fake)
    assert "another operator" in fake.calls[-1][1]["text"]
    assert (await get_action("lock_workstation")).confirm_user_id == 123
    await handle_callback(callback(action, "yes"), fake)
    assert await Command.count() == 1


async def test_inaccessible_message_cannot_arm_confirmation(api):
    fake = FakeAPI()
    await prepare(api, fake)
    action = await get_action("lock_workstation")
    update = callback(action)
    del update["message"]["reply_markup"]
    await handle_callback(update, fake)
    assert "Unable to show confirmation" in fake.calls[-1][1]["text"]
    assert (await get_action("lock_workstation")).confirm_until is None
    await handle_callback(callback(action, "yes"), fake)
    assert await Command.count() == 0


async def test_acknowledge_is_audited_once_and_never_reopens_closed_alert(api):
    fake = FakeAPI()
    _, alert, _, _ = await prepare(api, fake)
    action = await get_action("acknowledge")
    await handle_callback(callback(action), fake)
    await handle_callback(callback(action), fake)
    alert = await Alert.find_one(Alert.alert_id == alert.alert_id)
    assert alert.status == "acknowledged"
    assert len(alert.history) == 1 and alert.history[0]["actor"] == "telegram:123"
    await alert.set({Alert.status: "resolved"})
    await handle_callback(callback(action), fake)
    assert (await Alert.find_one(Alert.alert_id == alert.alert_id)).status == "resolved"
    lock = await get_action("lock_workstation")
    await handle_callback(callback(lock), fake)
    await handle_callback(callback(lock, "yes"), fake)
    assert await Command.count() == 0


async def test_lost_ack_replays_result_without_repeating_command_and_offset_is_durable(api):
    fake = FakeAPI()
    await prepare(api, fake)
    action = await get_action("lock_workstation")
    await handle_callback(callback(action), fake)
    fake.updates = [{"update_id": 100, "callback_query": callback(action, "yes")}]
    fake.fail_answer = True
    with pytest.raises(TelegramError):
        await poll_once(fake)
    assert await Command.count() == 1 and await TelegramCursor.count() == 0
    fake.fail_answer = False
    assert await poll_once(fake) == 1
    assert await Command.count() == 1
    assert (await TelegramCursor.find_one({})).offset == 101
    fake.updates = []
    await poll_once(fake)
    assert fake.calls[-1][1]["offset"] == 101


async def test_crash_after_queue_insertion_recovers_result_after_confirmation_expires(
    api, monkeypatch
):
    fake = FakeAPI()
    await prepare(api, fake)
    action = await get_action("lock_workstation")
    await handle_callback(callback(action), fake)

    async def interrupted_queue(*args, **kwargs):
        await commands.queue_command(*args, **kwargs)
        raise RuntimeError("Simulated interruption after command insert")

    monkeypatch.setattr("app.notify.telegram.queue_command", interrupted_queue)
    with pytest.raises(RuntimeError):
        await handle_callback(callback(action, "yes"), fake)
    assert await Command.count() == 1
    assert (await get_action("lock_workstation")).result is None
    await TelegramAction.get_pymongo_collection().update_one(
        {"callback_id": action.callback_id},
        {"$set": {"confirm_until": datetime.now(UTC) - timedelta(seconds=1)}},
    )
    await handle_callback(callback(action, "yes"), fake)
    assert await Command.count() == 1
    assert (await get_action("lock_workstation")).result.startswith("Queued cmd_")


async def test_telegram_adapter_uses_mock_http_and_redacts_errors():
    settings = get_settings()
    settings.telegram_bot_token = SecretStr("private-test-token")
    seen = []

    def handle(request):
        seen.append(request)
        return httpx.Response(200, json={"ok": True, "result": []})

    adapter = TelegramAPI(settings, httpx.MockTransport(handle))
    assert await adapter.call("getUpdates", {"offset": 1}) == []
    assert seen[0].url.path.endswith("/getUpdates")

    def fail(request):
        raise httpx.ConnectError("private-test-token")

    with pytest.raises(TelegramError) as error:
        await TelegramAPI(settings, httpx.MockTransport(fail)).call("getUpdates", {})
    assert "private-test-token" not in str(error.value)


@pytest.mark.parametrize(
    "payload", [[1], None, "not-an-object", {"ok": False, "error_code": "bad"}]
)
async def test_malformed_api_response_raises_sanitized_error(payload):
    settings = get_settings()
    settings.telegram_bot_token = SecretStr("private-test-token")
    adapter = TelegramAPI(
        settings, httpx.MockTransport(lambda request: httpx.Response(502, json=payload))
    )
    with pytest.raises(TelegramError) as error:
        await adapter.call("getUpdates", {})
    assert "private-test-token" not in str(error.value)


async def test_malformed_updates_do_not_block_valid_update_cursor(api):
    fake = FakeAPI()
    fake.updates = [
        None,
        "bad",
        {"update_id": True},
        {"update_id": 101, "callback_query": "bad"},
        {"update_id": 102, "callback_query": {"id": "bad-sender", "from": [123]}},
        {"update_id": 103, "callback_query": {"id": "bad-chat", "message": {"chat": []}}},
    ]
    assert await poll_once(fake) == 3
    assert (await TelegramCursor.find_one({})).offset == 104


async def test_replayed_keyboard_edit_is_successful_when_markup_already_matches():
    settings = get_settings()
    settings.telegram_bot_token = SecretStr("private-test-token")
    adapter = TelegramAPI(
        settings,
        httpx.MockTransport(
            lambda request: httpx.Response(
                400,
                json={
                    "ok": False,
                    "error_code": 400,
                    "description": "Bad Request: message is not modified: same reply markup",
                },
            )
        ),
    )
    assert await adapter.call("editMessageReplyMarkup", {}) is True
    with pytest.raises(TelegramError):
        await adapter.call("answerCallbackQuery", {})
