"""Retryable outbox with per-device/channel rate limits and batched digests.

Delivery is at least once: an interrupted acknowledgement after a successful external
send can produce a duplicate. Alert counts and outbox creation remain idempotent.
"""

import asyncio
import logging
import smtplib
import ssl
import uuid
from datetime import UTC, datetime, timedelta
from email.message import EmailMessage

import httpx
from pymongo import ReturnDocument

from app.core.config import Settings, get_settings
from app.forensics.chain import truncate_to_ms
from app.models import Alert, Device, Notification
from app.notify.telegram import keyboard_for_jobs

log = logging.getLogger(__name__)


class UnconfiguredError(Exception):
    pass


class DeliveryError(Exception):
    pass


class NotificationSender:
    def __init__(self, settings: Settings, transport=None):
        self.settings = settings
        self.transport = transport

    async def send(self, channel: str, text: str, *, reply_markup: dict | None = None) -> None:
        settings = self.settings
        if channel == "telegram":
            token = settings.telegram_bot_token.get_secret_value()
            if not token or not settings.telegram_chat_id:
                raise UnconfiguredError("Telegram bot token and destination chat ID are required")
            # HTTPX INFO logs include the bot token in the URL.
            logging.getLogger("httpx").setLevel(logging.WARNING)
            async with httpx.AsyncClient(timeout=15, transport=self.transport) as client:
                response = await client.post(
                    f"https://api.telegram.org/bot{token}/sendMessage",
                    json={
                        "chat_id": settings.telegram_chat_id,
                        "text": text[:3800],
                        **({"reply_markup": reply_markup} if reply_markup else {}),
                    },
                )
            if response.is_error:
                raise DeliveryError(f"Telegram returned HTTP {response.status_code}")
            if not response.json().get("ok"):
                raise DeliveryError("Telegram did not acknowledge the message")
        elif channel == "email":
            await asyncio.to_thread(self._email, text)
        else:
            raise ValueError("Unknown notification channel")

    def _email(self, text: str) -> None:
        settings = self.settings
        if not (settings.smtp_host and settings.smtp_from and settings.smtp_to):
            raise UnconfiguredError("SMTP host, sender and recipient are required")
        if not settings.smtp_ssl and not settings.smtp_starttls:
            raise UnconfiguredError("Configure SMTP TLS or STARTTLS")
        message = EmailMessage()
        message["Subject"] = "ShadowTrace security alert"
        message["From"] = settings.smtp_from
        message["To"] = settings.smtp_to
        message.set_content(text)
        context = ssl.create_default_context()
        if settings.smtp_ssl:
            connection = smtplib.SMTP_SSL(
                settings.smtp_host,
                settings.smtp_port,
                timeout=15,
                context=context,
            )
        else:
            connection = smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=15)
        with connection as smtp:
            if not settings.smtp_ssl:
                smtp.starttls(context=context)
            if settings.smtp_username:
                smtp.login(settings.smtp_username, settings.smtp_password.get_secret_value())
            smtp.send_message(message)


def _eligible(now: datetime) -> dict:
    return {
        "$or": [
            {"status": "pending", "next_attempt_at": {"$lte": now}},
            {"status": "sending", "lease_until": {"$lte": now}},
        ]
    }


async def _message(jobs: list[dict]) -> str:
    device = await Device.find_one(Device.device_id == jobs[0]["device_id"])
    hostname = device.hostname if device else jobs[0]["device_id"]
    lines = [f"ShadowTrace — {hostname}", f"Device: {jobs[0]['device_id']}"]
    if len(jobs) > 1:
        lines.append(f"Digest: {len(jobs)} alerts")
    for job in jobs:
        alert = await Alert.find_one(Alert.alert_id == job["alert_id"])
        if alert is None:
            lines.append(f"Alert {job['alert_id']} is no longer available")
            continue
        lines.extend(
            [
                "",
                f"[{alert.severity.upper()}] {alert.title[:150]}",
                f"{alert.rule_id} | occurrences: {alert.occurrence_count}",
                f"Time: {alert.last_event_at:%Y-%m-%d %H:%M:%S} UTC",
                f"Alert: {alert.alert_id}",
            ]
        )
    return "\n".join(lines)


async def dispatch_once(
    sender: NotificationSender | None = None, now: datetime | None = None
) -> int:
    settings = get_settings()
    if not settings.notifications_enabled:
        return 0
    now = truncate_to_ms(now or datetime.now(UTC))
    collection = Notification.get_pymongo_collection()
    first = await collection.find_one(_eligible(now), sort=[("created_at", 1)])
    if first is None:
        return 0
    scope = {"device_id": first["device_id"], "channel": first["channel"]}
    sent = collection.find(
        {
            **scope,
            "status": "sent",
            "sent_at": {"$gt": now - timedelta(minutes=1)},
        }
    )
    deliveries = {}
    async for row in sent:
        deliveries[row["delivery_id"]] = row["sent_at"]
    if len(deliveries) >= settings.notifications_per_minute:
        retry_at = min(deliveries.values()) + timedelta(minutes=1)
        await collection.update_many(
            {**scope, **_eligible(now)},
            {
                "$set": {
                    "status": "pending",
                    "next_attempt_at": retry_at,
                    "lease_until": None,
                }
            },
        )
        return 0

    pending = collection.find({**scope, **_eligible(now)}).sort("created_at", 1).limit(10)
    jobs = []
    async for candidate in pending:
        claimed = await collection.find_one_and_update(
            {"_id": candidate["_id"], **_eligible(now)},
            {
                "$set": {"status": "sending", "lease_until": now + timedelta(minutes=2)},
                "$inc": {"attempts": 1},
            },
            return_document=ReturnDocument.AFTER,
        )
        if claimed:
            jobs.append(claimed)
    if not jobs:
        return 0
    try:
        delivery_sender = sender or NotificationSender(settings)
        markup = await keyboard_for_jobs(jobs, settings) if first["channel"] == "telegram" else None
        if markup:
            await delivery_sender.send(first["channel"], await _message(jobs), reply_markup=markup)
        else:
            await delivery_sender.send(first["channel"], await _message(jobs))
    except Exception as exc:
        # Never persist raw HTTP/SMTP exceptions: URLs can contain credentials.
        detail = (
            str(exc) if isinstance(exc, (UnconfiguredError, DeliveryError)) else type(exc).__name__
        )
        for job in jobs:
            if isinstance(exc, UnconfiguredError):
                status = "unconfigured"
            else:
                status = (
                    "failed" if job["attempts"] >= settings.notification_max_attempts else "pending"
                )
            await collection.update_one(
                {"_id": job["_id"]},
                {
                    "$set": {
                        "status": status,
                        "last_error": detail,
                        "lease_until": None,
                        "next_attempt_at": now + timedelta(seconds=min(300, 2 ** job["attempts"])),
                    }
                },
            )
        log.warning("%s delivery deferred or failed: %s", first["channel"], detail)
        return 0
    delivery_id = uuid.uuid4().hex
    await collection.update_many(
        {"_id": {"$in": [job["_id"] for job in jobs]}},
        {
            "$set": {
                "status": "sent",
                "sent_at": now,
                "delivery_id": delivery_id,
                "last_error": None,
                "lease_until": None,
            }
        },
    )
    return len(jobs)


async def notification_loop(stop: asyncio.Event) -> None:
    while not stop.is_set():
        try:
            await dispatch_once()
        except Exception:
            log.exception("Notification worker failed; outbox retained for retry")
        try:
            await asyncio.wait_for(stop.wait(), timeout=1)
        except TimeoutError:
            pass
