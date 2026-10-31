from datetime import UTC, datetime, timedelta

import httpx
from pydantic import SecretStr

from app.core.config import get_settings
from app.models import Notification
from app.notify.dispatcher import NotificationSender, dispatch_once
from tests.conftest import enroll
from tests.test_ingest import make_event, upload


class FakeSender:
    def __init__(self, error=None):
        self.error = error
        self.sent = []

    async def send(self, channel, text):
        if self.error:
            raise self.error
        self.sent.append((channel, text))


async def prepare(api, *, telegram_only=False):
    get_settings().notifications_enabled = True
    creds = await enroll(api)
    event = make_event(
        1, category="network", action="connection_opened", data={"remote_ip": "203.0.113.66"}
    )
    await upload(api, creds, [event])
    if telegram_only:
        # MongoDB does not guarantee the order of jobs sharing a millisecond timestamp.
        # Isolate channel-specific tests so another eligible channel cannot be picked first.
        await Notification.get_pymongo_collection().delete_many({"channel": "email"})
    return creds


async def test_alert_queues_deliveries_and_success_is_recorded(api):
    await prepare(api)
    sender = FakeSender()
    assert await dispatch_once(sender) == 1
    assert await dispatch_once(sender) == 1
    assert await dispatch_once(sender) == 0
    jobs = await Notification.find_all().to_list()
    assert {n.channel for n in jobs} == {"telegram", "email"}
    assert all(n.status == "sent" and n.sent_at and n.delivery_id for n in jobs)
    assert {channel for channel, text in sender.sent} == {"telegram", "email"}
    assert all("ST-NETWORK-001" in text for _, text in sender.sent)


async def test_retry_keeps_outbox_and_redacts_raw_exception(api):
    await prepare(api, telegram_only=True)
    now = datetime.now(UTC) + timedelta(seconds=1)
    sender = FakeSender(httpx.ConnectError("https://example.invalid/private-token"))
    assert await dispatch_once(sender, now) == 0
    job = await Notification.find_one(Notification.channel == "telegram")
    assert job.status == "pending" and job.attempts == 1
    assert job.next_attempt_at > now
    assert job.last_error == "ConnectError"
    sender.error = None
    await dispatch_once(sender, now + timedelta(seconds=3))
    job = await Notification.find_one(Notification.channel == "telegram")
    assert job.status == "sent" and job.attempts == 2


async def test_rate_limit_defers_then_sends_one_digest(api):
    creds = await prepare(api)
    get_settings().notifications_per_minute = 1
    collection = Notification.get_pymongo_collection()
    # Focus this test on one channel; each channel has an independent delivery budget.
    await collection.delete_many({"channel": "email"})
    sender = FakeSender()
    now = datetime.now(UTC) + timedelta(seconds=1)
    assert await dispatch_once(sender, now) == 1
    await upload(
        api,
        creds,
        [
            make_event(
                2,
                category="process",
                action="process_started",
                data={
                    "name": "powershell.exe",
                    "command_line": "powershell -enc ZGVtbw==",
                },
            ),
            make_event(3, category="system", action="audit_log_cleared"),
        ],
    )
    await collection.delete_many({"channel": "email"})
    assert await dispatch_once(sender, now + timedelta(seconds=2)) == 0
    assert await dispatch_once(sender, now + timedelta(seconds=61)) == 2
    assert len(sender.sent) == 2
    assert "Digest: 2 alerts" in sender.sent[-1][1]


async def test_missing_credentials_are_visible_without_network_calls(api):
    await prepare(api, telegram_only=True)
    get_settings().telegram_bot_token = SecretStr("")
    get_settings().telegram_chat_id = ""
    assert await dispatch_once() == 0
    job = await Notification.find_one(Notification.channel == "telegram")
    assert job.status == "unconfigured"
    assert "required" in job.last_error


async def test_abandoned_delivery_lease_is_recovered(api):
    await prepare(api, telegram_only=True)
    now = datetime.now(UTC) + timedelta(minutes=3)
    await Notification.get_pymongo_collection().update_one(
        {"channel": "telegram"},
        {
            "$set": {
                "status": "sending",
                "attempts": 1,
                "lease_until": now - timedelta(seconds=1),
            }
        },
    )
    assert await dispatch_once(FakeSender(), now) == 1
    job = await Notification.find_one(Notification.channel == "telegram")
    assert job.status == "sent" and job.attempts == 2


async def test_retry_exhaustion_is_recorded(api):
    await prepare(api, telegram_only=True)
    get_settings().notification_max_attempts = 1
    await dispatch_once(FakeSender(TimeoutError("test")))
    job = await Notification.find_one(Notification.channel == "telegram")
    assert job.status == "failed" and job.attempts == 1


async def test_telegram_adapter_with_mock_transport():
    settings = get_settings()
    settings.telegram_bot_token = SecretStr("test-token")
    settings.telegram_chat_id = "test-chat"
    received = []

    def handle(request):
        received.append(request)
        return httpx.Response(200, json={"ok": True})

    sender = NotificationSender(settings, transport=httpx.MockTransport(handle))
    await sender.send("telegram", "Synthetic alert")
    assert len(received) == 1
    assert b"test-chat" in received[0].content


async def test_smtp_adapter_uses_verified_tls(monkeypatch):
    import ssl

    from app.notify import dispatcher

    settings = get_settings()
    settings.smtp_host = "smtp.example.invalid"
    settings.smtp_from = "sender@example.invalid"
    settings.smtp_to = "recipient@example.invalid"
    settings.smtp_username = "test-user"
    settings.smtp_ssl = False
    settings.smtp_starttls = True
    settings.smtp_password = SecretStr("test-password")
    calls = []

    class FakeSMTP:
        def __init__(self, *args, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def starttls(self, *, context):
            assert context.verify_mode == ssl.CERT_REQUIRED
            calls.append("tls")

        def login(self, username, password):
            calls.append("login")

        def send_message(self, message):
            assert message["To"] == "recipient@example.invalid"
            calls.append("sent")

    monkeypatch.setattr(dispatcher.smtplib, "SMTP", FakeSMTP)
    await NotificationSender(settings).send("email", "Synthetic alert")
    assert calls == ["tls", "login", "sent"]
