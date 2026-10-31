from datetime import datetime
from typing import Annotated, Literal

from beanie import Document, Indexed
from pymongo import IndexModel


class Notification(Document):
    notification_id: Annotated[str, Indexed(unique=True)]
    alert_id: str
    device_id: str
    channel: Literal["telegram", "email"]
    status: Literal["pending", "sending", "sent", "failed", "disabled", "unconfigured"]
    created_at: datetime
    next_attempt_at: datetime
    attempts: int = 0
    lease_until: datetime | None = None
    sent_at: datetime | None = None
    delivery_id: str | None = None
    last_error: str | None = None

    class Settings:
        name = "notifications"
        indexes = [
            IndexModel([("status", 1), ("next_attempt_at", 1)]),
            IndexModel([("device_id", 1), ("channel", 1), ("sent_at", -1)]),
        ]
