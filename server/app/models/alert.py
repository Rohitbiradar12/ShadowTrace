from datetime import datetime
from typing import Annotated, Any, Literal

from beanie import Document, Indexed
from pydantic import Field
from pymongo import IndexModel


class Alert(Document):
    alert_id: Annotated[str, Indexed(unique=True)]
    rule_id: str
    title: str
    severity: Literal["low", "medium", "high", "critical"]
    mitre: list[str] = Field(default_factory=list)
    device_id: str
    group_key: str
    group: dict[str, Any] = Field(default_factory=dict)
    status: Literal["new", "acknowledged", "investigating", "resolved", "false_positive"] = "new"
    created_at: datetime
    last_seen: datetime
    first_event_at: datetime
    last_event_at: datetime
    occurrence_count: int = 0
    event_ids: list[str] = Field(default_factory=list)
    suggested_action: str | None = None
    history: list[dict[str, Any]] = Field(default_factory=list)

    class Settings:
        name = "alerts"
        indexes = [
            IndexModel([("group_key", 1), ("last_seen", -1)]),
            IndexModel([("device_id", 1), ("created_at", -1)]),
            IndexModel([("status", 1), ("severity", 1), ("created_at", -1)]),
        ]


class AlertHit(Document):
    """One rule firing per triggering event; durable retry protection for alert counts."""

    hit_id: Annotated[str, Indexed(unique=True)]
    alert_id: str
    rule_id: str
    device_id: str
    trigger_event_id: str
    event_ids: list[str]
    received_at: datetime
    event_at: datetime

    class Settings:
        name = "alert_hits"
        indexes = [IndexModel([("alert_id", 1), ("received_at", -1)])]
