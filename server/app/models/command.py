"""Durable, allowlisted response commands. No shell or executable arguments are accepted."""

from datetime import UTC, datetime
from typing import Any, Literal

from beanie import Document
from pydantic import AwareDatetime, BaseModel, ConfigDict, Field
from pymongo import ASCENDING, IndexModel

Action = Literal["lock_workstation", "kill_process"]
ResultStatus = Literal["succeeded", "failed", "rejected", "unknown"]


class CommandResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    command_id: str = Field(pattern=r"^cmd_[a-f0-9]{32}$")
    status: ResultStatus
    detail: str = Field(max_length=500)
    finished_at: AwareDatetime


class Command(Document):
    command_id: str
    device_id: str
    action: Action
    params: dict[str, Any] = Field(default_factory=dict)
    actor: str
    reason: str
    source_event_id: str | None = None
    alert_id: str | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    expires_at: datetime
    status: Literal[
        "pending", "delivered", "expired", "cancelled", "succeeded", "failed", "rejected", "unknown"
    ] = "pending"
    deliveries: int = 0
    lease_until: datetime | None = None
    result: CommandResult | None = None
    result_received_at: datetime | None = None
    cancelled_by: str | None = None
    cancelled_at: datetime | None = None
    # Audit transitions live in the same document so the state and its audit are atomic.
    history: list[dict[str, Any]] = Field(default_factory=list)

    class Settings:
        name = "commands"
        indexes = [
            IndexModel([("command_id", ASCENDING)], unique=True),
            IndexModel(
                [("device_id", ASCENDING), ("status", ASCENDING), ("created_at", ASCENDING)]
            ),
        ]
