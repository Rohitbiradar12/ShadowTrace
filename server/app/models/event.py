from datetime import datetime
from enum import StrEnum
from typing import Annotated, Any
from uuid import UUID

from beanie import Document, Indexed
from pydantic import BaseModel, Field
from pymongo import DESCENDING, IndexModel


class Category(StrEnum):
    # Keep in sync with agent/shadowtrace_agent/schema.py
    PROCESS = "process"
    FILE = "file"
    USB = "usb"
    BROWSER = "browser"
    AUTH = "auth"
    NETWORK = "network"
    WIFI = "wifi"
    SYSTEM = "system"
    AGENT = "agent"


class EventIn(BaseModel):
    """An event as sent by the agent. The server adds device_id and chain fields."""

    event_id: UUID
    ts: datetime
    category: Category
    action: str = Field(pattern=r"^[a-z][a-z0-9_]{0,63}$")
    user: str | None = Field(default=None, max_length=256)
    data: dict[str, Any] = Field(default_factory=dict)
    seq: int = Field(ge=1)


class Event(Document):
    event_id: Annotated[str, Indexed(unique=True)]
    device_id: str
    ts: datetime
    category: Category
    action: str
    user: str | None = None
    data: dict[str, Any] = Field(default_factory=dict)
    seq: int
    received_at: datetime
    chain_index: int
    prev_hash: str
    hash: str

    class Settings:
        name = "events"
        indexes = [
            IndexModel([("device_id", 1), ("ts", DESCENDING)]),
            IndexModel([("category", 1), ("action", 1), ("ts", DESCENDING)]),
            IndexModel([("device_id", 1), ("chain_index", 1)], unique=True),
        ]
