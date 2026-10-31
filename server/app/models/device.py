from datetime import UTC, datetime
from typing import Annotated, Any, Literal

from beanie import Document, Indexed
from pydantic import Field

from app.forensics.chain import GENESIS_HASH

OsName = Literal["windows", "linux", "macos"]


class Device(Document):
    device_id: Annotated[str, Indexed(unique=True)]
    hostname: str
    os: OsName
    os_version: str
    agent_version: str
    api_key_hash: Annotated[str, Indexed(unique=True)]
    enrolled_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    last_seen: datetime | None = None
    last_ip: str | None = None
    stats: dict[str, Any] = Field(default_factory=dict)

    # Integrity anchor. Never rewind it to match deleted events.
    chain_length: int = 0
    chain_head: str = GENESIS_HASH
    # Highest agent sequence number received, and how many sequence numbers were skipped
    # (events the agent dropped or that never arrived).
    last_seq: int = 0
    missing_events: int = 0
    detection_index: int = -1

    class Settings:
        name = "devices"
