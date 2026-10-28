"""The OS-neutral event every collector emits.

A failed login is ``category=auth, action=logon_failed`` whether it came from the Windows
Event Log, journald or the macOS unified log — only the ``data`` details differ.
"""

import uuid
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Protocol


class Category(StrEnum):
    # Keep in sync with server/app/models/event.py
    PROCESS = "process"
    FILE = "file"
    USB = "usb"
    BROWSER = "browser"
    AUTH = "auth"
    NETWORK = "network"
    WIFI = "wifi"
    SYSTEM = "system"
    AGENT = "agent"


def utc_iso(dt: datetime | None = None) -> str:
    dt = (dt or datetime.now(UTC)).astimezone(UTC)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def new_event(
    category: Category,
    action: str,
    data: dict[str, Any] | None = None,
    user: str | None = None,
    ts: datetime | None = None,
) -> dict[str, Any]:
    """Build an event. ``seq`` is assigned when the event is written to the local buffer."""
    return {
        "event_id": str(uuid.uuid4()),
        "ts": utc_iso(ts),
        "category": Category(category).value,
        "action": action,
        "user": user,
        "data": data or {},
    }


class Emit(Protocol):
    def __call__(
        self,
        category: Category,
        action: str,
        data: dict[str, Any] | None = None,
        user: str | None = None,
        ts: datetime | None = None,
    ) -> None: ...
