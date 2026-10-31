"""Tamper-evident hash chain over each device's events.

Every stored event carries ``hash = sha256(prev_hash + canonical(event))``. Editing, deleting
or reordering any stored event breaks the chain from that point on, which ``verify_chain``
reports. Pure functions only — no database access — so they are easy to test.
"""

import hashlib
import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

GENESIS_HASH = "0" * 64

# Fields covered by the hash. Mongo's internal _id is deliberately excluded.
CHAINED_FIELDS = (
    "event_id",
    "device_id",
    "ts",
    "category",
    "action",
    "user",
    "data",
    "seq",
    "received_at",
    "chain_index",
)


def truncate_to_ms(dt: datetime) -> datetime:
    """MongoDB stores milliseconds, so anything finer would not survive a round trip."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    dt = dt.astimezone(UTC)
    return dt.replace(microsecond=dt.microsecond - dt.microsecond % 1000)


def _canonical_value(value: Any) -> Any:
    if isinstance(value, datetime):
        return truncate_to_ms(value).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    if hasattr(value, "value"):  # enums
        return value.value
    return value


def compute_hash(prev_hash: str, fields: Mapping[str, Any]) -> str:
    canonical = {name: _canonical_value(fields.get(name)) for name in CHAINED_FIELDS}
    payload = json.dumps(canonical, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256((prev_hash + payload).encode()).hexdigest()


@dataclass
class ChainVerification:
    ok: bool
    checked: int
    broken_at_index: int | None = None
    reason: str | None = None


def verify_chain(
    events: Iterable[Mapping[str, Any]], expected_length: int, expected_head: str
) -> ChainVerification:
    """Verify events sorted by chain_index against the device's recorded chain head."""
    prev_hash = GENESIS_HASH
    checked = 0
    for expected_index, event in enumerate(events):
        index = event.get("chain_index")
        if not isinstance(index, int) or isinstance(index, bool):
            return ChainVerification(False, checked, expected_index, "invalid chain index")
        if index != expected_index:
            return ChainVerification(False, checked, expected_index, "event missing from chain")
        if event.get("prev_hash") != prev_hash:
            return ChainVerification(False, checked, index, "prev_hash does not match")
        try:
            expected_hash = compute_hash(prev_hash, event)
        except (TypeError, ValueError):
            return ChainVerification(False, checked, index, "event content cannot be canonicalized")
        if expected_hash != event.get("hash"):
            return ChainVerification(False, checked, index, "event content was modified")
        prev_hash = event["hash"]
        checked += 1

    if checked < expected_length:
        return ChainVerification(False, checked, checked, "events missing from end of chain")
    if checked > expected_length:
        return ChainVerification(
            False, checked, expected_length, "events exceed recorded chain length"
        )
    if prev_hash != expected_head:
        return ChainVerification(False, checked, None, "chain head does not match device record")
    return ChainVerification(True, checked)
