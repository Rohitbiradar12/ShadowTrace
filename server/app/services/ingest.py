import asyncio
from collections import defaultdict
from dataclasses import dataclass
from datetime import UTC, datetime

from app.forensics.chain import GENESIS_HASH, compute_hash, truncate_to_ms
from app.models import Device, Event
from app.models.event import EventIn

# Chain appends must be serialized per device. This lock covers a single server process;
# the unique (device_id, chain_index) index rejects races if several workers are ever run.
_device_locks: defaultdict[str, asyncio.Lock] = defaultdict(asyncio.Lock)


@dataclass
class IngestResult:
    accepted: int
    duplicates: int


async def _chain_head(device_id: str) -> tuple[int, str]:
    """Next chain index and previous hash, read from the events themselves."""
    last = await Event.find(Event.device_id == device_id).sort(-Event.chain_index).first_or_none()
    if last is None:
        return 0, GENESIS_HASH
    return last.chain_index + 1, last.hash


async def ingest_batch(device_id: str, incoming: list[EventIn]) -> IngestResult:
    async with _device_locks[device_id]:
        # Agents retry batches after network errors, so the same event may arrive twice.
        ids = [str(e.event_id) for e in incoming]
        cursor = Event.get_pymongo_collection().find({"event_id": {"$in": ids}}, {"event_id": 1})
        existing = {doc["event_id"] async for doc in cursor}
        seen: set[str] = set()
        fresh: list[EventIn] = []
        for event in sorted(incoming, key=lambda e: e.seq):
            event_id = str(event.event_id)
            if event_id not in existing and event_id not in seen:
                seen.add(event_id)
                fresh.append(event)

        if not fresh:
            return IngestResult(accepted=0, duplicates=len(incoming))

        next_index, prev_hash = await _chain_head(device_id)
        received_at = truncate_to_ms(datetime.now(UTC))
        docs: list[Event] = []
        for event in fresh:
            fields = {
                "event_id": str(event.event_id),
                "device_id": device_id,
                "ts": truncate_to_ms(event.ts),
                "category": event.category,
                "action": event.action,
                "user": event.user,
                "data": event.data,
                "seq": event.seq,
                "received_at": received_at,
                "chain_index": next_index,
            }
            digest = compute_hash(prev_hash, fields)
            docs.append(Event(**fields, prev_hash=prev_hash, hash=digest))
            prev_hash = digest
            next_index += 1

        await Event.insert_many(docs)

        device = await Device.find_one(Device.device_id == device_id)
        if device is not None:
            missing = 0
            last_seq = device.last_seq
            for event in fresh:
                if event.seq > last_seq + 1:
                    missing += event.seq - last_seq - 1
                last_seq = max(last_seq, event.seq)
            await device.set(
                {
                    Device.chain_length: next_index,
                    Device.chain_head: prev_hash,
                    Device.last_seq: last_seq,
                    Device.missing_events: device.missing_events + missing,
                }
            )

        return IngestResult(accepted=len(docs), duplicates=len(incoming) - len(docs))
