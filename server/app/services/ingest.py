from dataclasses import dataclass
from datetime import UTC, datetime

from app.core.locks import device_lock
from app.forensics.chain import GENESIS_HASH, compute_hash, truncate_to_ms
from app.models import Device, Event
from app.models.event import EventIn


class IntegrityError(Exception):
    """An append would conceal missing or modified forensic evidence."""


@dataclass
class IngestResult:
    accepted: int
    duplicates: int


async def _update_head(device: Device, rows: list[dict], length: int, head: str) -> None:
    missing, last_seq = device.missing_events, device.last_seq
    for row in rows:
        seq = row["seq"]
        missing += max(0, seq - last_seq - 1)
        last_seq = max(last_seq, seq)
    await device.set(
        {
            Device.chain_length: length,
            Device.chain_head: head,
            Device.last_seq: last_seq,
            Device.missing_events: missing,
        }
    )


async def _chain_head(device: Device) -> tuple[int, str]:
    """Preserve the recorded anchor; recover only a verified, uncommitted suffix.

    MongoDB standalone does not support multi-document transactions. A crash between
    inserting events and updating the device is recoverable; deleting the anchored tail
    is not. Never replace that anchor with the last surviving event.
    """
    collection = Event.get_pymongo_collection()
    index, head = device.chain_length, device.chain_head
    if index:
        anchor = await collection.find_one(
            {
                "device_id": device.device_id,
                "chain_index": index - 1,
            }
        )
        if (
            anchor is None
            or anchor["hash"] != head
            or compute_hash(anchor["prev_hash"], anchor) != head
        ):
            raise IntegrityError("Stored chain tail does not match the device anchor")
    elif head != GENESIS_HASH:
        raise IntegrityError("Invalid genesis anchor")
    cursor = collection.find(
        {
            "device_id": device.device_id,
            "chain_index": {"$gte": index},
        }
    ).sort("chain_index", 1)
    recovered = []
    async for row in cursor:
        if (
            row["chain_index"] != index
            or row["prev_hash"] != head
            or compute_hash(head, row) != row["hash"]
        ):
            raise IntegrityError("Uncommitted chain suffix is incomplete or modified")
        recovered.append(row)
        index, head = index + 1, row["hash"]
    if recovered:
        await _update_head(device, recovered, index, head)
    return index, head


async def ingest_batch(device_id: str, incoming: list[EventIn]) -> IngestResult:
    async with device_lock(device_id):
        device = await Device.find_one(Device.device_id == device_id)
        if device is None:
            raise ValueError("Unknown device")
        next_index, prev_hash = await _chain_head(device)
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

        await _update_head(device, [d.model_dump() for d in docs], next_index, prev_hash)

        return IngestResult(accepted=len(docs), duplicates=len(incoming) - len(docs))
