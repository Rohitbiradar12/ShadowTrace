"""Persistent detection cursor, shared by ingestion and the recovery worker."""

import asyncio
import logging

from app.core.config import get_settings
from app.core.locks import device_lock
from app.detection.alerts import record_match
from app.detection.engine import get_engine
from app.models import Device, Event

log = logging.getLogger(__name__)


async def detect_device(device_id: str, limit: int = 1000) -> int:
    if not get_settings().detection_enabled:
        return 0
    engine = get_engine()
    processed = 0
    async with device_lock(device_id):
        device = await Device.find_one(Device.device_id == device_id)
        if device is None:
            return 0
        cursor = (
            Event.get_pymongo_collection()
            .find(
                {
                    "device_id": device_id,
                    "chain_index": {"$gt": device.detection_index},
                }
            )
            .sort("chain_index", 1)
            .limit(limit)
        )
        async for event in cursor:
            if event["chain_index"] != device.detection_index + 1:
                raise RuntimeError(f"Missing event before detection index {event['chain_index']}")
            for match in await engine.evaluate(event):
                await record_match(event, match)
            await device.set({Device.detection_index: event["chain_index"]})
            processed += 1
    return processed


async def detection_loop(stop: asyncio.Event) -> None:
    while not stop.is_set():
        try:
            devices = Device.find(
                {
                    "$expr": {
                        "$lt": [
                            {"$ifNull": ["$detection_index", -1]},
                            {"$subtract": ["$chain_length", 1]},
                        ]
                    }
                }
            )
            async for device in devices:
                if stop.is_set():
                    break
                try:
                    await detect_device(device.device_id, limit=100)
                except Exception:
                    log.exception(
                        "Detection failed for %s; cursor retained for retry", device.device_id
                    )
        except Exception:
            log.exception("Detection recovery scan failed")
        try:
            await asyncio.wait_for(stop.wait(), get_settings().detection_poll_seconds)
        except TimeoutError:
            pass
