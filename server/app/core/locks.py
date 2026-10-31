"""Per-device serialization for the MVP's single Uvicorn worker."""

import asyncio
from weakref import WeakValueDictionary

_locks: WeakValueDictionary[str, asyncio.Lock] = WeakValueDictionary()


def device_lock(device_id: str) -> asyncio.Lock:
    lock = _locks.get(device_id)
    if lock is None:
        lock = asyncio.Lock()
        _locks[device_id] = lock
    return lock
