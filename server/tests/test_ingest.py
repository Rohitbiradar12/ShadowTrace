import uuid
from datetime import UTC, datetime

from app.forensics.verify import verify_device_chain
from app.models import Device, Event
from tests.conftest import enroll


def make_event(seq: int, **overrides) -> dict:
    event = {
        "event_id": str(uuid.uuid4()),
        "ts": datetime.now(UTC).isoformat(),
        "category": "process",
        "action": "process_started",
        "user": "LAB-PC-01\\student",
        "data": {"pid": 1000 + seq, "name": "notepad.exe"},
        "seq": seq,
    }
    return event | overrides


async def upload(api, creds, events):
    return await api.post(
        "/api/v1/events/batch", headers={"X-Device-Key": creds["api_key"]}, json={"events": events}
    )


async def get_device(creds) -> Device:
    return await Device.find_one(Device.device_id == creds["device_id"])


async def test_batch_is_stored_with_device_id_and_chain(api):
    creds = await enroll(api)

    response = await upload(api, creds, [make_event(1), make_event(2), make_event(3)])

    assert response.json() == {"accepted": 3, "duplicates": 0}
    events = await Event.find(Event.device_id == creds["device_id"]).sort(+Event.seq).to_list()
    assert [e.chain_index for e in events] == [0, 1, 2]
    assert events[1].prev_hash == events[0].hash
    device = await get_device(creds)
    assert device.chain_length == 3 and device.chain_head == events[2].hash


async def test_retried_batch_is_deduplicated(api):
    creds = await enroll(api)
    batch = [make_event(1), make_event(2)]

    await upload(api, creds, batch)
    response = await upload(api, creds, batch + [make_event(3)])

    assert response.json() == {"accepted": 1, "duplicates": 2}
    assert await Event.find(Event.device_id == creds["device_id"]).count() == 3


async def test_chain_continues_across_batches_and_verifies(api):
    creds = await enroll(api)
    await upload(api, creds, [make_event(1), make_event(2)])
    await upload(api, creds, [make_event(3)])

    result = await verify_device_chain(await get_device(creds))

    assert result.ok and result.checked == 3


async def test_edited_event_is_detected(api):
    creds = await enroll(api)
    await upload(api, creds, [make_event(1), make_event(2), make_event(3)])

    # Simulate an attacker editing the database directly (e.g. via Compass).
    await Event.get_pymongo_collection().update_one(
        {"device_id": creds["device_id"], "chain_index": 1},
        {"$set": {"data.name": "totally-legit.exe"}},
    )
    result = await verify_device_chain(await get_device(creds))

    assert not result.ok
    assert result.broken_at_index == 1
    assert result.reason == "event content was modified"


async def test_deleted_event_is_detected(api):
    creds = await enroll(api)
    await upload(api, creds, [make_event(1), make_event(2), make_event(3)])

    await Event.get_pymongo_collection().delete_one(
        {"device_id": creds["device_id"], "chain_index": 1}
    )
    result = await verify_device_chain(await get_device(creds))

    assert not result.ok and result.broken_at_index == 1


async def test_deleted_last_event_is_detected(api):
    creds = await enroll(api)
    await upload(api, creds, [make_event(1), make_event(2)])

    await Event.get_pymongo_collection().delete_one(
        {"device_id": creds["device_id"], "chain_index": 1}
    )
    result = await verify_device_chain(await get_device(creds))

    assert not result.ok and result.reason == "events missing from end of chain"


async def test_sequence_gaps_are_counted_as_missing(api):
    creds = await enroll(api)
    await upload(api, creds, [make_event(1), make_event(2)])
    await upload(api, creds, [make_event(6)])

    device = await get_device(creds)
    assert device.last_seq == 6 and device.missing_events == 3


async def test_invalid_category_is_rejected(api):
    creds = await enroll(api)
    response = await upload(api, creds, [make_event(1, category="keylogger")])
    assert response.status_code == 422


async def test_oversized_batch_is_rejected(api):
    creds = await enroll(api)
    response = await upload(api, creds, [make_event(i) for i in range(1, 1002)])
    assert response.status_code == 413


async def test_upload_requires_device_key(api):
    response = await api.post("/api/v1/events/batch", json={"events": [make_event(1)]})
    assert response.status_code == 422  # missing header


async def test_devices_have_independent_chains(api):
    a, b = await enroll(api), await enroll(api)
    await upload(api, a, [make_event(1)])
    await upload(api, b, [make_event(1), make_event(2)])

    assert (await verify_device_chain(await get_device(a))).checked == 1
    assert (await verify_device_chain(await get_device(b))).checked == 2
