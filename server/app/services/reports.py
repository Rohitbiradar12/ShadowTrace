import json
from dataclasses import asdict
from datetime import UTC, datetime, timedelta

from app.core.locks import device_lock
from app.forensics.verify import verify_device_chain
from app.models import Alert, Command, Device, Event, Notification


def clean(document: dict) -> dict:
    return json.loads(
        json.dumps(
            {k: v for k, v in document.items() if k not in {"_id", "api_key_hash"}}, default=str
        )
    )


async def incident_report(alert_id: str) -> dict:
    alert = await Alert.find_one(Alert.alert_id == alert_id)
    if alert is None:
        raise ValueError("Alert not found")
    start = alert.first_event_at - timedelta(minutes=15)
    end = alert.last_event_at + timedelta(minutes=15)
    async with device_lock(alert.device_id):
        device = await Device.find_one(Device.device_id == alert.device_id)
        if device is None:
            raise ValueError("Device not found")
        verification = await verify_device_chain(device)
        collection = Event.get_pymongo_collection()
        evidence = [
            clean(e)
            async for e in collection.find(
                {"device_id": alert.device_id, "event_id": {"$in": alert.event_ids}}
            ).sort("chain_index", 1)
        ]
        query = {"device_id": alert.device_id, "ts": {"$gte": start, "$lte": end}}
        total = await collection.count_documents(query)
        timeline = [clean(e) async for e in collection.find(query).sort("ts", 1).limit(250)]
        anchor = {"length": device.chain_length, "head": device.chain_head}
    commands = (
        await Command.find(
            {
                "device_id": alert.device_id,
                "$or": [
                    {"alert_id": alert_id},
                    {"source_event_id": {"$in": alert.event_ids}},
                    {"created_at": {"$gte": start, "$lte": end}},
                ],
            }
        )
        .sort(+Command.created_at)
        .limit(100)
        .to_list()
    )
    deliveries = await Notification.find(Notification.alert_id == alert_id).to_list()
    return {
        "version": 1,
        "generated_at": datetime.now(UTC).isoformat(),
        "alert": alert.model_dump(mode="json", exclude={"id"}),
        "device": device.model_dump(mode="json", exclude={"id", "api_key_hash"}),
        "verification": asdict(verification),
        "anchor": anchor,
        "evidence": evidence,
        "missing_evidence": sorted(set(alert.event_ids) - {e["event_id"] for e in evidence}),
        "timeline": timeline,
        "timeline_total": total,
        "timeline_limit": 250,
        "window_start": start.isoformat(),
        "window_end": end.isoformat(),
        "commands": [c.model_dump(mode="json", exclude={"id"}) for c in commands],
        "notifications": [n.model_dump(mode="json", exclude={"id"}) for n in deliveries],
    }
