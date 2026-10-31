from datetime import UTC, datetime
from uuid import uuid4

from pymongo import ReturnDocument

from app.models import Alert

STATUSES = {"new", "acknowledged", "investigating", "resolved", "false_positive"}


async def change_alert(
    alert_id: str,
    actor: str,
    *,
    status: str | None = None,
    note: str | None = None,
    key: str | None = None,
    only_new: bool = False,
) -> Alert:
    if status is not None and status not in STATUSES:
        raise ValueError("Invalid alert status")
    note = note.strip() if note else None
    if status is None and not note:
        raise ValueError("Choose a status or enter a note")
    if note and len(note) > 2000:
        raise ValueError("Notes must be at most 2000 characters")
    key = key or uuid4().hex
    query = {
        "alert_id": alert_id,
        "history.key": {"$ne": key},
        "$expr": {"$lt": [{"$size": {"$ifNull": ["$history", []]}}, 1000]},
    }
    if only_new:
        query["status"] = "new"
    updates = {
        "$push": {
            "history": {
                "key": key,
                "at": datetime.now(UTC),
                "actor": actor,
                "status": status,
                "note": note,
            }
        }
    }
    if status:
        updates["$set"] = {"status": status}
    row = await Alert.get_pymongo_collection().find_one_and_update(
        query, updates, return_document=ReturnDocument.AFTER
    )
    if row:
        return Alert.model_validate(row)
    alert = await Alert.find_one(Alert.alert_id == alert_id)
    if alert is None:
        raise ValueError("Alert not found")
    if len(alert.history) >= 1000 and not any(h["key"] == key for h in alert.history):
        raise ValueError("Alert history limit reached")
    return alert
