"""Persist rule firings and aggregate them into deduplicated alerts."""

import hashlib
import json
from datetime import UTC, datetime, timedelta

from app.core.config import get_settings
from app.detection.engine import Match
from app.models import Alert, AlertHit, Notification
from app.services.commands import auto_respond


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


async def record_match(event: dict, match: Match) -> str:
    settings = get_settings()
    rule = match.rule
    hit_id = _digest(rule.id + ":" + event["event_id"])
    group_key = _digest(
        json.dumps(
            [rule.id, event["device_id"], match.group],
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        )
    )
    alerts = Alert.get_pymongo_collection()
    hits = AlertHit.get_pymongo_collection()
    old_hit = await hits.find_one({"hit_id": hit_id})
    if old_hit:
        alert_id = old_hit["alert_id"]
    else:
        recent = await alerts.find_one(
            {
                "group_key": group_key,
                "last_seen": {
                    "$gte": event["received_at"] - timedelta(seconds=settings.alert_dedup_seconds)
                },
                "status": {"$nin": ["resolved", "false_positive"]},
            },
            sort=[("last_seen", -1)],
        )
        alert_id = recent["alert_id"] if recent else "al_" + hit_id[:32]
    await alerts.update_one(
        {"alert_id": alert_id},
        {
            "$setOnInsert": {
                "alert_id": alert_id,
                "rule_id": rule.id,
                "title": rule.title,
                "severity": rule.severity,
                "mitre": rule.mitre,
                "device_id": event["device_id"],
                "group_key": group_key,
                "group": match.group,
                "status": "new",
                "created_at": event["received_at"],
                "last_seen": event["received_at"],
                "first_event_at": match.first_at,
                "last_event_at": match.last_at,
                "occurrence_count": 0,
                "event_ids": [],
                "suggested_action": rule.response.auto_action,
            }
        },
        upsert=True,
    )
    await hits.update_one(
        {"hit_id": hit_id},
        {
            "$setOnInsert": {
                "hit_id": hit_id,
                "alert_id": alert_id,
                "rule_id": rule.id,
                "device_id": event["device_id"],
                "trigger_event_id": event["event_id"],
                "event_ids": match.event_ids,
                "received_at": event["received_at"],
                "event_at": event["ts"],
            }
        },
        upsert=True,
    )
    # Recompute counts from durable hits. A crash between these writes is safe to retry.
    count = await hits.count_documents({"alert_id": alert_id})
    recent_hits = hits.find({"alert_id": alert_id}).sort("received_at", -1).limit(20)
    evidence = []
    async for hit in recent_hits:
        evidence.extend(hit["event_ids"])
    evidence = list(dict.fromkeys(evidence))[:100]
    await alerts.update_one(
        {"alert_id": alert_id},
        {
            "$set": {"occurrence_count": count, "event_ids": evidence},
            "$min": {"first_event_at": match.first_at},
            "$max": {"last_seen": event["received_at"], "last_event_at": match.last_at},
        },
    )
    channels = rule.response.notify
    if channels is None:
        channels = ["telegram", "email"] if rule.severity in {"high", "critical"} else []
    for channel in channels:
        notification_id = alert_id + ":" + channel
        now = datetime.now(UTC)
        await Notification.get_pymongo_collection().update_one(
            {"notification_id": notification_id},
            {
                "$setOnInsert": {
                    "notification_id": notification_id,
                    "alert_id": alert_id,
                    "device_id": event["device_id"],
                    "channel": channel,
                    "status": "pending" if settings.notifications_enabled else "disabled",
                    "created_at": now,
                    "next_attempt_at": now,
                    "attempts": 0,
                    "lease_until": None,
                    "sent_at": None,
                    "delivery_id": None,
                    "last_error": None,
                }
            },
            upsert=True,
        )
    await auto_respond(event, rule.response.auto_action, alert_id, rule.id)
    return alert_id
