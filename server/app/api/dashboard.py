"""Authenticated dashboard queries and operator actions. No secrets in read responses."""

import asyncio
import csv
import hashlib
import io
import json
import re
from dataclasses import asdict
from datetime import UTC, datetime, timedelta
from typing import Annotated, Literal
from uuid import UUID

from bson import ObjectId
from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import Response
from pydantic import AwareDatetime, BaseModel, Field
from pymongo import ReturnDocument

from app.core.config import get_settings
from app.core.locks import device_lock
from app.core.security import ENROLLMENT_TOKEN_PREFIX, generate_token, hash_token
from app.detection.engine import get_engine
from app.detection.rules import load_rules
from app.forensics.verify import verify_device_chain
from app.models import Alert, Command, Device, EnrollmentToken, Event, Notification
from app.models.command import Action
from app.models.event import Category
from app.models.user import AuditEntry, Role, Session, User
from app.services.auth import (
    Administrator,
    CurrentUser,
    Operator,
    create_user,
    public_user,
)
from app.services.commands import cancel_command, queue_command
from app.services.triage import change_alert

router = APIRouter(prefix="/ui", tags=["dashboard"])
Limit = Annotated[int, Query(ge=1, le=200)]
Offset = Annotated[int, Query(ge=0, le=100000)]
AlertStatus = Literal["new", "acknowledged", "investigating", "resolved", "false_positive"]
Severity = Literal["low", "medium", "high", "critical"]


def public(document, *, exclude=None):
    return document.model_dump(
        mode="json", exclude={"id", "api_key_hash", "password_hash", *(exclude or [])}
    )


def device_view(device: Device) -> dict:
    online = bool(
        device.last_seen
        and device.last_seen
        > datetime.now(UTC)
        - timedelta(seconds=max(30, get_settings().heartbeat_interval_seconds * 3))
    )
    return {**public(device), "online": online}


async def find_device(device_id: str) -> Device:
    device = await Device.find_one(Device.device_id == device_id)
    if device is None:
        raise HTTPException(404, "Device not found")
    return device


async def find_alert(alert_id: str) -> Alert:
    alert = await Alert.find_one(Alert.alert_id == alert_id)
    if alert is None:
        raise HTTPException(404, "Alert not found")
    return alert


@router.get("/overview")
async def overview(principal: CurrentUser):
    now = datetime.now(UTC)
    since = now - timedelta(hours=24)
    online_since = now - timedelta(seconds=max(30, get_settings().heartbeat_interval_seconds * 3))
    opened = {"status": {"$nin": ["resolved", "false_positive"]}}
    devices, online, events, alerts = await asyncio.gather(
        Device.count(),
        Device.find({"last_seen": {"$gte": online_since}}).count(),
        Event.find({"received_at": {"$gte": since}}).count(),
        Alert.find(opened).count(),
    )
    collection = Alert.get_pymongo_collection()
    severity = await collection.aggregate(
        [
            {"$match": opened},
            {"$group": {"_id": "$severity", "count": {"$sum": 1}}},
        ]
    )
    trend = await collection.aggregate(
        [
            {"$match": {"created_at": {"$gte": since}}},
            {
                "$group": {
                    "_id": {
                        "$dateToString": {"format": "%Y-%m-%dT%H:00:00Z", "date": "$created_at"}
                    },
                    "count": {"$sum": 1},
                }
            },
            {"$sort": {"_id": 1}},
        ]
    )
    top_rules = await collection.aggregate(
        [
            {"$match": opened},
            {"$group": {"_id": "$rule_id", "count": {"$sum": 1}}},
            {"$sort": {"count": -1, "_id": 1}},
            {"$limit": 5},
        ]
    )
    top_devices = await collection.aggregate(
        [
            {"$match": opened},
            {"$group": {"_id": "$device_id", "count": {"$sum": 1}}},
            {"$sort": {"count": -1, "_id": 1}},
            {"$limit": 5},
        ]
    )
    recent = await Alert.find_all().sort(-Alert.last_seen).limit(8).to_list()
    feed = await Event.find_all().sort(-Event.received_at).limit(10).to_list()
    return {
        "devices": devices,
        "online": online,
        "events_24h": events,
        "open_alerts": alerts,
        "severity": {r["_id"]: r["count"] async for r in severity},
        "trend": [{"hour": r["_id"], "count": r["count"]} async for r in trend],
        "top_rules": [{"id": r["_id"], "count": r["count"]} async for r in top_rules],
        "top_devices": [{"id": r["_id"], "count": r["count"]} async for r in top_devices],
        "recent_alerts": [public(a, exclude={"history"}) for a in recent],
        "feed": [public(e) for e in feed],
        "updated_at": now,
    }


@router.get("/devices")
async def devices(
    principal: CurrentUser,
    q: str = Query("", max_length=100),
    limit: Limit = 50,
    offset: Offset = 0,
):
    query = {"hostname": {"$regex": re.escape(q), "$options": "i"}} if q else {}
    rows = await Device.find(query).sort(+Device.hostname).skip(offset).limit(limit).to_list()
    counts = await Alert.get_pymongo_collection().aggregate(
        [
            {
                "$match": {
                    "device_id": {"$in": [r.device_id for r in rows]},
                    "status": {"$nin": ["resolved", "false_positive"]},
                }
            },
            {"$group": {"_id": "$device_id", "count": {"$sum": 1}}},
        ]
    )
    counts = {c["_id"]: c["count"] async for c in counts}
    return {
        "items": [{**device_view(d), "open_alerts": counts.get(d.device_id, 0)} for d in rows],
        "total": await Device.find(query).count(),
        "limit": limit,
        "offset": offset,
    }


@router.get("/devices/{device_id}")
async def device_detail(device_id: str, principal: CurrentUser):
    device = await find_device(device_id)
    alerts = (
        await Alert.find(Alert.device_id == device_id).sort(-Alert.last_seen).limit(20).to_list()
    )
    processes = (
        await Event.find(
            {"device_id": device_id, "category": "process", "action": "process_started"}
        )
        .sort(-Event.ts)
        .limit(30)
        .to_list()
    )
    commands = (
        await Command.find(Command.device_id == device_id)
        .sort(-Command.created_at)
        .limit(30)
        .to_list()
    )
    return {
        "device": device_view(device),
        "alerts": [public(a, exclude={"history"}) for a in alerts],
        "processes": [public(e) for e in processes],
        "commands": [public(c) for c in commands],
    }


@router.post("/devices/{device_id}/verify")
async def verify(device_id: str, principal: CurrentUser):
    async with device_lock(device_id):
        device = await find_device(device_id)
        result = await verify_device_chain(device)
    return asdict(result)


@router.get("/alerts")
async def alerts(
    principal: CurrentUser,
    status: AlertStatus | None = None,
    severity: Severity | None = None,
    device_id: str | None = None,
    q: str = Query("", max_length=100),
    limit: Limit = 50,
    offset: Offset = 0,
):
    query = {
        k: v
        for k, v in {"status": status, "severity": severity, "device_id": device_id}.items()
        if v
    }
    if q:
        query["$or"] = [
            {k: {"$regex": re.escape(q), "$options": "i"}} for k in ("title", "rule_id")
        ]
    rows = await Alert.find(query).sort(-Alert.last_seen).skip(offset).limit(limit).to_list()
    return {
        "items": [public(a, exclude={"history"}) for a in rows],
        "total": await Alert.find(query).count(),
        "limit": limit,
        "offset": offset,
    }


@router.get("/alerts/{alert_id}")
async def alert_detail(alert_id: str, principal: CurrentUser):
    alert = await find_alert(alert_id)
    events = (
        await Event.find({"device_id": alert.device_id, "event_id": {"$in": alert.event_ids}})
        .sort(+Event.ts)
        .to_list()
    )
    notifications = await Notification.find(Notification.alert_id == alert_id).to_list()
    commands = await Command.find(Command.alert_id == alert_id).sort(-Command.created_at).to_list()
    return {
        "alert": public(alert),
        "device": device_view(await find_device(alert.device_id)),
        "events": [public(e) for e in events],
        "notifications": [public(n) for n in notifications],
        "commands": [public(c) for c in commands],
    }


class TriageIn(BaseModel):
    status: AlertStatus | None = None
    note: str | None = Field(None, min_length=1, max_length=2000)


@router.patch("/alerts/{alert_id}")
async def triage(alert_id: str, body: TriageIn, principal: Operator):
    await find_alert(alert_id)
    try:
        return public(
            await change_alert(alert_id, principal.actor, status=body.status, note=body.note)
        )
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc


def event_query(device_id, category, action, q, start, end):
    query = {
        k: v
        for k, v in {"device_id": device_id, "category": category, "action": action}.items()
        if v
    }
    if start and end and start > end:
        raise HTTPException(422, "Start time must be before end time")
    if start or end:
        query["ts"] = {**({"$gte": start} if start else {}), **({"$lte": end} if end else {})}
    if q:
        query["$or"] = [
            {k: {"$regex": re.escape(q), "$options": "i"}}
            for k in (
                "action",
                "user",
                "data.name",
                "data.exe",
                "data.path",
                "data.url",
                "data.domain",
                "data.remote_ip",
                "data.command_line",
                "data.target_user",
                "data.ssid",
                "data.threat_name",
            )
        ]
    return query


@router.get("/events")
async def events(
    principal: CurrentUser,
    device_id: str | None = None,
    category: Category | None = None,
    action: str | None = Query(None, max_length=64),
    q: str = Query("", max_length=100),
    start: AwareDatetime | None = None,
    end: AwareDatetime | None = None,
    limit: Limit = 50,
    offset: Offset = 0,
    order: Literal["asc", "desc"] = "desc",
):
    query = event_query(device_id, category, action, q, start, end)
    rows = (
        await Event.find(query)
        .sort([("ts", 1 if order == "asc" else -1), ("event_id", 1)])
        .skip(offset)
        .limit(limit)
        .to_list()
    )
    return {
        "items": [public(e) for e in rows],
        "total": await Event.find(query).count(),
        "limit": limit,
        "offset": offset,
    }


def csv_value(value) -> str:
    value = str(value or "")
    return "'" + value if value.startswith(("=", "+", "-", "@", "\t", "\r", "\n")) else value


@router.get("/events.csv")
async def event_csv(
    principal: CurrentUser,
    device_id: str | None = None,
    category: Category | None = None,
    action: str | None = Query(None, max_length=64),
    q: str = Query("", max_length=100),
    start: AwareDatetime | None = None,
    end: AwareDatetime | None = None,
):
    query = event_query(device_id, category, action, q, start, end)
    rows = await Event.find(query).sort(+Event.ts).limit(5000).to_list()
    output = io.StringIO(newline="")
    writer = csv.writer(output)
    writer.writerow(
        [
            "event_id",
            "device_id",
            "timestamp_utc",
            "category",
            "action",
            "user",
            "sequence",
            "hash",
            "data",
        ]
    )
    for e in rows:
        writer.writerow(
            [
                csv_value(v)
                for v in [
                    e.event_id,
                    e.device_id,
                    e.ts.isoformat(),
                    e.category,
                    e.action,
                    e.user,
                    e.seq,
                    e.hash,
                    json.dumps(e.data, ensure_ascii=False),
                ]
            ]
        )
    total = await Event.find(query).count()
    return Response(
        output.getvalue(),
        media_type="text/csv; charset=utf-8",
        headers={
            "Content-Disposition": 'attachment; filename="shadowtrace-events.csv"',
            "X-Total-Count": str(total),
            "X-Export-Limit": "5000",
        },
    )


@router.get("/events/{event_id}")
async def event_detail(event_id: str, principal: CurrentUser):
    event = await Event.find_one(Event.event_id == event_id)
    if event is None:
        raise HTTPException(404, "Event not found")
    return public(event)


class CommandIn(BaseModel):
    device_id: str = Field(min_length=1, max_length=100)
    action: Action
    event_id: str | None = Field(None, max_length=64)
    alert_id: str | None = Field(None, max_length=64)
    reason: str = Field(min_length=1, max_length=500)
    ttl_seconds: int = Field(120, ge=10, le=900)
    request_id: UUID


def check_command_request(command: Command, body: CommandIn) -> None:
    if (
        command.device_id,
        command.action,
        command.source_event_id,
        command.reason,
        command.alert_id,
        (command.expires_at - command.created_at).total_seconds(),
    ) != (
        body.device_id,
        body.action,
        body.event_id,
        body.reason,
        body.alert_id,
        body.ttl_seconds,
    ):
        raise HTTPException(409, "Request ID already used for a different command")


@router.post("/commands", status_code=201)
async def issue_command(body: CommandIn, principal: Operator):
    command_id = (
        "cmd_" + hashlib.sha256(f"{principal.actor}:{body.request_id}".encode()).hexdigest()[:32]
    )
    existing = await Command.find_one(Command.command_id == command_id)
    if existing is not None:
        check_command_request(existing, body)
        return public(existing)
    if body.alert_id:
        alert = await find_alert(body.alert_id)
        if alert.device_id != body.device_id or (
            body.event_id and body.event_id not in alert.event_ids
        ):
            raise HTTPException(400, "Command target does not match alert evidence")
    try:
        command = await queue_command(
            body.device_id,
            body.action,
            actor=principal.actor,
            reason=body.reason,
            event_id=body.event_id,
            alert_id=body.alert_id,
            ttl_seconds=body.ttl_seconds,
            command_id=command_id,
        )
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    check_command_request(command, body)
    return public(command)


@router.get("/commands")
async def commands(
    principal: CurrentUser, device_id: str | None = None, limit: Limit = 50, offset: Offset = 0
):
    query = {"device_id": device_id} if device_id else {}
    rows = await Command.find(query).sort(-Command.created_at).skip(offset).limit(limit).to_list()
    return {
        "items": [public(c) for c in rows],
        "total": await Command.find(query).count(),
        "limit": limit,
        "offset": offset,
    }


@router.post("/commands/{command_id}/cancel")
async def cancel(command_id: str, principal: Operator):
    if not await cancel_command(command_id, principal.actor):
        raise HTTPException(409, "Only an undelivered pending command can be cancelled")
    return {"ok": True}


@router.get("/commands/{command_id}")
async def command_detail(command_id: str, principal: CurrentUser):
    command = await Command.find_one(Command.command_id == command_id)
    if command is None:
        raise HTTPException(404, "Command not found")
    return public(command)


@router.get("/rules")
async def rules(principal: CurrentUser):
    rows = load_rules(get_settings().rules_dir)
    return {
        "items": [r.model_dump(mode="json") for r in rows],
        "active_count": len(get_engine().rules),
        "restart_required_after_file_edit": True,
    }


@router.get("/settings")
async def settings(principal: Administrator):
    config = get_settings()
    return {
        "notifications_enabled": config.notifications_enabled,
        "telegram_configured": bool(
            config.telegram_chat_id and config.telegram_bot_token.get_secret_value()
        ),
        "telegram_controls_enabled": config.telegram_controls_enabled,
        "telegram_operators": len(config.telegram_allowed_user_ids),
        "smtp_configured": bool(config.smtp_host and config.smtp_from and config.smtp_to),
        "auto_response_enabled": config.auto_response_enabled,
        "session_hours": config.session_hours,
        "secure_cookies": config.session_cookie_secure,
        "heartbeat_seconds": config.heartbeat_interval_seconds,
        "indicators": {
            name: definition.model_dump()
            for name, definition in get_engine().intel.definitions.items()
        },
    }


class UserIn(BaseModel):
    username: str = Field(min_length=3, max_length=64)
    password: str = Field(min_length=12, max_length=128)
    role: Role = "viewer"


class UserUpdate(BaseModel):
    role: Role | None = None
    disabled: bool | None = None


@router.get("/users")
async def users(principal: Administrator):
    return {"items": [public_user(u) for u in await User.find_all().sort(+User.username).to_list()]}


@router.post("/users", status_code=201)
async def add_user(body: UserIn, principal: Administrator):
    try:
        return public_user(
            await create_user(body.username, body.password, body.role, principal.actor)
        )
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc


@router.patch("/users/{username}")
async def update_user(username: str, body: UserUpdate, principal: Administrator):
    async with device_lock("dashboard-user-management"):
        user = await User.find_one(User.username == username)
        if user is None:
            raise HTTPException(404, "User not found")
        if username == principal.user.username and body.disabled:
            raise HTTPException(400, "You cannot disable your own account")
        removing_admin = (
            user.role == "admin"
            and not user.disabled
            and (body.disabled or (body.role and body.role != "admin"))
        )
        if removing_admin and await User.find({"role": "admin", "disabled": False}).count() <= 1:
            raise HTTPException(400, "Keep at least one enabled administrator")
        changes = {k: v for k, v in body.model_dump().items() if v is not None}
        updated = await User.get_pymongo_collection().find_one_and_update(
            {"_id": user.id},
            {"$set": changes, "$inc": {"session_version": 1}},
            return_document=ReturnDocument.AFTER,
        )
        user = User.model_validate(updated)
        await Session.find(Session.username == username).delete()
        await AuditEntry(
            actor=principal.actor, action="user_updated", target=username, details=changes
        ).insert()
    return public_user(user)


class TokenIn(BaseModel):
    hours: int = Field(1, ge=1, le=168)
    max_uses: int = Field(1, ge=1, le=100)
    note: str = Field("", max_length=200)


@router.post("/enrollment-tokens", status_code=201)
async def enrollment(body: TokenIn, principal: Administrator):
    token = generate_token(ENROLLMENT_TOKEN_PREFIX)
    expires = datetime.now(UTC) + timedelta(hours=body.hours)
    row = EnrollmentToken(
        token_hash=hash_token(token), expires_at=expires, max_uses=body.max_uses, note=body.note
    )
    await row.insert()
    await AuditEntry(
        actor=principal.actor,
        action="enrollment_token_created",
        target=str(row.id),
        details={"max_uses": body.max_uses},
    ).insert()
    return {"token": token, "expires_at": expires, "max_uses": body.max_uses}


@router.get("/enrollment-tokens")
async def enrollment_tokens(principal: Administrator):
    rows = await EnrollmentToken.find_all().sort(-EnrollmentToken.created_at).limit(100).to_list()
    return {"items": [{**public(r, exclude={"token_hash"}), "id": str(r.id)} for r in rows]}


@router.delete("/enrollment-tokens/{token_id}")
async def revoke_enrollment(token_id: str, principal: Administrator):
    if not ObjectId.is_valid(token_id):
        raise HTTPException(404, "Token not found")
    row = await EnrollmentToken.get(ObjectId(token_id))
    if row is None:
        raise HTTPException(404, "Token not found")
    await row.delete()
    await AuditEntry(
        actor=principal.actor, action="enrollment_token_revoked", target=token_id
    ).insert()
    return {"ok": True}


@router.get("/audit")
async def audit(principal: Administrator, limit: Limit = 50, offset: Offset = 0):
    rows = (
        await AuditEntry.find_all().sort(-AuditEntry.created_at).skip(offset).limit(limit).to_list()
    )
    return {"items": [public(r) for r in rows], "total": await AuditEntry.count()}


@router.post("/notifications/{notification_id}/retry")
async def retry_notification(notification_id: str, principal: Administrator):
    result = await Notification.get_pymongo_collection().update_one(
        {
            "notification_id": notification_id,
            "status": {"$in": ["failed", "disabled", "unconfigured"]},
        },
        {
            "$set": {
                "status": "pending",
                "attempts": 0,
                "next_attempt_at": datetime.now(UTC),
                "lease_until": None,
                "last_error": None,
            }
        },
    )
    if not result.modified_count:
        raise HTTPException(409, "Only failed, disabled or unconfigured deliveries can be retried")
    await AuditEntry(
        actor=principal.actor, action="notification_retried", target=notification_id
    ).insert()
    return {"ok": True}
