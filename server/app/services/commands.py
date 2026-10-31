"""Durable allowlisted responses shared by the authenticated UI, Telegram and local CLI."""

import hashlib
from datetime import UTC, datetime, timedelta
from pathlib import PureWindowsPath
from uuid import uuid4

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, ValidationError
from pymongo import ReturnDocument

from app.core.config import get_settings
from app.models.command import Action, Command, CommandResult
from app.models.device import Device
from app.models.event import Event


class ProcessTarget(BaseModel):
    model_config = ConfigDict(extra="forbid")

    pid: int = Field(strict=True, gt=4)
    exe: str = Field(min_length=1, max_length=32768)
    create_time: AwareDatetime


def process_target(event: dict) -> dict:
    if event["category"] != "process" or event["action"] != "process_started":
        raise ValueError("Kill requires a process_started event")
    data = event["data"]
    try:
        target = ProcessTarget.model_validate({k: data.get(k) for k in ProcessTarget.model_fields})
    except ValidationError as exc:
        raise ValueError("Process event must include PID, executable path and start time") from exc
    if not PureWindowsPath(target.exe).is_absolute():
        raise ValueError("Process executable path must be absolute")
    return target.model_dump(mode="json")


async def queue_command(
    device_id: str,
    action: Action,
    *,
    actor: str,
    reason: str,
    event_id: str | None = None,
    ttl_seconds: int = 120,
    alert_id: str | None = None,
    command_id: str | None = None,
) -> Command:
    if action not in {"lock_workstation", "kill_process"}:
        raise ValueError("Unsupported response action")
    if not actor.strip() or not reason.strip() or len(actor) > 256 or len(reason) > 500:
        raise ValueError("An actor and a reason (up to 500 characters) are required")
    if not 10 <= ttl_seconds <= 900:
        raise ValueError("Command lifetime must be 10..900 seconds")
    device = await Device.find_one(Device.device_id == device_id)
    if device is None or device.os != "windows":
        raise ValueError("Response commands require an enrolled Windows device")
    params = {}
    if action == "kill_process":
        event = (
            await Event.get_pymongo_collection().find_one(
                {"event_id": event_id, "device_id": device_id}
            )
            if event_id
            else None
        )
        if event is None:
            raise ValueError("Supply a process event ID belonging to this device")
        params = process_target(event)
    elif event_id:
        raise ValueError("Lock commands do not accept a process event")
    now = datetime.now(UTC)
    command = Command(
        command_id=command_id or "cmd_" + uuid4().hex,
        device_id=device_id,
        action=action,
        params=params,
        actor=actor,
        reason=reason,
        source_event_id=event_id,
        alert_id=alert_id,
        created_at=now,
        expires_at=now + timedelta(seconds=ttl_seconds),
        history=[{"status": "pending", "at": now, "actor": actor, "reason": reason}],
    )
    # Deterministic auto-response IDs make detection replay safe, including a crash after insert.
    saved = await Command.get_pymongo_collection().find_one_and_update(
        {"command_id": command.command_id},
        {"$setOnInsert": command.model_dump(exclude={"id"})},
        upsert=True,
        return_document=ReturnDocument.AFTER,
    )
    return Command.model_validate(saved)


async def deliver_commands(device_id: str) -> list[dict]:
    now = datetime.now(UTC)
    collection = Command.get_pymongo_collection()
    await collection.update_many(
        {
            "device_id": device_id,
            "status": {"$in": ["pending", "delivered"]},
            "expires_at": {"$lte": now},
        },
        {
            "$set": {"status": "expired", "lease_until": None},
            "$push": {"history": {"status": "expired", "at": now, "actor": "server"}},
        },
    )
    commands = []
    for _ in range(10):
        row = await collection.find_one_and_update(
            {
                "device_id": device_id,
                "expires_at": {"$gt": now},
                "$or": [
                    {"status": "pending"},
                    {"status": "delivered", "lease_until": {"$lte": now}},
                ],
            },
            {
                "$set": {"status": "delivered", "lease_until": now + timedelta(seconds=30)},
                "$inc": {"deliveries": 1},
                "$push": {"history": {"status": "delivered", "at": now, "actor": "server"}},
            },
            sort=[("created_at", 1)],
            return_document=ReturnDocument.AFTER,
        )
        if row is None:
            break
        commands.append(
            {
                k: row[k]
                for k in ("command_id", "device_id", "action", "params", "created_at", "expires_at")
            }
        )
    return commands


async def accept_results(device_id: str, results: list[CommandResult]) -> list[str]:
    acknowledged = []
    collection = Command.get_pymongo_collection()
    for result in results:
        now = datetime.now(UTC)
        row = await collection.find_one_and_update(
            {
                "command_id": result.command_id,
                "device_id": device_id,
                "deliveries": {"$gt": 0},
                "result": None,
            },
            {
                "$set": {
                    "status": result.status,
                    "result": result.model_dump(),
                    "result_received_at": now,
                    "lease_until": None,
                },
                "$push": {"history": {"status": result.status, "at": now, "actor": device_id}},
            },
            return_document=ReturnDocument.AFTER,
        )
        # Result uploads are idempotent. The first result wins, even if a later retry differs.
        if row is None:
            row = await collection.find_one(
                {"command_id": result.command_id, "device_id": device_id, "result": {"$ne": None}}
            )
        if row:
            acknowledged.append(result.command_id)
    return acknowledged


async def cancel_command(command_id: str, actor: str) -> bool:
    now = datetime.now(UTC)
    result = await Command.get_pymongo_collection().update_one(
        {"command_id": command_id, "status": "pending"},
        {
            "$set": {"status": "cancelled", "cancelled_by": actor, "cancelled_at": now},
            "$push": {"history": {"status": "cancelled", "at": now, "actor": actor}},
        },
    )
    return bool(result.modified_count)


async def auto_respond(event: dict, action: Action | None, alert_id: str, rule_id: str) -> None:
    settings = get_settings()
    if action is None or not settings.auto_response_enabled:
        return
    age = (datetime.now(UTC) - event["ts"]).total_seconds()
    if age < -5 or age > settings.auto_response_max_event_age_seconds:
        return  # Never act on a stale offline backlog or a future-dated event.
    if action == "kill_process":
        try:
            process_target(event)
        except ValueError:
            return
    device = await Device.find_one(Device.device_id == event["device_id"])
    if device is None or device.os != "windows":
        return
    # At most one automatic action per deduplicated alert, including after server restarts.
    key = hashlib.sha256((alert_id + ":" + action).encode()).hexdigest()[:32]
    await queue_command(
        event["device_id"],
        action,
        actor=f"rule:{rule_id}",
        reason=f"Automatic response: {rule_id}",
        event_id=event["event_id"] if action == "kill_process" else None,
        alert_id=alert_id,
        command_id="cmd_" + key,
    )
