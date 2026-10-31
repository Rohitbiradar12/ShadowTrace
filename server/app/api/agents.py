from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel, Field

from app.api.deps import CurrentDevice
from app.core.config import get_settings
from app.core.security import (
    API_KEY_PREFIX,
    generate_device_id,
    generate_token,
    hash_token,
)
from app.models import Device, EnrollmentToken
from app.models.command import CommandResult
from app.models.device import OsName
from app.services.commands import accept_results, deliver_commands

router = APIRouter(prefix="/agents", tags=["agents"])


class EnrollIn(BaseModel):
    enrollment_token: str
    hostname: str = Field(min_length=1, max_length=255)
    os: OsName
    os_version: str = Field(max_length=255)
    agent_version: str = Field(max_length=32)


class EnrollOut(BaseModel):
    device_id: str
    api_key: str


class HeartbeatIn(BaseModel):
    agent_version: str = Field(max_length=32)
    uptime_seconds: float = 0
    stats: dict[str, Any] = Field(default_factory=dict)
    command_results: list[CommandResult] = Field(default_factory=list, max_length=100)


class HeartbeatOut(BaseModel):
    server_time: datetime
    heartbeat_interval_seconds: int
    commands: list[dict[str, Any]] = Field(default_factory=list)
    acknowledged_results: list[str] = Field(default_factory=list)


@router.post("/enroll", response_model=EnrollOut, status_code=status.HTTP_201_CREATED)
async def enroll(body: EnrollIn, request: Request) -> EnrollOut:
    now = datetime.now(UTC)
    # Atomic claim so a single-use token cannot enroll two devices concurrently.
    token = await EnrollmentToken.get_pymongo_collection().find_one_and_update(
        {
            "token_hash": hash_token(body.enrollment_token),
            "expires_at": {"$gt": now},
            "$expr": {"$lt": ["$uses", "$max_uses"]},
        },
        {"$inc": {"uses": 1}},
    )
    if token is None:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Invalid, expired or used enrollment token")

    api_key = generate_token(API_KEY_PREFIX)
    device = Device(
        device_id=generate_device_id(),
        hostname=body.hostname,
        os=body.os,
        os_version=body.os_version,
        agent_version=body.agent_version,
        api_key_hash=hash_token(api_key),
        last_seen=now,
        last_ip=request.client.host if request.client else None,
    )
    await device.insert()
    return EnrollOut(device_id=device.device_id, api_key=api_key)


@router.post("/heartbeat", response_model=HeartbeatOut)
async def heartbeat(body: HeartbeatIn, device: CurrentDevice, request: Request) -> HeartbeatOut:
    now = datetime.now(UTC)
    await device.set(
        {
            Device.last_seen: now,
            Device.last_ip: request.client.host if request.client else None,
            Device.agent_version: body.agent_version,
            Device.stats: {**body.stats, "uptime_seconds": body.uptime_seconds},
        }
    )
    return HeartbeatOut(
        server_time=now,
        heartbeat_interval_seconds=get_settings().heartbeat_interval_seconds,
        acknowledged_results=await accept_results(device.device_id, body.command_results),
        commands=await deliver_commands(device.device_id),
    )
