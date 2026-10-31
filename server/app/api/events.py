from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel

from app.api.deps import CurrentDevice
from app.core.config import get_settings
from app.detection.service import detect_device
from app.models.event import EventIn
from app.services.ingest import IntegrityError, ingest_batch

router = APIRouter(prefix="/events", tags=["events"])


class BatchIn(BaseModel):
    events: list[EventIn]


class BatchOut(BaseModel):
    accepted: int
    duplicates: int


@router.post("/batch", response_model=BatchOut)
async def upload_batch(body: BatchIn, device: CurrentDevice) -> BatchOut:
    limit = get_settings().max_batch_events
    if len(body.events) > limit:
        raise HTTPException(status.HTTP_413_CONTENT_TOO_LARGE, f"At most {limit} events per batch")
    try:
        result = await ingest_batch(device.device_id, body.events)
    except IntegrityError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
    # Also run on duplicate retries: an earlier attempt may have committed events and
    # stopped before detection finished. External notification delivery is asynchronous.
    await detect_device(device.device_id)
    return BatchOut(accepted=result.accepted, duplicates=result.duplicates)
