from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel

from app.api.deps import CurrentDevice
from app.core.config import get_settings
from app.models.event import EventIn
from app.services.ingest import ingest_batch

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
    result = await ingest_batch(device.device_id, body.events)
    return BatchOut(accepted=result.accepted, duplicates=result.duplicates)
