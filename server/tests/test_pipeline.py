import asyncio
import runpy
from pathlib import Path

from app.core.config import get_settings
from app.forensics.verify import verify_device_chain
from app.main import app, lifespan
from app.models import Alert, Device, Notification
from app.models.event import EventIn
from app.services.ingest import ingest_batch
from tests.conftest import enroll
from tests.test_ingest import upload


def demo_events():
    demo = Path(__file__).resolve().parents[2] / "scripts" / "demo_pipeline.py"
    return runpy.run_path(str(demo))["build_events"]()


async def test_synthetic_demo_creates_three_alerts_and_keeps_chain_valid(api):
    creds = await enroll(api)
    response = await upload(api, creds, demo_events())
    assert response.json() == {"accepted": 7, "duplicates": 0}
    alerts = await Alert.find_all().to_list()
    assert {a.rule_id for a in alerts} == {"ST-AUTH-001", "ST-BROWSER-001", "ST-WIFI-001"}
    device = await Device.find_one(Device.device_id == creds["device_id"])
    assert (await verify_device_chain(device)).ok
    assert device.detection_index == 6
    assert await Notification.count() == 6


async def test_startup_worker_recovers_events_committed_before_detection(api):
    creds = await enroll(api)
    await ingest_batch(creds["device_id"], [EventIn.model_validate(e) for e in demo_events()])
    assert await Alert.count() == 0
    get_settings().detection_poll_seconds = 0.02
    async with lifespan(app):
        for _ in range(100):
            if await Alert.count() == 3:
                break
            await asyncio.sleep(0.02)
        assert await Alert.count() == 3
