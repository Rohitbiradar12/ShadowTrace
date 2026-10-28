from app.models import Device
from tests.conftest import enroll, make_enrollment_token


async def test_enroll_returns_device_credentials(api):
    creds = await enroll(api)

    assert creds["device_id"].startswith("dev_")
    assert creds["api_key"].startswith("stk_")
    device = await Device.find_one(Device.device_id == creds["device_id"])
    assert device.hostname == "LAB-PC-01"
    assert device.api_key_hash != creds["api_key"]  # only the hash is stored


async def test_single_use_token_cannot_enroll_twice(api):
    token = await make_enrollment_token(max_uses=1)
    await enroll(api, token)

    response = await api.post(
        "/api/v1/agents/enroll",
        json={
            "enrollment_token": token,
            "hostname": "LAB-PC-02",
            "os": "windows",
            "os_version": "x",
            "agent_version": "0.1.0",
        },
    )
    assert response.status_code == 403


async def test_multi_use_token_enrolls_several_devices(api):
    token = await make_enrollment_token(max_uses=3)
    ids = {(await enroll(api, token))["device_id"] for _ in range(3)}
    assert len(ids) == 3


async def test_expired_token_is_rejected(api):
    token = await make_enrollment_token(hours=-1)
    response = await api.post(
        "/api/v1/agents/enroll",
        json={
            "enrollment_token": token,
            "hostname": "x",
            "os": "linux",
            "os_version": "x",
            "agent_version": "0.1.0",
        },
    )
    assert response.status_code == 403


async def test_heartbeat_updates_last_seen_and_stats(api):
    creds = await enroll(api)

    response = await api.post(
        "/api/v1/agents/heartbeat",
        headers={"X-Device-Key": creds["api_key"]},
        json={"agent_version": "0.1.1", "uptime_seconds": 42, "stats": {"buffered_events": 7}},
    )

    assert response.status_code == 200
    assert response.json()["commands"] == []
    device = await Device.find_one(Device.device_id == creds["device_id"])
    assert device.agent_version == "0.1.1"
    assert device.stats == {"buffered_events": 7, "uptime_seconds": 42}


async def test_heartbeat_rejects_unknown_key(api):
    response = await api.post(
        "/api/v1/agents/heartbeat",
        headers={"X-Device-Key": "stk_not-a-real-key"},
        json={"agent_version": "0.1.0"},
    )
    assert response.status_code == 401
