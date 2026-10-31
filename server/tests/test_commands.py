import asyncio
from datetime import UTC, datetime, timedelta

import pytest

from app.core.config import get_settings
from app.models import Command, Device
from app.services.commands import cancel_command, deliver_commands, queue_command
from tests.conftest import enroll
from tests.test_detection import use_rule
from tests.test_ingest import make_event, upload


async def issue(creds, **overrides):
    params = {"actor": "cli:operator", "reason": "Contain lab incident", **overrides}
    return await queue_command(
        creds["device_id"], params.pop("action", "lock_workstation"), **params
    )


async def beat(api, creds, results=None):
    return await api.post(
        "/api/v1/agents/heartbeat",
        headers={"X-Device-Key": creds["api_key"]},
        json={"agent_version": "0.1.0", "command_results": results or []},
    )


def result(command_id, **overrides):
    return {
        "command_id": command_id,
        "status": "succeeded",
        "detail": "Lock request accepted",
        "finished_at": datetime.now(UTC).isoformat(),
        **overrides,
    }


async def test_heartbeat_delivers_only_own_commands_and_persists_result(api):
    creds, other = await enroll(api), await enroll(api)
    command = await issue(creds)
    assert (await beat(api, other)).json()["commands"] == []
    payload = (await beat(api, creds)).json()
    assert payload["commands"][0]["command_id"] == command.command_id
    assert payload["commands"][0]["device_id"] == creds["device_id"]
    assert payload["commands"][0]["params"] == {}
    assert (await beat(api, creds)).json()["commands"] == []  # delivery lease
    assert (await beat(api, other, [result(command.command_id)])).json()[
        "acknowledged_results"
    ] == []
    completed = (await beat(api, creds, [result(command.command_id)])).json()
    assert completed["acknowledged_results"] == [command.command_id]
    assert completed["commands"] == []
    saved = await Command.find_one(Command.command_id == command.command_id)
    assert saved.status == "succeeded"
    assert [item["status"] for item in saved.history] == ["pending", "delivered", "succeeded"]
    assert saved.actor == "cli:operator" and saved.reason == "Contain lab incident"


async def test_duplicate_ack_first_result_wins_and_is_not_delivered_again(api):
    creds = await enroll(api)
    command = await issue(creds)
    await beat(api, creds)
    for status in ("succeeded", "failed"):
        response = await beat(api, creds, [result(command.command_id, status=status)])
        assert response.json()["acknowledged_results"] == [command.command_id]
    saved = await Command.find_one(Command.command_id == command.command_id)
    assert saved.result.status == "succeeded"
    assert len(saved.history) == 3


async def test_pending_command_cannot_be_completed_by_unsolicited_result(api):
    creds = await enroll(api)
    command = await issue(creds)
    # The result is processed before delivery, so a guessed pending ID cannot bypass delivery.
    response = await beat(api, creds, [result(command.command_id)])
    assert response.json()["acknowledged_results"] == []
    assert response.json()["commands"][0]["command_id"] == command.command_id


async def test_lease_retry_and_concurrent_delivery(api):
    creds = await enroll(api)
    command = await issue(creds)
    first, second = await asyncio.gather(
        deliver_commands(creds["device_id"]), deliver_commands(creds["device_id"])
    )
    assert len(first) + len(second) == 1
    await Command.get_pymongo_collection().update_one(
        {"command_id": command.command_id},
        {"$set": {"lease_until": datetime.now(UTC) - timedelta(seconds=1)}},
    )
    again = await deliver_commands(creds["device_id"])
    assert again[0]["command_id"] == command.command_id
    saved = await Command.find_one(Command.command_id == command.command_id)
    assert saved.deliveries == 2


async def test_expired_commands_do_not_execute_but_late_results_are_recorded(api):
    creds = await enroll(api)
    pending, delivered = await issue(creds), await issue(creds)
    await Command.get_pymongo_collection().update_one(
        {"command_id": pending.command_id},
        {"$set": {"expires_at": datetime.now(UTC) - timedelta(seconds=1)}},
    )
    response = (await beat(api, creds)).json()
    assert [c["command_id"] for c in response["commands"]] == [delivered.command_id]
    assert (await Command.find_one(Command.command_id == pending.command_id)).status == "expired"
    await Command.get_pymongo_collection().update_one(
        {"command_id": delivered.command_id},
        {"$set": {"expires_at": datetime.now(UTC) - timedelta(seconds=1)}},
    )
    await beat(api, creds)
    assert (await Command.find_one(Command.command_id == delivered.command_id)).status == "expired"
    await beat(api, creds, [result(delivered.command_id)])
    assert (
        await Command.find_one(Command.command_id == delivered.command_id)
    ).status == "succeeded"


async def test_cancel_only_undelivered_commands(api):
    creds = await enroll(api)
    pending, delivered = await issue(creds), await issue(creds)
    assert await cancel_command(pending.command_id, "cli:other")
    await beat(api, creds)
    assert not await cancel_command(delivered.command_id, "cli:other")
    saved = await Command.find_one(Command.command_id == pending.command_id)
    assert saved.cancelled_by == "cli:other"
    assert saved.history[-1]["status"] == "cancelled"


async def test_kill_requires_process_identity_from_the_same_device(api):
    creds, other = await enroll(api), await enroll(api)
    event = make_event(
        1,
        action="process_started",
        data={
            "pid": 12345,
            "exe": r"C:\Lab\worker.exe",
            "create_time": datetime.now(UTC).isoformat(),
        },
    )
    assert (await upload(api, creds, [event])).status_code == 200
    command = await issue(creds, action="kill_process", event_id=event["event_id"])
    assert command.params["pid"] == 12345
    assert command.source_event_id == event["event_id"]
    for device, event_id in ((other, event["event_id"]), (creds, None), (creds, "unknown")):
        with pytest.raises(ValueError):
            await issue(device, action="kill_process", event_id=event_id)
    missing = make_event(2, action="process_started", data={"pid": 12345})
    await upload(api, creds, [missing])
    with pytest.raises(ValueError, match="PID"):
        await issue(creds, action="kill_process", event_id=missing["event_id"])


async def test_response_actions_validate_reason_ttl_platform_and_allowlist(api):
    creds = await enroll(api)
    for overrides in (
        {"action": "shell"},
        {"reason": "  "},
        {"ttl_seconds": 0},
        {"ttl_seconds": 901},
        {"event_id": "not-for-lock"},
    ):
        with pytest.raises(ValueError):
            await issue(creds, **overrides)
    await Device.get_pymongo_collection().update_one(
        {"device_id": creds["device_id"]}, {"$set": {"os": "linux"}}
    )
    with pytest.raises(ValueError, match="Windows"):
        await issue(creds)
    assert await Command.count() == 0


async def test_result_schema_rejects_unknown_status_naive_time_and_extra_fields(api):
    creds = await enroll(api)
    command = await issue(creds)
    for changes in (
        {"status": "whatever"},
        {"finished_at": "2026-10-28T12:00:00"},
        {"detail": "x" * 501},
        {"shell": "run"},
    ):
        response = await beat(api, creds, [result(command.command_id, **changes)])
        assert response.status_code == 422


async def test_auto_response_opt_in_recent_event_and_deduplication(api, tmp_path):
    use_rule(tmp_path, response={"auto_action": "lock_workstation"})
    creds = await enroll(api)
    await upload(api, creds, [make_event(1, category="auth", action="logon_failed")])
    assert await Command.count() == 0
    get_settings().auto_response_enabled = True
    stale = make_event(
        2,
        category="auth",
        action="logon_failed",
        ts=(datetime.now(UTC) - timedelta(minutes=10)).isoformat(),
    )
    await upload(api, creds, [stale])
    assert await Command.count() == 0
    batch = [make_event(i, category="auth", action="logon_failed") for i in (3, 4)]
    await upload(api, creds, batch)
    await upload(api, creds, batch)
    assert await Command.count() == 1
    command = await Command.find_one({})
    assert command.actor == "rule:TEST-RULE" and command.alert_id is not None


async def test_auto_kill_never_infers_pid_from_unrelated_event(api, tmp_path):
    get_settings().auto_response_enabled = True
    use_rule(tmp_path, response={"auto_action": "kill_process"})
    creds = await enroll(api)
    await upload(
        api,
        creds,
        [
            make_event(
                1,
                category="auth",
                action="logon_failed",
                data={
                    "pid": 12345,
                    "exe": r"C:\Lab\worker.exe",
                    "create_time": datetime.now(UTC).isoformat(),
                },
            )
        ],
    )
    assert await Command.count() == 0


async def test_defender_events_create_matching_alerts(api):
    from app.models import Alert

    creds = await enroll(api)
    for seq, action in enumerate(
        [
            "defender_threat_detected",
            "defender_action_failed",
            "defender_protection_disabled",
            "defender_action_taken",
            "defender_config_changed",
        ],
        start=1,
    ):
        await upload(api, creds, [make_event(seq, category="system", action=action)])
    assert {a.rule_id for a in await Alert.find_all().to_list()} == {
        "ST-DEFENDER-001",
        "ST-DEFENDER-002",
        "ST-DEFENDER-003",
    }
