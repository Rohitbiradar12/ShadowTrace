from datetime import UTC, datetime, timedelta

import pytest
import yaml
from pydantic import ValidationError

from app.core.config import get_settings
from app.detection.conditions import MISSING, match_conditions
from app.detection.engine import get_engine
from app.detection.intel import IndicatorList, IntelLists
from app.detection.rules import Rule, Threshold
from app.models import Alert, AlertHit, Device, Notification
from tests.conftest import enroll
from tests.test_ingest import make_event, upload


def use_rule(tmp_path, **overrides):
    rule = {
        "id": "TEST-RULE",
        "title": "Test detection",
        "severity": "high",
        "category": "auth",
        "match": {"action": "logon_failed"},
        **overrides,
    }
    (tmp_path / "test.yaml").write_text(yaml.safe_dump(rule), encoding="utf-8")
    get_settings().rules_dir = tmp_path
    get_engine.cache_clear()


def failure(seq, user="student", ts=None):
    return make_event(
        seq,
        category="auth",
        action="logon_failed",
        data={"target_user": user},
        ts=ts or datetime.now(UTC).isoformat(),
    )


@pytest.mark.parametrize(
    ("matcher", "value", "expected"),
    [
        ({"eq": "abc"}, "abc", True),
        ({"ne": "abc"}, MISSING, True),
        ({"in": [1, 2]}, 2, True),
        ({"not_in": [1, 2]}, 3, True),
        ({"exists": False}, MISSING, True),
        ({"gt": 2}, 3, True),
        ({"ge": 3}, 3, True),
        ({"lt": 3}, 2, True),
        ({"le": 3}, 3, True),
        ({"contains": "b"}, "abc", True),
        ({"icontains": "B"}, "abc", True),
        ({"contains_any": ["x", "b"]}, "abc", True),
        ({"icontains_any": ["X", "B"]}, "abc", True),
        ({"startswith": ["a", "b"]}, "abc", True),
        ({"istartswith": "A"}, "abc", True),
        ({"endswith": "c"}, "abc", True),
        ({"iendswith": "C"}, "abc", True),
        ({"regex": "^a.c$"}, "abc", True),
        ({"iregex": "^A.C$"}, "abc", True),
        ({"gt": 1}, "invalid", False),
        ({"icontains": "a"}, None, False),
    ],
)
def test_condition_operators(matcher, value, expected):
    event = {} if value is MISSING else {"data": {"value": value}}
    assert match_conditions(event, {"data.value": matcher}) is expected


def test_rules_validate_durations_operators_and_required_match():
    assert Threshold(count=5, within="2m", group_by=["data.target_user"]).window_seconds == 120
    for matcher in ({"unknown": 1}, {"regex": "["}, {"exists": "false"}, {}):
        with pytest.raises(ValidationError):
            Rule(id="TEST-RULE", title="Invalid", match={"action": matcher})
    with pytest.raises(ValidationError):
        Rule(id="TEST-RULE", title="Missing conditions")


def test_starter_pack_and_local_lists_load():
    engine = get_engine()
    assert len(engine.rules) == 27
    assert engine.intel.contains("bad_domains", "sub.DEMO-BAD.example")
    assert not engine.intel.contains("bad_domains", "not-demo-bad.example")
    lists = IntelLists(
        {
            "network": IndicatorList(kind="ip", values=["192.0.2.0/24"]),
            "paths": IndicatorList(kind="path", values=[r"C:\Sensitive"]),
        }
    )
    assert lists.contains("network", "192.0.2.5")
    assert not lists.contains("network", "::1")
    assert lists.contains("paths", r"c:\sensitive\report.txt")
    assert not lists.contains("paths", r"c:\sensitive-other\report.txt")


async def test_single_events_deduplicate_and_upload_retry_is_idempotent(api, tmp_path):
    use_rule(tmp_path)
    creds = await enroll(api)
    batch = [failure(1)]
    assert (await upload(api, creds, batch)).status_code == 200
    await upload(api, creds, batch)
    await upload(api, creds, [failure(2)])
    alert = await Alert.find_one(Alert.rule_id == "TEST-RULE")
    assert alert.occurrence_count == 2
    assert len(alert.event_ids) == 2
    assert await Alert.count() == 1
    assert await AlertHit.count() == 2
    assert await Notification.count() == 2
    assert all(n.status == "disabled" for n in await Notification.find_all().to_list())


async def test_threshold_survives_engine_restart_and_separates_users_and_devices(api, tmp_path):
    use_rule(tmp_path, threshold={"count": 3, "within": "120s", "group_by": ["data.target_user"]})
    a, b = await enroll(api), await enroll(api)
    await upload(api, a, [failure(1), failure(2, user="someone_else")])
    await upload(api, b, [failure(1), failure(2)])
    get_engine.cache_clear()
    await upload(api, a, [failure(3)])
    assert await Alert.count() == 0
    await upload(api, a, [failure(4)])
    alert = await Alert.find_one(Alert.rule_id == "TEST-RULE")
    assert alert.device_id == a["device_id"]
    assert len(alert.event_ids) == 3


async def test_threshold_handles_out_of_order_event_times(api, tmp_path):
    use_rule(tmp_path, threshold={"count": 3, "within": "60s", "group_by": ["data.target_user"]})
    creds = await enroll(api)
    now = datetime.now(UTC)
    await upload(
        api,
        creds,
        [
            failure(1, ts=(now + timedelta(seconds=20)).isoformat()),
            failure(2, ts=(now + timedelta(seconds=40)).isoformat()),
        ],
    )
    assert await Alert.count() == 0
    await upload(api, creds, [failure(3, ts=now.isoformat())])
    assert await Alert.count() == 1


async def test_threshold_does_not_combine_events_outside_window(api, tmp_path):
    use_rule(tmp_path, threshold={"count": 3, "within": "60s", "group_by": ["data.target_user"]})
    creds = await enroll(api)
    now = datetime.now(UTC)
    await upload(
        api,
        creds,
        [
            failure(1, ts=(now - timedelta(seconds=61)).isoformat()),
            failure(2, ts=(now + timedelta(seconds=61)).isoformat()),
            failure(3, ts=now.isoformat()),
        ],
    )
    assert await Alert.count() == 0


async def test_cursor_retry_after_alert_write_does_not_double_count(api, tmp_path, monkeypatch):
    from app.detection import service

    use_rule(tmp_path)
    creds = await enroll(api)
    original = service.record_match

    async def crash(event, match):
        await original(event, match)
        raise RuntimeError("simulated detection crash")

    monkeypatch.setattr(service, "record_match", crash)
    batch = [failure(1)]
    with pytest.raises(RuntimeError, match="simulated detection crash"):
        await upload(api, creds, batch)
    monkeypatch.setattr(service, "record_match", original)
    await upload(api, creds, batch)
    alert = await Alert.find_one(Alert.rule_id == "TEST-RULE")
    device = await Device.find_one(Device.device_id == creds["device_id"])
    assert alert.occurrence_count == 1
    assert device.detection_index == 0
    assert await AlertHit.count() == 1
    assert await Notification.count() == 2


async def test_exclusion_and_disabled_rule_suppress_alerts(api, tmp_path):
    use_rule(tmp_path, exclude=[{"data.target_user": "trusted"}])
    creds = await enroll(api)
    await upload(api, creds, [failure(1, user="trusted")])
    assert await Alert.count() == 0
    use_rule(tmp_path, enabled=False)
    await upload(api, creds, [failure(2)])
    assert await Alert.count() == 0


async def test_dedup_expiry_opens_a_new_alert(api, tmp_path):
    use_rule(tmp_path)
    creds = await enroll(api)
    await upload(api, creds, [failure(1)])
    await Alert.get_pymongo_collection().update_many(
        {},
        {
            "$set": {
                "last_seen": datetime.now(UTC) - timedelta(seconds=601),
            }
        },
    )
    await upload(api, creds, [failure(2)])
    assert await Alert.count() == 2


async def test_unknown_usb_includes_missing_serial_and_respects_allowlist(api):
    get_engine().intel.values["allowed_usb_serials"].add("TRUSTED")
    creds = await enroll(api)
    for seq, serial in enumerate(["TRUSTED", None, "UNLISTED"], start=1):
        response = await upload(
            api,
            creds,
            [
                make_event(
                    seq,
                    category="usb",
                    action="device_connected",
                    data={"serial": serial},
                )
            ],
        )
        assert response.status_code == 200
    alert = await Alert.find_one(Alert.rule_id == "ST-USB-001")
    assert alert.occurrence_count == 2
    assert await Alert.count() == 1
