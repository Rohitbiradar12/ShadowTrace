import asyncio
import csv
import io
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import httpx
import pytest
from argon2 import PasswordHasher
from bson import ObjectId
from pydantic import SecretStr

from app.api import auth as auth_api
from app.core.config import get_settings
from app.main import app
from app.models import Alert, Command, Device, Event
from app.models.user import Session, User
from app.services.auth import PASSWORDS, create_user
from tests.conftest import enroll
from tests.test_ingest import make_event, upload

PASSWORD = "test-password-only-123"


async def login(api, role="admin", username="operator"):
    if not await User.find_one(User.username == username):
        await create_user(username, PASSWORD, role, "test")
    result = await api.post("/api/v1/auth/login", json={"username": username, "password": PASSWORD})
    assert result.status_code == 200, result.text
    api.headers["X-CSRF-Token"] = result.json()["csrf_token"]
    return result


async def detection(api):
    creds = await enroll(api)
    event = make_event(
        1,
        category="network",
        action="connection_opened",
        data={"remote_ip": "203.0.113.66", "path": "<script>alert('x')</script>"},
        user='=HYPERLINK("https://example.invalid")',
    )
    await upload(api, creds, [event])
    alert = await Alert.find_one(Alert.device_id == creds["device_id"])
    return creds, event, alert


async def test_dashboard_shell_and_assets_have_security_headers(api):
    response = await api.get("/")
    assert response.status_code == 200
    assert "Sign in to your workspace" in response.text
    assert "frame-ancestors 'none'" in response.headers["content-security-policy"]
    assert response.headers["x-content-type-options"] == "nosniff"
    for asset in ("app.js", "api.js", "pages.js", "ui.js", "app.css", "report.css", "mark.svg"):
        assert (await api.get("/assets/" + asset)).status_code == 200


@pytest.mark.parametrize(
    "path",
    [
        "overview",
        "devices",
        "alerts",
        "events",
        "commands",
        "rules",
        "settings",
        "users",
        "audit",
        "events.csv",
        "enrollment-tokens",
    ],
)
async def test_dashboard_data_requires_login(api, path):
    response = await api.get("/api/v1/ui/" + path)
    assert response.status_code == 401
    assert response.headers["cache-control"] == "no-store"


async def test_login_session_cookie_hashes_and_logout(api):
    result = await login(api)
    cookie = result.headers["set-cookie"]
    assert "HttpOnly" in cookie and "SameSite=strict" in cookie
    user = await User.find_one(User.username == "operator")
    assert user.password_hash.startswith("$argon2id$") and PASSWORD not in user.password_hash
    session = await Session.find_one({})
    assert session.token_hash != api.cookies.get("st_session")
    assert "password_hash" not in result.text
    assert (await api.get("/api/v1/auth/me")).json()["user"]["role"] == "admin"
    token = api.cookies.get("st_session")
    assert (await api.post("/api/v1/auth/logout")).status_code == 200
    api.cookies.set("st_session", token)
    assert (await api.get("/api/v1/auth/me")).status_code == 401


async def test_login_rotates_existing_session_and_expiry_is_enforced(api):
    await login(api)
    old = api.cookies.get("st_session")
    await login(api)
    assert api.cookies.get("st_session") != old
    assert await Session.count() == 1
    await Session.get_pymongo_collection().update_many(
        {}, {"$set": {"expires_at": datetime.now(UTC) - timedelta(seconds=1)}}
    )
    assert (await api.get("/api/v1/auth/me")).status_code == 401


async def test_secure_cookie_configuration(api):
    get_settings().session_cookie_secure = True
    response = await login(api)
    assert "Secure" in response.headers["set-cookie"]


async def test_csrf_and_origin_protect_mutations_including_login(api):
    response = await api.post(
        "/api/v1/auth/login",
        headers={"Origin": "https://attacker.invalid"},
        json={"username": "nobody", "password": "anything"},
    )
    assert response.status_code == 403
    await login(api)
    csrf = api.headers.pop("X-CSRF-Token")
    assert (await api.post("/api/v1/auth/logout")).status_code == 403
    api.headers["X-CSRF-Token"] = csrf
    assert (
        await api.post("/api/v1/auth/logout", headers={"Origin": "https://attacker.invalid"})
    ).status_code == 403
    assert (
        await api.post("/api/v1/auth/logout", headers={"Origin": "http://test"})
    ).status_code == 200


async def test_malformed_origin_and_non_ascii_csrf_are_rejected(api):
    rejected = await api.post(
        "/api/v1/auth/login",
        headers={"Origin": "http://["},
        json={"username": "nobody", "password": "anything"},
    )
    assert rejected.status_code == 403
    await login(api)
    rejected = await api.post("/api/v1/auth/logout", headers={b"x-csrf-token": b"\xff"})
    assert rejected.status_code == 403


@pytest.mark.parametrize("change", ["password", "disabled"])
async def test_login_cannot_restore_credentials_changed_during_verification(
    api, monkeypatch, change
):
    user = await create_user("operator", PASSWORD, "admin", "test")
    # Exercise the rehash path as well as normal credential verification.
    await user.set(
        {User.password_hash: PasswordHasher(time_cost=1, memory_cost=8192).hash(PASSWORD)}
    )
    started, resume = asyncio.Event(), asyncio.Event()
    to_thread = asyncio.to_thread

    async def paused_verification(function, *args, **kwargs):
        result = await to_thread(function, *args, **kwargs)
        if function is auth_api.verify_password:
            started.set()
            await resume.wait()
        return result

    monkeypatch.setattr(auth_api.asyncio, "to_thread", paused_verification)
    attempt = asyncio.create_task(
        api.post("/api/v1/auth/login", json={"username": "operator", "password": PASSWORD})
    )
    try:
        await asyncio.wait_for(started.wait(), 5)
        replacement = await to_thread(PASSWORDS.hash, "replacement-password-456")
        updates = {"password_hash": replacement} if change == "password" else {"disabled": True}
        await User.get_pymongo_collection().update_one(
            {"_id": user.id}, {"$set": updates, "$inc": {"session_version": 1}}
        )
    finally:
        resume.set()
    response = await attempt
    assert response.status_code == 401 and await Session.count() == 0
    current = await User.get(user.id)
    if change == "password":
        assert current.password_hash == replacement
    else:
        assert current.disabled


async def test_password_change_does_not_overwrite_a_concurrent_reset(api, monkeypatch):
    await login(api)
    started, resume = asyncio.Event(), asyncio.Event()
    to_thread = asyncio.to_thread

    async def paused_verification(function, *args, **kwargs):
        result = await to_thread(function, *args, **kwargs)
        if function is auth_api.verify_password:
            started.set()
            await resume.wait()
        return result

    monkeypatch.setattr(auth_api.asyncio, "to_thread", paused_verification)
    attempt = asyncio.create_task(
        api.post(
            "/api/v1/auth/password",
            json={"current_password": PASSWORD, "new_password": "racing-password-456"},
        )
    )
    try:
        await asyncio.wait_for(started.wait(), 5)
        replacement = await to_thread(PASSWORDS.hash, "recovered-password-789")
        await User.get_pymongo_collection().update_one(
            {"username": "operator"},
            {"$set": {"password_hash": replacement}, "$inc": {"session_version": 1}},
        )
    finally:
        resume.set()
    assert (await attempt).status_code == 409
    current = await User.find_one(User.username == "operator")
    assert current.password_hash == replacement and current.session_version == 1
    assert (await api.get("/api/v1/auth/me")).status_code == 401


async def test_login_throttling_and_generic_failures(api):
    await create_user("operator", PASSWORD, "admin", "test")
    responses = [
        await api.post("/api/v1/auth/login", json={"username": "operator", "password": "wrong"})
        for _ in range(11)
    ]
    assert responses[0].status_code == 401
    assert responses[-1].status_code == 429
    assert "Retry-After" in responses[-1].headers
    absent = await api.post("/api/v1/auth/login", json={"username": "absent", "password": "wrong"})
    assert absent.json() == responses[0].json()


async def test_viewer_cannot_triage_command_or_manage_configuration(api):
    creds, _, alert = await detection(api)
    await login(api, "viewer")
    for path in ("overview", "alerts", "devices", "events", "rules", "commands"):
        assert (await api.get("/api/v1/ui/" + path)).status_code == 200
    for path in ("settings", "users", "audit", "enrollment-tokens"):
        assert (await api.get("/api/v1/ui/" + path)).status_code == 403
    assert (
        await api.patch(f"/api/v1/ui/alerts/{alert.alert_id}", json={"status": "resolved"})
    ).status_code == 403
    response = await api.post(
        "/api/v1/ui/commands",
        json={
            "device_id": creds["device_id"],
            "action": "lock_workstation",
            "reason": "test",
            "request_id": str(uuid4()),
        },
    )
    assert response.status_code == 403 and await Command.count() == 0


async def test_analyst_triage_audit_and_command_idempotency(api):
    creds, _, alert = await detection(api)
    await login(api, "analyst")
    response = await api.patch(
        f"/api/v1/ui/alerts/{alert.alert_id}",
        json={"status": "investigating", "note": "<script>unsafe</script>"},
    )
    assert response.status_code == 200
    assert response.json()["history"][0]["actor"] == "user:operator"
    command = {
        "device_id": creds["device_id"],
        "alert_id": alert.alert_id,
        "action": "lock_workstation",
        "reason": "Contain test incident",
        "request_id": str(uuid4()),
    }
    first = await api.post("/api/v1/ui/commands", json=command)
    second = await api.post("/api/v1/ui/commands", json=command)
    assert first.status_code == second.status_code == 201
    assert first.json()["command_id"] == second.json()["command_id"]
    assert await Command.count() == 1
    assert (
        await api.post("/api/v1/ui/commands", json={**command, "ttl_seconds": 900})
    ).status_code == 409
    command["reason"] = "Different action request"
    assert (await api.post("/api/v1/ui/commands", json=command)).status_code == 409
    command_id = first.json()["command_id"]
    assert (await api.get(f"/api/v1/ui/commands/{command_id}")).status_code == 200
    assert (await api.post(f"/api/v1/ui/commands/{command_id}/cancel")).status_code == 200
    assert (await api.post(f"/api/v1/ui/commands/{command_id}/cancel")).status_code == 409
    assert (await api.get("/api/v1/ui/settings")).status_code == 403


async def test_cross_device_alert_command_link_is_rejected(api):
    _, _, alert = await detection(api)
    other = await enroll(api)
    await login(api)
    response = await api.post(
        "/api/v1/ui/commands",
        json={
            "device_id": other["device_id"],
            "alert_id": alert.alert_id,
            "action": "lock_workstation",
            "reason": "test",
            "request_id": str(uuid4()),
        },
    )
    assert response.status_code == 400
    assert await Command.count() == 0


async def test_event_filters_literal_search_pagination_and_csv_formula_safety(api):
    creds, event, _ = await detection(api)
    await login(api)
    response = await api.get(
        "/api/v1/ui/events",
        params={
            "device_id": creds["device_id"],
            "q": "203.0.113.66",
            "category": "network",
            "limit": 1,
        },
    )
    assert response.json()["total"] == 1
    assert response.json()["items"][0]["event_id"] == event["event_id"]
    assert (await api.get("/api/v1/ui/events", params={"q": ".*"})).json()["total"] == 0
    assert (await api.get("/api/v1/ui/events", params={"offset": 1})).json()["items"] == []
    assert (await api.get("/api/v1/ui/events", params={"limit": 10000})).status_code == 422
    assert (
        await api.get(
            "/api/v1/ui/events",
            params={"start": "2026-10-31T00:00:00Z", "end": "2026-10-01T00:00:00Z"},
        )
    ).status_code == 422
    export = await api.get("/api/v1/ui/events.csv", params={"device_id": creds["device_id"]})
    assert export.status_code == 200 and export.headers["x-export-limit"] == "5000"
    rows = list(csv.DictReader(io.StringIO(export.text)))
    assert rows[0]["user"].startswith("'=HYPERLINK")
    assert rows[0]["event_id"] == event["event_id"]


async def test_device_overview_rules_and_settings_do_not_expose_secrets(api):
    creds, _, _ = await detection(api)
    await login(api)
    get_settings().telegram_bot_token = SecretStr("private-test-token")
    get_settings().smtp_password = SecretStr("private-smtp-password")
    data = (await api.get("/api/v1/ui/overview")).json()
    assert data["devices"] == 1 and data["events_24h"] == 1 and data["open_alerts"] == 1
    assert data["severity"]["critical"] == 1 and sum(r["count"] for r in data["trend"]) == 1
    for path in ("/devices", "/devices/" + creds["device_id"], "/settings", "/users"):
        response = await api.get("/api/v1/ui" + path)
        assert response.status_code == 200
        assert "api_key_hash" not in response.text and "password_hash" not in response.text
        assert (
            "private-test-token" not in response.text
            and "private-smtp-password" not in response.text
        )
    assert len((await api.get("/api/v1/ui/rules")).json()["items"]) == 27


async def test_user_management_revokes_sessions_and_preserves_last_admin(api):
    await login(api)
    assert (
        await api.patch("/api/v1/ui/users/operator", json={"role": "viewer"})
    ).status_code == 400
    assert (
        await api.patch("/api/v1/ui/users/operator", json={"disabled": True})
    ).status_code == 400
    assert (
        await api.post(
            "/api/v1/ui/users",
            json={"username": "analyst", "password": PASSWORD, "role": "analyst"},
        )
    ).status_code == 201
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as other:
        await login(other, "analyst", "analyst")
        assert (
            await api.patch("/api/v1/ui/users/analyst", json={"disabled": True})
        ).status_code == 200
        assert (await other.get("/api/v1/auth/me")).status_code == 401


async def test_password_change_revokes_all_sessions(api):
    await login(api)
    response = await api.post(
        "/api/v1/auth/password",
        json={"current_password": PASSWORD, "new_password": "another-test-password-456"},
    )
    assert response.status_code == 200 and await Session.count() == 0
    assert (
        await api.post("/api/v1/auth/login", json={"username": "operator", "password": PASSWORD})
    ).status_code == 401
    assert (
        await api.post(
            "/api/v1/auth/login",
            json={"username": "operator", "password": "another-test-password-456"},
        )
    ).status_code == 200


async def test_enrollment_token_display_once_and_revocation(api):
    await login(api)
    response = await api.post("/api/v1/ui/enrollment-tokens", json={"note": "Lab onboarding"})
    assert response.status_code == 201
    token = response.json()["token"]
    listing = await api.get("/api/v1/ui/enrollment-tokens")
    assert token not in listing.text and "token_hash" not in listing.text
    token_id = listing.json()["items"][0]["id"]
    assert (await api.delete(f"/api/v1/ui/enrollment-tokens/{token_id}")).status_code == 200
    assert (await api.get("/api/v1/ui/enrollment-tokens")).json()["items"] == []


async def test_report_is_authenticated_escaped_and_verifies_tampering(api):
    creds, event, alert = await detection(api)
    assert (await api.get(f"/reports/{alert.alert_id}")).status_code == 401
    await login(api)
    await api.patch(
        f"/api/v1/ui/alerts/{alert.alert_id}", json={"note": "<script>window.pwned=1</script>"}
    )
    report = await api.get(f"/reports/{alert.alert_id}")
    assert report.status_code == 200 and "Forensic verification: PASS" in report.text
    assert "<script>window.pwned" not in report.text
    assert "&lt;script&gt;window.pwned" in report.text
    assert "api_key_hash" not in report.text and "no-store" in report.headers["cache-control"]
    archive = (await api.get(f"/api/v1/ui/reports/{alert.alert_id}.json")).json()
    assert archive["verification"]["ok"] is True
    assert archive["evidence"][0]["event_id"] == event["event_id"]
    await Event.get_pymongo_collection().update_one(
        {"event_id": event["event_id"]}, {"$set": {"data.remote_ip": "tampered"}}
    )
    assert "Forensic verification: FAIL" in (await api.get(f"/reports/{alert.alert_id}")).text
    verification = (await api.post(f"/api/v1/ui/devices/{creds['device_id']}/verify")).json()
    assert verification["ok"] is False


async def test_report_identifies_deleted_evidence(api):
    _, event, alert = await detection(api)
    await login(api)
    await Event.get_pymongo_collection().delete_one({"event_id": event["event_id"]})
    result = (await api.get(f"/api/v1/ui/reports/{alert.alert_id}.json")).json()
    assert not result["verification"]["ok"]
    assert result["missing_evidence"] == [event["event_id"]]


@pytest.mark.parametrize("field", ["chain_index", "prev_hash", "hash"])
async def test_report_marks_missing_chain_metadata_as_failed_verification(api, field):
    _, event, alert = await detection(api)
    await login(api)
    await Event.get_pymongo_collection().update_one(
        {"event_id": event["event_id"]}, {"$unset": {field: ""}}
    )
    report = await api.get(f"/reports/{alert.alert_id}")
    assert report.status_code == 200 and "Forensic verification: FAIL" in report.text
    archive = await api.get(f"/api/v1/ui/reports/{alert.alert_id}.json")
    assert archive.status_code == 200 and not archive.json()["verification"]["ok"]


async def test_report_handles_noncanonical_corrupt_evidence(api):
    _, event, alert = await detection(api)
    await login(api)
    await Event.get_pymongo_collection().update_one(
        {"event_id": event["event_id"]}, {"$set": {"data.corruption": ObjectId()}}
    )
    archive = await api.get(f"/api/v1/ui/reports/{alert.alert_id}.json")
    assert archive.status_code == 200 and not archive.json()["verification"]["ok"]


async def test_chain_rejects_inconsistent_anchor_length(api):
    creds, _, _ = await detection(api)
    await login(api)
    await Device.get_pymongo_collection().update_one(
        {"device_id": creds["device_id"]}, {"$set": {"chain_length": 0}}
    )
    verification = (await api.post(f"/api/v1/ui/devices/{creds['device_id']}/verify")).json()
    assert (
        not verification["ok"] and verification["reason"] == "events exceed recorded chain length"
    )
