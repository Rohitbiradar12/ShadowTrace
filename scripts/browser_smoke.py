"""Exercise the dashboard in a real browser with an isolated, disposable MongoDB.

Run with the server's development environment. Uses Edge on Windows, Chromium
elsewhere (override with ST_BROWSER_CHANNEL). Creates only synthetic telemetry;
no endpoint agent runs and notifications/automatic responses are disabled.
Screenshots, a printable incident PDF, and a summary go in artifacts/browser.
"""

import asyncio
import json
import os
import re
import secrets
import socket
import subprocess
import sys
import time
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
from demo_pipeline import build_events
from playwright.sync_api import expect, sync_playwright
from pymongo import AsyncMongoClient

ROOT = Path(__file__).resolve().parents[1]
ARTIFACTS = ROOT / "artifacts" / "browser"
HOSTNAME = "SHADOWTRACE-SYNTHETIC-DEMO"
NOTE = "Reviewed synthetic evidence. <script>window.stInjected = true</script>"
# Full-page captures with entrance animations finished, so screenshots are submission-ready.
SHOT = {"full_page": True, "animations": "disabled"}


async def seed(password: str) -> dict:
    # Environment is set before importing application modules or loading .env.
    from app.core.config import get_settings
    from app.core.db import init_db
    from app.core.security import ENROLLMENT_TOKEN_PREFIX, generate_token, hash_token
    from app.main import app
    from app.models import Alert, Device, EnrollmentToken
    from app.services.auth import create_user

    client = await init_db(get_settings())
    try:
        await create_user("browser-admin", password, "admin", "browser-smoke")
        await create_user("browser-viewer", password, "viewer", "browser-smoke")
        token = generate_token(ENROLLMENT_TOKEN_PREFIX)
        await EnrollmentToken(
            token_hash=hash_token(token),
            expires_at=datetime.now(UTC) + timedelta(hours=1),
            max_uses=1,
            note="Browser smoke seed",
        ).insert()
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as api:
            response = await api.post(
                "/api/v1/agents/enroll",
                json={
                    "enrollment_token": token,
                    "hostname": HOSTNAME,
                    "os": "windows",
                    "os_version": "Windows 11 (synthetic)",
                    "agent_version": "0.1.0-demo",
                },
            )
            response.raise_for_status()
            creds = response.json()
            events = build_events()
            now = datetime.now(UTC).isoformat()
            for category, action, data in [
                (
                    "process",
                    "process_started",
                    {
                        "pid": 45678,
                        "name": "powershell.exe",
                        "exe": r"C:\Lab\powershell.exe",
                        "command_line": "powershell.exe -EncodedCommand SYNTHETIC_DEMO",
                        "create_time": now,
                    },
                ),
                (
                    "system",
                    "defender_threat_detected",
                    {
                        "threat_name": "Synthetic demonstration",
                        "threat_id": "demo-only",
                    },
                ),
            ]:
                events.append(
                    {
                        "event_id": str(uuid.uuid4()),
                        "seq": len(events) + 1,
                        "ts": now,
                        "category": category,
                        "action": action,
                        "user": "DEMO\\student",
                        "data": {**data, "simulated": True},
                    }
                )
            response = await api.post(
                "/api/v1/events/batch",
                headers={"X-Device-Key": creds["api_key"]},
                json={"events": events},
            )
            response.raise_for_status()
            assert response.json()["accepted"] == len(events)
            response = await api.post(
                "/api/v1/agents/heartbeat",
                headers={"X-Device-Key": creds["api_key"]},
                json={
                    "agent_version": "0.1.0-demo",
                    "uptime_seconds": 120,
                    "stats": {
                        "buffered_events": 0,
                        "dropped_events": 0,
                        "memory_mb": 37.5,
                        "cpu_percent": 0.4,
                        "collectors": {"process": "running", "defender": "running"},
                    },
                },
            )
            response.raise_for_status()
            assert response.json()["commands"] == []
        await Device(
            device_id="dev_browser_offline",
            hostname="LAB-OFFLINE-DEMO",
            os="windows",
            os_version="Windows 11 (synthetic)",
            agent_version="0.1.0-demo",
            api_key_hash=hash_token(secrets.token_urlsafe(32)),
            last_seen=datetime.now(UTC) - timedelta(days=1),
        ).insert()
        alert = await Alert.find_one(Alert.rule_id == "ST-PROCESS-001")
        assert alert is not None, "Synthetic process event did not create an alert"
        return {
            "device_id": creds["device_id"],
            "alert_id": alert.alert_id,
            "alert_title": alert.title,
            "events": len(events),
            "alerts": await Alert.count(),
        }
    finally:
        await client.close()


async def cleanup_database(mongo_url: str, database: str) -> None:
    if not re.fullmatch(r"shadowtrace_browser_[0-9a-f]{32}", database):
        raise ValueError("Refusing to drop a database not created by this script")
    client = AsyncMongoClient(mongo_url)
    try:
        await client.drop_database(database)
    finally:
        await client.close()


def wait_for_server(base_url: str, process: subprocess.Popen) -> None:
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(
                "Browser smoke server exited; see artifacts/browser/server.log"
            )
        try:
            if httpx.get(base_url + "/api/v1/health", timeout=1).status_code == 200:
                return
        except httpx.TransportError:
            pass
        time.sleep(0.2)
    raise TimeoutError("Browser smoke server did not become ready within 30 seconds")


def exercise_browser(base_url: str, password: str, seeded: dict) -> dict:
    failures: list[str] = []
    pages_checked: list[str] = []
    with sync_playwright() as playwright:
        channel = os.environ.get(
            "ST_BROWSER_CHANNEL", "msedge" if os.name == "nt" else ""
        )
        browser = playwright.chromium.launch(
            headless=True, **({"channel": channel} if channel else {})
        )
        context = browser.new_context(
            viewport={"width": 1440, "height": 1000},
            color_scheme=os.environ.get("ST_BROWSER_COLOR_SCHEME", "dark"),
            # The dashboard skips count-up and entrance motion, so captures show final values.
            reduced_motion="reduce",
        )
        context.set_default_timeout(10000)

        def observe(page):
            page.on("pageerror", lambda error: failures.append(str(error)))
            page.on(
                "console",
                lambda message: (
                    failures.append(message.text)
                    if message.type == "error"
                    and "401 (Unauthorized)" not in message.text
                    else None
                ),
            )
            page.on(
                "response",
                lambda response: (
                    failures.append(f"HTTP {response.status}: {response.url}")
                    if response.status >= 400
                    and not (
                        response.status == 401 and response.url.endswith("/auth/me")
                    )
                    else None
                ),
            )

        context.on("page", observe)
        page = context.new_page()

        def route(path: str, title: str):
            page.goto(base_url + "/#/" + path)
            expect(page.locator("#main-content h1")).to_have_text(title)
            expect(page.locator("#main-content")).to_have_attribute(
                "aria-busy", "false"
            )
            pages_checked.append(path.split("?")[0])

        def close_dialog():
            page.get_by_role("button", name="Close dialog", exact=True).click()
            expect(page.locator("#action-dialog")).not_to_be_visible()

        def sign_in(username: str):
            expect(page.locator("#login-view")).to_be_visible()
            page.get_by_label("Username", exact=True).fill(username)
            page.get_by_label("Password", exact=True).fill(password)
            page.get_by_role("button", name="Sign in", exact=False).click()
            expect(page.locator("#workspace")).to_be_visible()

        try:
            page.goto(base_url)
            expect(
                page.get_by_role("heading", name="Sign in to your workspace")
            ).to_be_visible()
            page.screenshot(path=str(ARTIFACTS / "login.png"), **SHOT)
            sign_in("browser-admin")
            expect(page.locator("#main-content h1")).to_have_text("Security overview")
            expect(page.locator(".metric")).to_have_count(4)
            expect(page.locator(".metric").nth(2).locator("strong")).to_have_text(
                str(seeded["events"])
            )
            page.screenshot(path=str(ARTIFACTS / "overview.png"), **SHOT)
            # All seeded alerts are untriaged, so the sidebar badge counts every one.
            expect(page.locator("#nav-alert-count")).to_have_text(str(seeded["alerts"]))
            # Auto-refresh shows a countdown and still runs after mouse navigation
            # (focus left on a sidebar link used to block it).
            page.locator('[data-nav="overview"]').click()
            expect(page.locator("#refresh-text")).to_have_text(
                re.compile(r"Refreshing in \d+s")
            )
            with page.expect_request("**/api/v1/ui/overview", timeout=20000):
                pass
            # Command palette: shortcut, live alert search and opening a result.
            page.keyboard.press("Control+K")
            palette = page.locator("#palette")
            expect(palette).to_be_visible()
            page.get_by_label("Search ShadowTrace").fill("powershell")
            result = palette.get_by_role(
                "option", name=re.compile("Encoded PowerShell command")
            )
            expect(result).to_be_visible()
            page.screenshot(path=str(ARTIFACTS / "palette.png"), animations="disabled")
            result.click()
            expect(palette).not_to_be_visible()
            expect(page.locator("#main-content h1")).to_have_text(
                "Encoded PowerShell command"
            )
            # Every main page must load real data with no JavaScript/server errors.
            for path, title in [
                ("alerts", "Alert queue"),
                ("devices", "Endpoints"),
                ("events", "Events explorer"),
                ("timeline", "Forensic timeline"),
                ("commands", "Response history"),
                ("reports", "Incident reports"),
                ("rules", "Detection rules"),
                ("settings", "Workspace settings"),
                ("account", "My account"),
            ]:
                route(path, title)

            # Expanding one rule card must not stretch the card beside it.
            route("rules", "Detection rules")
            cards = page.locator(".rule-card")
            neighbour = cards.nth(1).bounding_box()["height"]
            cards.nth(0).locator("summary").click()
            expect(cards.nth(0).locator("pre")).to_be_visible()
            assert cards.nth(1).bounding_box()["height"] == neighbour, "rule card stretched"
            page.screenshot(path=str(ARTIFACTS / "rules.png"), animations="disabled")
            # Pages without auto-refresh say so; typing in a filter pauses it elsewhere.
            expect(page.locator("#refresh-status")).to_have_attribute("data-state", "static")
            route("alerts", "Alert queue")
            page.get_by_label("Search title or rule").click()
            expect(page.locator("#refresh-text")).to_have_text("Auto-refresh paused")

            route(f"alerts/{seeded['alert_id']}", seeded["alert_title"])
            page.get_by_label("Status", exact=True).select_option("investigating")
            page.get_by_label("Investigation note (optional)").fill(NOTE)
            page.get_by_role("button", name="Save triage").click()
            expect(page.locator(".note-list")).to_contain_text(NOTE)
            assert page.evaluate("window.stInjected") is None

            page.get_by_role("button", name="Lock workstation", exact=True).click()
            expect(page.get_by_role("dialog")).to_contain_text(HOSTNAME)
            page.get_by_label("Reason for this action").fill(
                "Synthetic browser lock confirmation"
            )
            page.get_by_role("button", name="Queue workstation lock").click()
            expect(page.get_by_role("dialog")).not_to_be_visible()
            expect(page.locator("#main-content")).to_contain_text("lock workstation")
            page.get_by_role("button", name="Kill process", exact=True).click()
            expect(page.get_by_role("dialog")).to_contain_text("45678")
            expect(page.get_by_role("dialog")).to_contain_text(r"C:\Lab\powershell.exe")
            page.get_by_label("Reason for this action").fill(
                "Synthetic browser process confirmation"
            )
            page.get_by_role("button", name="Queue termination").click()
            expect(page.get_by_role("dialog")).not_to_be_visible()
            expect(page.locator("#main-content")).to_contain_text("kill process")
            page.screenshot(path=str(ARTIFACTS / "alert.png"), **SHOT)

            with page.expect_popup() as popup:
                page.get_by_role("link", name="Incident report").click()
            report = popup.value
            expect(
                report.get_by_role("heading", name="Forensic verification: PASS")
            ).to_be_visible()
            expect(report.locator(".note")).to_have_text(NOTE)
            assert report.evaluate("window.stInjected") is None
            with report.expect_download() as download:
                report.get_by_role("link", name="Download JSON").click()
            download.value.save_as(ARTIFACTS / "incident.json")
            evidence = json.loads(
                (ARTIFACTS / "incident.json").read_text(encoding="utf-8")
            )
            assert evidence["verification"]["ok"] and len(evidence["commands"]) == 2
            report.pdf(
                path=str(ARTIFACTS / "incident.pdf"), format="A4", print_background=True
            )
            report.close()

            page.get_by_role("link", name="Open timeline", exact=True).click()
            expect(page.locator("#main-content h1")).to_have_text("Forensic timeline")
            expect(page.locator(".timeline > li")).to_have_count(seeded["events"])
            page.locator(".timeline > li").first.get_by_role(
                "button", name="Inspect event"
            ).click()
            expect(page.get_by_role("dialog")).to_contain_text("Chain index")
            close_dialog()

            route("events", "Events explorer")
            page.get_by_label("Category", exact=True).select_option("process")
            page.get_by_role("button", name="Apply filters").click()
            expect(page.locator("tbody tr")).to_have_count(1)
            with page.expect_download() as download:
                page.get_by_role("link", name="Export CSV").click()
            download.value.save_as(ARTIFACTS / "events.csv")
            assert "process_started" in (ARTIFACTS / "events.csv").read_text(
                encoding="utf-8-sig"
            )

            route(f"devices/{seeded['device_id']}", HOSTNAME)
            page.get_by_role("button", name="Verify event chain").click()
            expect(page.get_by_role("dialog")).to_contain_text("Verification passed")
            close_dialog()

            route("commands", "Response history")
            expect(page.locator("tbody tr")).to_have_count(2)
            page.get_by_role("button", name="Details", exact=True).first.click()
            expect(page.get_by_role("dialog")).to_contain_text("browser-admin")
            close_dialog()
            page.get_by_role("button", name="Cancel", exact=True).first.click()
            page.get_by_role("button", name="Cancel command", exact=True).click()
            expect(page.get_by_role("dialog")).not_to_be_visible()
            expect(page.locator("tbody")).to_contain_text("cancelled")

            route("settings", "Workspace settings")
            page.get_by_role("button", name="Create token", exact=True).click()
            page.get_by_label("Purpose", exact=True).fill("Browser smoke enrollment")
            page.locator("#dialog-submit").click()
            expect(page.locator(".token-box")).to_contain_text("shown only once")
            assert page.locator(".token-box code").inner_text().startswith("ste_")
            close_dialog()
            token_row = page.locator("tr").filter(has_text="Browser smoke enrollment")
            expect(token_row).to_be_visible()
            token_row.get_by_role("button", name="Revoke", exact=True).click()
            page.get_by_role("button", name="Revoke token", exact=True).click()
            expect(token_row).to_have_count(0)
            page.locator("#new-username").fill("browser-created")
            page.get_by_label("Password (12+ characters)", exact=True).fill(password)
            page.get_by_label("Role", exact=True).select_option("analyst")
            page.get_by_role("button", name="Create account", exact=True).click()
            expect(
                page.locator('[data-action="manage-user"][data-username="browser-created"]')
            ).to_be_visible()

            page.set_viewport_size({"width": 390, "height": 844})
            route("overview", "Security overview")
            assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
            page.screenshot(path=str(ARTIFACTS / "mobile.png"), **SHOT)
            for path, title in [
                (f"alerts/{seeded['alert_id']}", seeded["alert_title"]),
                ("settings", "Workspace settings"),
                ("events", "Events explorer"),
            ]:
                route(path, title)
                assert page.evaluate(
                    "document.documentElement.scrollWidth <= innerWidth"
                ), path
            page.get_by_role("button", name="Toggle navigation").click()
            page.locator('[data-nav="alerts"]').click()
            expect(page.locator("#main-content h1")).to_have_text("Alert queue")
            expect(
                page.get_by_role("button", name="Toggle navigation")
            ).to_have_attribute("aria-expanded", "false")

            page.set_viewport_size({"width": 1440, "height": 1000})
            page.get_by_role("button", name="Sign out", exact=True).click()
            sign_in("browser-viewer")
            route(f"alerts/{seeded['alert_id']}", seeded["alert_title"])
            expect(
                page.get_by_role("button", name="Lock workstation", exact=True)
            ).to_have_count(0)
            expect(
                page.get_by_role("button", name="Kill process", exact=True)
            ).to_have_count(0)
            expect(page.get_by_role("button", name="Save triage")).to_have_count(0)
            expect(page.locator('[data-nav="settings"]')).not_to_be_visible()
            page.get_by_role("button", name="Sign out", exact=True).click()
            expect(page.locator("#login-view")).to_be_visible()
            assert not failures, "Browser errors: " + "\n".join(failures)
            return {
                "pages_checked": pages_checked,
                "browser_errors": failures,
                "result": "PASS",
            }
        except BaseException:
            page.screenshot(path=str(ARTIFACTS / "failure.png"), **SHOT)
            (ARTIFACTS / "failure.html").write_text(page.content(), encoding="utf-8")
            if failures:
                print("Browser errors:", "\n".join(failures), file=sys.stderr)
            raise
        finally:
            context.close()
            browser.close()


def main() -> int:
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    database = "shadowtrace_browser_" + uuid.uuid4().hex
    mongo_url = os.environ.get(
        "ST_TEST_MONGO_URL", "mongodb://127.0.0.1:27017/?serverSelectionTimeoutMS=3000"
    )
    os.environ.update(
        ST_MONGO_URL=mongo_url,
        ST_MONGO_DB=database,
        ST_NOTIFICATIONS_ENABLED="false",
        ST_AUTO_RESPONSE_ENABLED="false",
        ST_TELEGRAM_CONTROLS_ENABLED="false",
        ST_SESSION_COOKIE_SECURE="false",
        ST_DETECTION_ENABLED="true",
        ST_RULES_DIR=str(ROOT / "rules"),
        ST_INTEL_FILE=str(ROOT / "intel" / "lists.yaml"),
    )
    sys.path.insert(0, str(ROOT / "server"))
    password = secrets.token_urlsafe(24)
    process = None
    started = time.monotonic()
    try:
        seeded = asyncio.run(seed(password))
        with socket.socket() as reserved:
            reserved.bind(("127.0.0.1", 0))
            port = reserved.getsockname()[1]
        base_url = f"http://127.0.0.1:{port}"
        os.environ["ST_PUBLIC_URL"] = base_url
        with (ARTIFACTS / "server.log").open("w", encoding="utf-8") as log:
            process = subprocess.Popen(
                [
                    sys.executable,
                    "-m",
                    "uvicorn",
                    "app.main:app",
                    "--host",
                    "127.0.0.1",
                    "--port",
                    str(port),
                ],
                cwd=ROOT / "server",
                env=os.environ.copy(),
                stdout=log,
                stderr=subprocess.STDOUT,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
            )
            wait_for_server(base_url, process)
            result = exercise_browser(base_url, password, seeded)
        result.update(seeded, elapsed_seconds=round(time.monotonic() - started, 1))
        (ARTIFACTS / "summary.json").write_text(
            json.dumps(result, indent=2), encoding="utf-8"
        )
        print(
            f"Browser smoke PASS: {seeded['events']} events, "
            f"{seeded['alerts']} alerts; artifacts/browser"
        )
        return 0
    finally:
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        asyncio.run(cleanup_database(mongo_url, database))


if __name__ == "__main__":
    raise SystemExit(main())
