"""Submit synthetic telemetry to an explicitly selected demo server.

This does not perform failed logins, connect to suspicious sites, or change Wi-Fi.
Use the server virtual environment. Configured notifications will receive demo alerts.
"""

import argparse
import getpass
import uuid
from datetime import UTC, datetime, timedelta

import httpx


def build_events() -> list[dict]:
    now = datetime.now(UTC)
    events = []
    for seq in range(1, 6):
        events.append(
            {
                "event_id": str(uuid.uuid4()),
                "seq": seq,
                "ts": (now - timedelta(seconds=7 - seq)).isoformat(),
                "category": "auth",
                "action": "logon_failed",
                "user": "DEMO\\student",
                "data": {"target_user": "DEMO\\student", "simulated": True},
            }
        )
    for category, action, data in [
        (
            "browser",
            "url_visited",
            {"domain": "demo-bad.example", "url": "https://demo-bad.example/"},
        ),
        ("wifi", "network_connected", {"ssid": "Demo Open WiFi", "is_open": True}),
    ]:
        events.append(
            {
                "event_id": str(uuid.uuid4()),
                "seq": len(events) + 1,
                "ts": now.isoformat(),
                "category": category,
                "action": action,
                "user": "DEMO\\student",
                "data": {**data, "simulated": True},
            }
        )
    return events


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server", default="http://127.0.0.1:8000")
    args = parser.parse_args()
    token = getpass.getpass("Demo enrollment token: ")
    with httpx.Client(
        base_url=args.server.rstrip("/") + "/api/v1", timeout=30
    ) as client:
        enrolled = client.post(
            "/agents/enroll",
            json={
                "enrollment_token": token,
                "hostname": "SHADOWTRACE-SYNTHETIC-DEMO",
                "os": "windows",
                "os_version": "synthetic demo",
                "agent_version": "0.1.0-demo",
            },
        )
        enrolled.raise_for_status()
        creds = enrolled.json()
        response = client.post(
            "/events/batch",
            headers={"X-Device-Key": creds["api_key"]},
            json={"events": build_events()},
        )
        response.raise_for_status()
    print(f"Demo device: {creds['device_id']}")
    print(f"Upload: {response.json()}")
    print("Expected: ST-AUTH-001, ST-BROWSER-001 and ST-WIFI-001 alerts.")
    print(f"Inspect with: python -m app.cli list-alerts --device {creds['device_id']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
