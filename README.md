# ShadowTrace

ShadowTrace is a Windows-first endpoint monitoring project covering **Monitor → Detect →
Alert → Investigate → Respond**. A Python agent buffers telemetry in SQLite; a FastAPI and
MongoDB server detects suspicious activity, records a forensic hash chain, and serves an
authenticated dashboard. Operators can triage alerts, export reports, and queue Windows
lock/kill responses through the dashboard, CLI, or allowlisted Telegram controls.

The submission MVP includes eight collectors, 27 YAML rules, nine local indicator lists,
retrying Telegram/email notifications, role-based accounts and browser checks. The full
product roadmap and deployment acceptance items remain explicit in [PLAN.md](docs/PLAN.md).

## Requirements

- Python 3.12 or newer and MongoDB 8 running locally (or a configured MongoDB server).
- Windows 10/11 for the full collector set. Security-log monitoring requires elevation.
- Run the server with **one Uvicorn worker**: per-device ingestion/detection is serialized
  inside that process. Multi-worker deployment is not supported yet.

## Server and dashboard setup (PowerShell)

From the repository root:

```powershell
cd server
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
if (!(Test-Path .env)) { Copy-Item .env.example .env }
.\.venv\Scripts\python.exe -m app.cli validate-rules
.\.venv\Scripts\python.exe -m app.cli create-user admin --role admin
.\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Choose a password of 12–128 characters when prompted. There is no default account or password.
Open **http://127.0.0.1:8000/** and sign in. No frontend build or internet-hosted assets are
required. Health is at `/api/v1/health`; API documentation is at `/docs`.

Run server commands from `server/` so its `.env` is loaded. The default database is
`shadowtrace`; configure `ST_MONGO_URL` and `ST_MONGO_DB` before creating an account if needed.
For deployment beyond localhost, terminate HTTPS at a trusted reverse proxy, set
`ST_SESSION_COOKIE_SECURE=true`, and set `ST_PUBLIC_URL` to the dashboard's external origin.
Proxy forwarding must preserve the request's public host/scheme for same-origin checks.
Restart the server after changing environment variables, rule files, or indicator lists.

The dashboard includes Overview, Alerts, Devices, Events, Timeline, Commands, Reports, Rules,
Settings and My account. [The user guide](docs/user-guide.md) explains each workflow.

| Role | Access |
|---|---|
| Viewer | Read telemetry, rules and reports; verify chains; change own password |
| Analyst | Viewer access plus alert triage and response commands |
| Administrator | Analyst access plus accounts, enrollment, delivery retry and settings |

Passwords use Argon2id. Sessions use opaque, revocable HttpOnly/SameSite cookies; mutations
require a session CSRF token and same-origin validation. Role changes, disabling an account,
password changes and resets revoke that account's sessions. To reset a forgotten password,
run `python -m app.cli reset-password admin` from `server/` using its virtual environment.

Create a short-lived token in **Settings → Endpoint enrollment**, or in another terminal:

```powershell
cd server
.\.venv\Scripts\python.exe -m app.cli create-enrollment-token --hours 1 --max-uses 1
```

## Agent setup

From the repository root:

```powershell
cd agent
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
if (!(Test-Path config.local.yaml)) { Copy-Item config.example.yaml config.local.yaml }
.\.venv\Scripts\python.exe -m shadowtrace_agent -c config.local.yaml enroll --token YOUR_TOKEN
.\.venv\Scripts\python.exe -m shadowtrace_agent -c config.local.yaml run
```

Set `server_url` and watched/sensitive folders in `config.local.yaml`. Its sample data
directory is local to `agent/`; collector cursors, logs and the offline buffer use that same
directory. Browser history begins at the first baseline, then catches up across restarts.
The process and network collectors use polling, so short-lived activity can be missed.

The eighth collector reads Defender Operational events, starting at the current tail on first
run and resuming across restarts. A missing/inaccessible channel produces an agent-health alert.
For elevated logon installation and response configuration, see [operations](docs/operations.md).
Disclose collection to the people using monitored endpoints; browsing URLs and command lines
can contain sensitive information.

## Rules, alerts and delivery

Use the dashboard to inspect alerts, evidence, delivery state and response history, or use
the CLI below. The dashboard displays loaded rules and indicator lists; edit their source
files and restart the server to apply changes. Browser rule editing is future work.

From `server/`, using its virtual environment:

```powershell
.\.venv\Scripts\python.exe -m app.cli list-devices
.\.venv\Scripts\python.exe -m app.cli list-alerts
.\.venv\Scripts\python.exe -m app.cli show-alert ALERT_ID
.\.venv\Scripts\python.exe -m app.cli list-notifications
.\.venv\Scripts\python.exe -m app.cli verify-chain DEVICE_ID
```

There are 27 starter YAML rules in `rules/`. Configure indicators and allowlists in
`intel/lists.yaml`, then validate and restart the server. The shipped bad indicators are
**synthetic demo fixtures**, not a maintained threat feed. See [rule syntax](docs/rules.md).

Notification delivery defaults to disabled. To enable it, set `ST_NOTIFICATIONS_ENABLED=true`
and configure Telegram's bot token/destination chat ID and/or SMTP values from `.env.example`.
High/critical alerts use both channels by default; rules can set `response.notify` explicitly.
Unconfigured channels are recorded as `unconfigured`, without repeated network attempts.

Delivery runs independently of ingestion. Failed sends retry with backoff, then become
`failed`; each device/channel has a rate budget and pending alerts are combined into digests.
After correcting settings and restarting, explicitly retry a disabled/unconfigured/failed
delivery with `python -m app.cli retry-notification NOTIFICATION_ID`. Sent deliveries are not
reset by that command. A lost external acknowledgement can cause a repeated notification.

Administrators can also retry these deliveries from an alert's dashboard page. Telegram
buttons additionally require `ST_TELEGRAM_CONTROLS_ENABLED=true` and a JSON list of numeric
operator IDs in `ST_TELEGRAM_ALLOWED_USER_IDS`. Both chat and operator must match. Lock/kill
require confirmation within 60 seconds; callbacks expire and are deduplicated. Use a dedicated
bot without a webhook or another polling client. See
[Telegram controls](docs/operations.md#telegram-controls) before enabling them.

## Synthetic demo

Create a separate enrollment token, keep the server running, then from the repository root:

```powershell
.\server\.venv\Scripts\python.exe scripts/demo_pipeline.py
```

Paste the token when prompted. The script enrolls a clearly named synthetic device and sends
seven sample events. Expect brute-force, browser-domain and open-Wi-Fi alerts. It does not
perform those activities on the machine. If notifications are enabled, the configured
destinations receive these demo alerts.

## Tests

Run the isolated dashboard walkthrough from the repository root:

```powershell
.\server\.venv\Scripts\python.exe scripts/browser_smoke.py
```

It uses its own disposable `shadowtrace_browser_<uuid>` MongoDB database, ephemeral accounts
and localhost server, with external notifications and automatic responses disabled. Responses
are queued only for synthetic endpoints. It closes its server and removes only its database;
screenshots, a PDF and downloads remain in `artifacts/browser/`. Windows uses installed Edge.
On Linux, install Chromium first with `python -m playwright install --with-deps chromium`.
See [the demo playbook](docs/demo.md) for the interactive walkthrough and acceptance steps.

Run in each package directory:

```powershell
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\ruff.exe check .
```

Server tests use a unique disposable database per test and remove only that database.
`ST_TEST_MONGO_URL` can select a test MongoDB instance; production `ST_MONGO_URL` is not used
as the test destination. Telegram/SMTP tests use mocks. CI runs the Windows agent suite and
the server suite against a MongoDB service. Response tests mock locking/termination; a read-only
Windows API test checks process identity. PowerShell scripts are syntax-checked in Windows CI.
CI also validates rules, checks dashboard JavaScript syntax, exercises the browser walkthrough
and saves its artifacts.

## Current limits

Detection uses persisted event-time windows and survives restarts and out-of-order arrivals.
Alert counts and outbox creation are idempotent across retries; evidence previews retain up
to 100 event IDs, with firings retained separately in `alert_hits`. The recovery worker and
`python -m app.cli scan-pending` process events left behind by interrupted requests.

The forensic chain protects against edits/deletions relative to the device's saved anchor.
It has no external signed anchor: an attacker controlling both collections can rewrite both.
A missing/modified tail returns HTTP 409 and leaves the agent's events buffered for investigation.
Retention must preserve chain anchors; automatic event deletion is not enabled.

Response commands use expiring heartbeat delivery and a persistent execution/result journal.
The agent requires `responses.enabled: true`. Automatic rules additionally require
`ST_AUTO_RESPONSE_ENABLED=true`; both default off. No starter rule enables an automatic action.
See [command operation and failure states](docs/operations.md#response-commands).

CSV export includes at most 5,000 matching events. Incident reports include linked evidence,
a bounded 250-event timeline, response history and chain verification; the report identifies
truncation. Print the HTML report to save a PDF, or download its JSON representation.

Fresh-install scripts set protective ACLs but still need an elevated clean-machine trial.
Actual workstation locking/termination and live Telegram/SMTP delivery need controlled lab
acceptance with your configuration. Automated checks mock these effects. DPAPI key storage,
quarantine, file-read auditing, executable signing, feed synchronization, browser rule editing,
packaging, multi-worker scale and Linux/macOS agents remain future work. See
[architecture](docs/architecture.md) and the [project report](docs/project-report.md).
