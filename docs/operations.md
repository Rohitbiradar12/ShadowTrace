# Operations guide

Installation, server administration, notifications, responses and testing. For first-time
setup, start with the [README](../README.md).

## Server administration

Run server commands from `server/`, using its virtual environment, so `server/.env` is loaded.
The default database is `shadowtrace` on local MongoDB; set `ST_MONGO_URL` and `ST_MONGO_DB`
before creating the first account if you need something else. Validate rules with
`python -m app.cli validate-rules`. Health is at `/api/v1/health`; API documentation is at `/docs`.

Run **one Uvicorn worker**: per-device ingestion and detection are serialized inside that
process, so multi-worker deployment is not supported yet. Restart the server after changing
environment variables, rule files or indicator lists.

To deploy beyond localhost, terminate HTTPS at a trusted reverse proxy, set
`ST_SESSION_COOKIE_SECURE=true`, and set `ST_PUBLIC_URL` to the dashboard's external origin.
The proxy must preserve the request's public host and scheme for same-origin checks.

Passwords use Argon2id. Sessions use opaque, revocable HttpOnly/SameSite cookies; changes
require a session CSRF token and same-origin validation. Role changes, disabling an account,
password changes and resets revoke that account's sessions. Reset a forgotten password with
`python -m app.cli reset-password USERNAME`.

Useful CLI commands:

```powershell
.\.venv\Scripts\python.exe -m app.cli create-enrollment-token --hours 1 --max-uses 1
.\.venv\Scripts\python.exe -m app.cli list-devices
.\.venv\Scripts\python.exe -m app.cli list-alerts
.\.venv\Scripts\python.exe -m app.cli show-alert ALERT_ID
.\.venv\Scripts\python.exe -m app.cli list-notifications
.\.venv\Scripts\python.exe -m app.cli verify-chain DEVICE_ID
.\.venv\Scripts\python.exe -m app.cli scan-pending
```

`scan-pending` (and the background recovery worker) processes events left behind by
interrupted requests.

## Agent notes

The sample configuration keeps the agent's data directory inside `agent/`; collector cursors,
logs and the offline buffer live there. Browser history starts at a first-run baseline and then
catches up across restarts. The process and network collectors poll, so very short-lived
activity can be missed. Security-log monitoring requires an elevated agent.

## Notifications

Delivery is disabled by default. To enable it, set `ST_NOTIFICATIONS_ENABLED=true` and fill in
the Telegram bot token and destination chat ID and/or the SMTP values from `.env.example`.
High and critical alerts use both channels by default; a rule can set `response.notify`
explicitly. Unconfigured channels are recorded as `unconfigured` without network attempts.

Delivery runs independently of ingestion. Failed sends retry with backoff and then become
`failed`. Each device/channel has a rate budget, and pending alerts are combined into digests.
After fixing settings and restarting, retry a disabled, unconfigured or failed delivery from
the alert's dashboard page (administrators) or with
`python -m app.cli retry-notification NOTIFICATION_ID`. Sent deliveries are never reset. A lost
external acknowledgement can cause a repeated notification.

### Telegram controls

Telegram buttons additionally require `ST_TELEGRAM_CONTROLS_ENABLED=true` and a JSON list of
numeric operator IDs in `ST_TELEGRAM_ALLOWED_USER_IDS`. Both the chat and the operator must
match. Lock and kill require confirmation within 60 seconds; callbacks expire and are
deduplicated. Use a dedicated bot with no webhook and no other polling client.

## Fresh installation

Use Windows 10/11, a machine-wide Python 3.12+ installation and an elevated PowerShell
terminal **as the administrator whose interactive session will be monitored**. The task
starts only when that account logs on; this MVP is not a multi-user Windows service.
The underlying Python runtime must remain installed.

From the repository root, preview with your actual Python path and server origin:

```powershell
.\scripts\install-agent.ps1 -ServerUrl https://shadowtrace.example.test `
    -PythonExe 'C:\Program Files\Python312\python.exe' -EnableAuditPolicy -WhatIf
```

Remove `-WhatIf` to install. A local demo may use `http://127.0.0.1:8000`; remote origins
require HTTPS and a certificate trusted by the endpoint. The script prompts for a single-use
enrollment token and passes it through stdin. It does not store the token in configuration.

Installation creates `C:\Program Files\ShadowTrace` for code/venv and
`C:\ProgramData\ShadowTrace` for configuration, credentials, cursors, journals and logs.
Access is limited to SYSTEM and Administrators. Existing directories/tasks are refused to
preserve enrollment and forensic data; use the manual README setup for an existing host.
An interrupted installation leaves its files intact for diagnosis/manual recovery.

The **ShadowTrace Agent** task runs at logon with an interactive principal and highest
privileges, using `pythonw.exe` so there is no console window. `-StartNow` starts it after
installation; otherwise it begins at the next logon. `-EnableResponses` opts this endpoint
into lock/kill commands. Without it, received commands produce a `rejected` result.
Interactive logon and elevation are specified through Microsoft's
[ScheduledTasks principal API](https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/new-scheduledtaskprincipal).

`-EnableAuditPolicy` saves `audit-policy-before.csv` and enables success/failure auditing for
logon, logoff, account lockout, user-account management and security-group management.
It uses [subcategory GUIDs](https://learn.microsoft.com/en-us/windows/win32/secauthz/auditing-constants)
so Windows display language does not change the commands. Domain policy may override local
audit settings. File-read auditing and SACL setup remain future work.

To stop and unregister the task:

```powershell
.\scripts\uninstall-agent.ps1 -WhatIf
.\scripts\uninstall-agent.ps1
```

Uninstall retains code, configuration and forensic data, and does not restore the whole audit
policy automatically. Review the backup before restoring policy so later administrator changes
are not overwritten. Keys are protected by filesystem ACLs, but are not yet DPAPI encrypted.

## Defender monitoring

`collectors.defender.enabled` defaults to true on Windows. The collector uses
`Microsoft-Windows-Windows Defender/Operational`; it baselines on first run and subsequently
resumes saved record IDs/timestamps, including after a cleared log. It handles bounded batches
and keeps the cursor when buffering fails. Log retention can still remove events before polling.

It records detections (1116), action reports (1117), action failures (1118/1119), protection
changes (5000/5001/5010/5012), configuration changes (5007) and blocked tampering (5013).
The three starter rules alert on detections, failed actions and disabled protection. An 1117
event may represent an Allow action, so it is not labeled as successful remediation.
These mappings follow [Microsoft's event reference](https://learn.microsoft.com/en-us/defender-endpoint/troubleshoot-microsoft-defender-antivirus).

## Response commands

For a manually configured agent, edit its YAML and restart it:

```yaml
responses:
  enabled: true
  allowed_actions: [lock_workstation, kill_process]
```

From `server/`, using its virtual environment, issue commands with a reason:

```powershell
.\.venv\Scripts\python.exe -m app.cli issue-command DEVICE_ID lock_workstation --reason 'Contain incident'
.\.venv\Scripts\python.exe -m app.cli issue-command DEVICE_ID kill_process --event EVENT_UUID --reason 'Stop confirmed lab process'
.\.venv\Scripts\python.exe -m app.cli list-commands --device DEVICE_ID
.\.venv\Scripts\python.exe -m app.cli show-command COMMAND_ID
.\.venv\Scripts\python.exe -m app.cli cancel-command COMMAND_ID
```

Kill takes a stored `process_started` event ID belonging to the device. Alert details expose
evidence IDs; choose the process-start evidence. The event must contain PID, executable path
and start time. The agent compares that identity to the live Windows process and uses the
same handle for verification and termination, preventing PID reuse between those operations.
It refuses the agent, its ancestors, named essential processes and any process that Windows
marks critical. This check uses the [Windows critical-process API](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-isprocesscritical).

Commands expire after 120 seconds by default (`--ttl` accepts 10..900 seconds). Delivery uses
the next heartbeat (normally ten seconds), with a 30-second lease for retransmission after
network failure. Results are returned on a subsequent heartbeat. Each device key can retrieve
and acknowledge only that device's commands. Commands can be cancelled only before delivery.
An offline command is marked expired when that device next polls; `expires_at` is always visible.

The endpoint saves a command before executing it and retains results in `commands.db` until
the server acknowledges them. Completed records remain for duplicate suppression. Do not delete
this journal on an enrolled device. An interrupted execution reports `unknown` after restart
and is not automatically repeated. Review the endpoint before issuing a new command in that
case. A late result may replace `expired`; the command history keeps both transitions.

Results are `succeeded`, `failed`, `rejected`, or `unknown`. Lock success means Windows accepted
the asynchronous request, not that the final desktop state was observed; this is the
[LockWorkStation contract](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-lockworkstation).
Each command retains actor, reason, source event, delivery attempts and state transitions in
MongoDB. The agent also queues a `command_result` forensic event when it saves a normal result.
These acknowledgements are endpoint reports, not independent proof that a compromised agent
carried out an action. Command history is not part of the forensic event hash chain.

Commands can be created from the local CLI, from the dashboard by analysts and
administrators, and through allowlisted [Telegram controls](#telegram-controls). There is no
unauthenticated HTTP command-creation route.

Automatic actions additionally require `ST_AUTO_RESPONSE_ENABLED=true` and a rule with
`response.auto_action`. No starter rule has one. Old/future-dated events cannot trigger them,
and each deduplicated alert/action queues at most one command. See [rule configuration](rules.md).

## Testing

From `server/` or `agent/`, using that package's virtual environment:

```powershell
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\ruff.exe check .
```

Server tests use a unique disposable database per test and remove only that database.
`ST_TEST_MONGO_URL` selects the test MongoDB instance; the production `ST_MONGO_URL` is never
used for tests. Telegram/SMTP tests use mocks. The isolated browser walkthrough
(`scripts/browser_smoke.py`) is described in the [demo playbook](demo.md). CI runs the Windows
agent suite, the server suite against a MongoDB service, rule validation, JavaScript and
PowerShell syntax checks, and the browser walkthrough.

## Current limits

- The forensic chain detects edits and deletions relative to the device's saved anchor, but
  has no external signed anchor: an attacker controlling both collections can rewrite both.
  A missing or modified tail returns HTTP 409 and leaves the agent's events buffered.
  Automatic event deletion is not enabled; any retention policy must preserve chain anchors.
- CSV export includes at most 5,000 events. Incident reports include linked evidence, up to
  250 timeline events, response history and chain verification, and say when they are
  truncated. Print the report page to save a PDF, or download its JSON.
- Real locking/termination and live Telegram/SMTP delivery need a controlled lab test with
  your configuration; automated checks mock them.
- Future work: DPAPI key storage, quarantine, file-read auditing, executable signing, feed
  synchronization, browser rule editing, packaging, multi-worker scale and Linux/macOS agents.

## Validation status

Automated tests cover command ownership, expiry, lease retries, idempotent results, interrupted
execution, protected processes, PID/image/start-time mismatch, rule opt-in, Defender parsing,
cursor restart/reset and failed buffering. Lock/termination functions and notification sends
are mocked. One Windows test reads the test process's identity through the actual native API.
PowerShell installation scripts are syntax-checked; elevated installation, real lock/kill and
live Telegram/SMTP delivery still require a controlled lab acceptance run.

Local validation on 2026-10-28 passed 79 agent tests and 72 server tests, Ruff, rule validation
(27 rules / 9 lists), and both PowerShell parsers. A read-only Defender API smoke check also
parsed the latest local event and handled an empty query without emitting or uploading data.
