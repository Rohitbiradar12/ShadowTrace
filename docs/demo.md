# Demo and acceptance playbook

The submission walkthrough uses synthetic event metadata. It does not need account lockouts,
log clearing, malware, live process termination or changes to the machine's Wi-Fi/protection.
Complete [server setup](../README.md#server-and-dashboard-setup-powershell) with MongoDB running.

## Isolated browser walkthrough

From the repository root with the server development dependencies installed:

```powershell
.\server\.venv\Scripts\python.exe scripts/browser_smoke.py
```

On Linux, use the installed server Python and install the browser once:

```bash
server/.venv/bin/python -m playwright install --with-deps chromium
server/.venv/bin/python scripts/browser_smoke.py
```

Windows uses installed Microsoft Edge. `ST_BROWSER_CHANNEL` can select another installed
Playwright browser channel. `ST_TEST_MONGO_URL` selects the MongoDB instance for this check;
it defaults to localhost and does not inherit the production MongoDB URL.

The script creates a disposable database named `shadowtrace_browser_<uuid>`, temporary
accounts, a synthetic online endpoint and an offline endpoint. It uploads fabricated
authentication, browser, Wi-Fi, process and Defender records through the ingestion API.
It starts its own localhost server and runs the browser against that server. Notifications,
Telegram controls and automatic responses remain disabled; no endpoint agent is started.

The walkthrough covers login, navigation, triage, evidence inspection, timeline, chain
verification, synthetic response queue/cancellation, account/enrollment administration,
CSV/report export, viewer restrictions and mobile layout. Queuing a response against the
synthetic device does not execute anything on the machine. The script stops its own server
and removes its generated database when it finishes.

Screenshots, a PDF, downloads, server log and a machine-readable summary are written to
`artifacts/browser/`. These files are ignored by Git; CI uploads them under the
`shadowtrace-browser` artifact. Inspect the screenshots/PDF before using them in a submission.

## Interactive presentation

Use a dedicated demo database by setting `ST_MONGO_DB=shadowtrace_demo` in `server/.env`
before creating its first administrator. Keep notification/Telegram controls and automatic
responses disabled for this synthetic presentation. Start one server worker as in the README.

1. Sign in and show the empty Overview and role-based navigation.
2. In Settings, create a one-use enrollment token with a one-hour lifetime.
3. From the repository root, run the pipeline script and paste that token when prompted:

   ```powershell
   .\server\.venv\Scripts\python.exe scripts/demo_pipeline.py
   ```

4. Show the synthetic endpoint and seven uploaded records. The expected incidents are
   **ST-AUTH-001** (five failed logins), **ST-BROWSER-001** (demo-listed domain) and
   **ST-WIFI-001** (open Wi-Fi). These are metadata fixtures, not activities performed on
   the presenter machine.
5. Open an alert, inspect evidence, add a note, mark it investigating and follow its timeline.
6. Verify the device chain. Open its incident report, then print/save it to PDF and download
   JSON. Export a filtered set of events as CSV.
7. Explain the command workflow using the isolated browser artifact or a pending command
   on the synthetic device. Do not interpret pending as successful remediation.
8. Show the local YAML rule conditions and administrative configuration, then sign in as a
   viewer to demonstrate the read-only role.

The interactive demo keeps its records in the chosen demo database for presentation. If you
intentionally enable external notifications, configured destinations receive these demo alerts.
The browser walkthrough is the option that cleans up its data automatically.

## Reproducible checks

From `agent/` and then `server/`, using each package's environment:

```powershell
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\ruff.exe check .
```

From `server/`, validate rule/list definitions:

```powershell
.\.venv\Scripts\python.exe -m app.cli validate-rules
```

The CI workflow also checks the installer with PowerShell's parser, JavaScript syntax and
the isolated browser walkthrough. API tests use unique disposable MongoDB databases and
mock external effects. Record the actual test output with the commit you present; do not
reuse a test count after changing the suite.

## Separate lab acceptance

The following checks require an operator-controlled Windows lab endpoint and configured
destinations. They have not been performed merely by passing the synthetic/browser tests.

| Check | Procedure and evidence to record |
|---|---|
| Fresh install | On a clean lab VM, preview then run the elevated installer. Confirm ACLs, task principal, enrollment and collection after logon. Record uninstall retention behavior. |
| Offline recovery | Disconnect only the lab agent from its test server, produce harmless watched-file activity, reconnect and verify buffering/upload/chain state. |
| Real lock | Opt in the lab endpoint, save work, issue one reasoned lock command and record the observed screen state plus command result. |
| Real kill | Start a disposable lab process, select its recorded process-start evidence, issue a kill and compare observed termination with the journal/server result. |
| External delivery | Configure your test Telegram chat/operator and SMTP destination, intentionally enable notifications, generate a synthetic incident and record receipt/delivery state. |
| Telegram response | Use the configured operator to acknowledge an incident and confirm an action on the lab endpoint; record an unauthorized operator rejection and command result. |
| Performance | Measure CPU, RAM, buffering and alert latency under specified endpoint/event counts; report duration and hardware with the measurements. |

Use [operations.md](operations.md) for installation/response semantics. Live acceptance must
be reported separately from mock transport/effect checks and from fabricated health metrics.
