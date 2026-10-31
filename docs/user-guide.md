# Dashboard user guide

Follow the [README setup](../README.md#1-start-the-server), create the
first administrator with the CLI, then open http://127.0.0.1:8000/. Use your chosen account;
there are no default credentials. Times displayed by the dashboard and date filters use UTC.

## Sign-in and roles

Sessions expire after eight hours by default. Sign out from the navigation; changing your
password in **My account** signs out all your sessions. An administrator can reset a forgotten
password with `python -m app.cli reset-password USERNAME` from the server environment.

Viewers can read and export data, open reports and verify chains. Analysts can also triage
alerts and issue/cancel eligible responses. Administrators additionally manage accounts,
enrollment tokens, delivery retry and settings. A disabled account cannot sign in; changing
its role or disabling it revokes existing sessions.

## Overview and endpoint inventory

**Overview** shows online endpoints, open incidents, recent event volume, alert severity,
hourly incident activity, leading rules/endpoints and a recent-event feed. List/overview
views refresh periodically while you are not editing a field or using a control. Use the
refresh control when you need an immediate update.

**Devices** searches endpoint hostnames. Open a device to inspect heartbeat time, collection
status, reported CPU/memory, buffered/dropped events, recent alerts and observed processes.
Process rows are historical observations, not proof that the process is still running.
**Verify event chain** checks the stored history against its saved anchor and reports the
first failure if one is found.

## Investigate an alert

1. Open **Alerts** and filter by severity, status, endpoint or title/rule search.
2. Open an incident to inspect the rule, ATT&CK tags, occurrence count, timing and evidence.
3. Choose **Inspect** on an event to see its stored metadata and chain fields.
4. Open **Timeline** to examine surrounding endpoint activity. The incident link selects
   the window from 15 minutes before its first event to 15 minutes after its last event.
5. Add an investigation note and choose a status: new, acknowledged, investigating, resolved,
   or false positive. Analysts and administrators can update the incident.

Triage preserves actor/time history. A repeated firing may extend an open deduplicated
incident; a closed incident does not absorb a new firing. Evidence previews retain up to
100 event IDs, while individual firings persist separately in the database.

Notification delivery appears on the incident page. An administrator may retry disabled,
unconfigured or failed jobs after correcting server settings and restarting. A sent job
cannot be reset through this retry control.

## Explore events and timelines

**Events** supports endpoint, category, exact action, metadata search and UTC time filters.
Use pagination for larger results. Metadata search treats text literally rather than as a
regular expression. **Timeline** presents the selected endpoint's records chronologically;
choose an endpoint first when entering it from the main navigation.

**Export CSV** applies the current filters and includes at most 5,000 rows. Narrow the time
window for larger investigations. Spreadsheet-formula-like values are prefixed so opening
the file does not interpret endpoint metadata as formulas.

## Queue a response

For a Windows device, analysts/administrators can choose **Lock workstation** from the
device/incident page. **Kill process** is offered for suitable stored process-start evidence.
Review the device, executable, PID and creation time in the dialog, supply a reason, choose
an expiry (10–900 seconds; default 120), then confirm.

The agent must be running and configured with response execution enabled. A queued command
is delivered through heartbeat; it is not an immediate success notification. Open
**Commands** or the incident's response history to see delivery attempts, transitions and
results. Only an undelivered pending command can be cancelled. An offline endpoint may not
receive the command before it expires.

Results include succeeded, failed, rejected and unknown. An unknown result means execution
was interrupted; review the endpoint before issuing a new response. Kill may be rejected
because identity changed, the process exited, or it is protected. See the full
[response semantics](operations.md#response-commands).

## Reports

Open **Reports** or **Incident report** from an alert. The authenticated report includes:

- Incident metadata, triage history and device details.
- Linked evidence, missing-evidence findings and chain verification against the saved anchor.
- The surrounding event timeline, notification delivery and relevant response history.

Choose **Print / Save as PDF** to use your browser's print dialog. **Download JSON** provides
the report data for archiving. Timeline output is bounded to 250 records and response history
is bounded; report totals/limits identify omitted rows. Use Events/Commands to investigate
beyond these previews. Verification describes the database at report generation time.

## Rules and administration

**Rules** lets every role inspect conditions, severity and response configuration. Rule and
allowlist changes are made in the project's YAML files, validated with the CLI, then loaded
by restarting the server. This release has no browser rule editor.

In **Settings**, administrators can create accounts, manage their roles/disabled state,
create/revoke enrollment tokens, inspect delivery/response configuration and review recent
administrative actions. Enrollment tokens are shown once at creation. Copy the token before
closing its dialog. Revoking a token prevents future enrollment; it does not revoke device
keys that were already issued. The last enabled administrator is protected from removal.

Channel secrets remain in the server environment and are never shown by the settings API.
Configure Telegram/SMTP, secure cookies and response policies in `server/.env`, then restart.
The [operations guide](operations.md) explains Telegram operator IDs and the Windows installer.

## Screenshots

The [browser walkthrough](demo.md#isolated-browser-walkthrough) generates current desktop
overview, incident and mobile screenshots alongside a printable PDF in `artifacts/browser/`.
These generated files are ignored by Git and are also retained as CI workflow artifacts.
