# Windows installation and responses

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

Manual creation is limited to the local CLI and the operator's OS/database access. There is
no unauthenticated HTTP command-creation route. Dashboard roles and Telegram allowlisted
callbacks are the next integration steps.

Automatic actions additionally require `ST_AUTO_RESPONSE_ENABLED=true` and a rule with
`response.auto_action`. No starter rule has one. Old/future-dated events cannot trigger them,
and each deduplicated alert/action queues at most one command. See [rule configuration](rules.md).

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
