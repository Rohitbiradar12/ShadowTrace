# ShadowTrace EDR — Implementation plan and delivery status

> Source: Group 13 project deck (BKIT Bhalki, Dept. of CSE – Cyber Security,
> Guide: Prof. PremKumar).
> Goal: a lightweight, affordable EDR covering
> **Monitor → Detect → Alert → Investigate → Respond** for college labs,
> cyber cafés, startups and small offices.

Updated: **2026-10-30**.

## 0. Submission MVP

The original Windows product roadmap represents roughly 11–12 weeks for a four-person
team. The submission implements a complete monitoring-to-response loop with the scope
below. Section 12 preserves the larger roadmap; those future features are not claims
about the current build.

| Deliverable | Implementation status |
|---|---|
| Enrollment, heartbeat, batched upload, offline buffer and forensic hash chain | Implemented, with restart/retry and chain-recovery tests |
| Process, file, network, browser, Security Event Log, USB, Wi-Fi and Defender collectors | Eight collectors implemented; Windows installation scripts provided |
| YAML detection, local intel, deduplication and Telegram/email notifications | 27 starter rules, nine lists, persistent detection cursor and retrying outbox |
| Windows lock/kill responses | Durable commands through dashboard, CLI, Telegram confirmation or explicitly enabled rules |
| Authenticated dashboard and investigation | Local accounts, roles, overview, alerts, devices, events, timeline, commands, rules, settings and account page |
| Incident reports and exports | Authenticated printable HTML/JSON report with chain verification; CSV event export |
| Demo, documentation and CI | Synthetic pipeline demo, isolated browser walkthrough, architecture/user guides, project report and CI checks |

MVP choices:

- Plain HTML/CSS/JavaScript served by FastAPI; no separate frontend build or hosting service.
- Argon2id passwords and revocable server-side sessions with HttpOnly cookies.
- Print-friendly incident pages for browser **Save as PDF**, plus JSON.
- Polling dashboard refresh rather than WebSockets.
- Local rule and intel files rather than feed synchronization or browser editing.
- One server worker, with process-local coordination for forensic writes and commands.
- Lock and verified process termination only; quarantine is deferred.

### Validation and remaining acceptance

Automated coverage includes collection/recovery, detection, command journaling, role/session
boundaries, CSRF, triage, report escaping/integrity, Telegram confirmation/deduplication,
and an isolated desktop/mobile browser walkthrough. The documented commands and CI run
these checks; generated browser screenshots and a printable report go to **artifacts/browser/**.

Response effects and Telegram/SMTP transports are mocked in automated checks. A native,
read-only Windows process identity test and Defender Event Log query have been exercised.
An elevated clean-machine installation, real workstation lock/kill and configured external
message delivery still require operator-run lab acceptance. Performance targets have not
been measured in a long-running multi-endpoint deployment.

[README](../README.md) gives setup instructions. [Demo playbook](demo.md) separates the
synthetic walkthrough from those real-environment acceptance steps.

## 1. Scope and boundaries

| Objective | Delivered behavior |
|---|---|
| Lightweight collection | Python agent, configurable polling, bounded batches and SQLite offline buffering |
| Activity monitoring | Eight collectors spanning files, processes, browsing, logins, devices and network activity |
| Threat detection | Validated single-event and threshold YAML rules, allowlists, local indicators and ATT&CK tags |
| Forensic logging | Per-device SHA-256 event chain, saved anchor, integrity check, searchable timeline and exports |
| Alerts | Persistent triage state and retrying Telegram/email delivery with rate limits and digests |
| Central dashboard | Authenticated investigation, account administration and device enrollment |
| Response | Audited expiring lock/kill commands, endpoint opt-in and persisted execution/results |

The full collector and responder target is Windows 10/11. Common collectors have a
platform-aware interface; complete Linux/macOS endpoint support is future work.
The server and browser dashboard are OS-independent.

Kernel drivers, machine-learning malware classification, enterprise SIEM integration and
network isolation are outside the submission MVP. No claim of antivirus replacement or
independently verified endpoint remediation is made.

## 2. Delivered architecture

~~~mermaid
flowchart LR
    C[Eight Windows/common collectors] --> B[SQLite event buffer]
    B -->|Batched device-key API| I[FastAPI ingest]
    I --> F[MongoDB events and hash-chain anchor]
    F --> D[YAML detection and local lists]
    D --> A[Alerts and notification outbox]
    A --> N[Telegram / SMTP]
    A --> U[Authenticated dashboard and reports]
    U --> Q[Durable command queue]
    N -->|Allowlisted confirmation| Q
    D -->|Opt-in rule action| Q
    Q -->|Heartbeat lease| R[Agent response journal]
    R --> W[Windows lock / verified process termination]
    R -->|Result acknowledgement| Q
~~~

Detection belongs on the server so rules, event-time history and alert state share a
single durable source. Device keys authorize enrollment-derived endpoint identity;
dashboard sessions and Telegram operator IDs authorize separate operator workflows.

See [architecture.md](architecture.md) for components, trust boundaries and failure behavior.

## 3. Stack

| Area | Current implementation |
|---|---|
| Agent | Python 3.12+, psutil, watchdog, pywin32/WMI, SQLite, httpx, YAML/Pydantic |
| Windows execution | Interactive elevated logon task; native Windows response APIs |
| Server | FastAPI/Uvicorn, Pydantic, Beanie with PyMongo async, MongoDB 8 |
| Authentication | Argon2id; opaque session cookie, hashed session token and server-side expiry/version |
| Detection | File-backed YAML rules, persistent MongoDB event-time windows and detection cursor |
| Notifications | httpx Telegram Bot API and standard-library SMTP TLS client in a worker thread |
| Dashboard | Local HTML/CSS/JavaScript modules, SVG chart, responsive tables and dialogs |
| Reports | Jinja autoescaped HTML, browser printing, JSON and CSV |
| Verification | pytest, Ruff, native PowerShell parsing, Playwright and GitHub Actions |

## 4. Repository map

~~~text
agent/shadowtrace_agent/
  collectors/common/       process, file, network, browser
  collectors/windows/      Security Event Log, USB, Wi-Fi, Defender
  response/                protected Windows actions and response journal
  transport/               server client, offline buffer and delivery loops
server/app/
  api/                     agent endpoints, dashboard endpoints, session auth
  models/                  MongoDB documents
  detection/               rule loading, matching, persistent detection/alerts
  notify/                  delivery outbox and Telegram controls
  services/                ingest, auth, triage, commands and reports
  forensics/               hash-chain writes and verification
  web/static/              dashboard modules and styles
  web/templates/           printable incident report
rules/                     27 YAML rules
intel/lists.yaml           nine local indicator/allowlists
scripts/                   demo, browser validation, Windows install/uninstall
docs/                      plan, setup-related guides, architecture and report
~~~

## 5. Data and durability

| Collection/group | Purpose |
|---|---|
| devices, enrollment_tokens | Device identity/key hash, heartbeat, saved chain anchor and enrollment quotas/expiry |
| events | Validated telemetry with sequence, chain index, previous hash and event hash |
| alerts, alert_hits | Deduplicated incidents, evidence references, individual firings and triage history |
| notifications | Delivery channel, retry state, attempts and digest/rate-limit bookkeeping |
| commands | Target evidence, actor, reason, expiry, delivery lease, result and history |
| users, sessions, login_buckets, audit_log | Hashed credentials/tokens, roles, revocation, login throttling and operator audit |
| telegram_actions, telegram_cursors | Expiring callback targets, confirmation owner/result and durable polling offset |

Event envelopes contain an event UUID, device ID, timestamp, category/action, user,
type-specific metadata and sequence. The server appends the chain metadata. Agent credentials,
password hashes and session tokens are excluded from dashboard/report representations.

There is no automatic TTL deletion of event history. Retention must preserve chain semantics.
The anchor is stored in the same database: a party who rewrites both events and anchors can
forge a replacement history. External signed anchoring remains future work.

## 6. Collection

Four common collectors cover process starts/stops, watched file changes, connections and
browser history/download metadata. Windows collectors add Security events, USB changes,
Wi-Fi changes and Defender Operational records.

Saved collector cursors and SQLite buffering recover across restarts and temporary network
failure. Browser and Event Log collectors baseline at first run. Polling can miss short-lived
activity; log retention can remove unseen records. File *read* access, Authenticode verification,
and per-user multi-session monitoring are not included.

## 7. Detection

Rules are loaded from YAML and validated before use. Matching supports typed comparisons,
text/regex conditions, list lookups, exclusions and per-device grouped thresholds. Thresholds
use persisted event-time windows, including late/offline arrivals. A durable cursor lets the
recovery worker resume interrupted detection.

Alert firings and notification jobs are idempotent across retries. A new firing joins the
same open rule/device/group incident inside the configured rolling deduplication period.
Closed incidents do not absorb new firings. Evidence previews retain up to 100 event IDs;
individual firings remain available in the database.

See [rules.md](rules.md) for supported syntax, all 27 rules, ATT&CK mappings and list tuning.
The supplied bad indicators are demo fixtures, not live threat intelligence.

## 8. Notifications and Telegram

Notifications default off until destinations are configured. Each device/channel has a rate
budget; pending alerts can form digests. Transient failures retry with backoff and exhausted
jobs remain inspectable/retryable by an administrator.

Telegram controls additionally require an enabled flag, the configured destination chat and
an allowlist of numeric operator IDs. Callback payloads reference server-stored evidence,
expire, and cannot select an arbitrary PID. Lock/kill require the same operator's confirmation
within 60 seconds. Durable callback results and command IDs suppress repeated execution
requests after network retries. Acknowledge does not reopen a closed incident.

A dedicated bot must use this server's long polling without another polling client or webhook.
See [operations.md](operations.md#telegram-controls) for setup.

## 9. Response behavior

Commands are queued by an analyst/administrator, local CLI, allowed Telegram operator or
explicitly enabled rule. The agent also requires local response opt-in. Commands expire,
are leased through heartbeat and retain actor/reason/state history.

Kill requires a stored process-start event with PID, absolute executable path and creation
time. Windows identity checks and termination use the same process handle, and refuse the
agent, its ancestors and protected/critical processes. A durable endpoint journal suppresses
duplicates and resends saved results after lost acknowledgement. An interrupted action is
reported as **unknown** instead of being automatically repeated.

The default heartbeat is ten seconds and default command TTL is 120 seconds. Lock success
means the Windows request was accepted, not that the final desktop state was observed.
See [operations.md](operations.md#response-commands) for all result states.

## 10. Dashboard and reports

All data routes require a session. Viewers can investigate/export; analysts can additionally
triage and queue/cancel eligible commands; administrators also manage users, tokens and retry
failed deliveries. Account changes revoke existing sessions. The last enabled administrator
cannot be removed through the dashboard.

Pages cover Overview, Alerts, Devices, Events, Timeline, Commands, Reports, Rules, Settings
and My account. Device process rows are historical observations, not a live process snapshot.
Rules and deployment settings are inspected in the browser and configured in files.

CSV export includes at most 5,000 matching events and neutralizes spreadsheet formulas.
Incident reports include alert/evidence, triage history, delivery/response state, chain
verification and a bounded surrounding timeline. HTML can be printed to PDF; JSON is also
available. See [user-guide.md](user-guide.md).

## 11. Security and operating assumptions

- Deploy with HTTPS, secure session cookies and a trusted reverse proxy outside localhost.
- Use one server worker; database and server OS administrators are trusted.
- Store device keys, enrollment/session tokens and dashboard passwords as hashes server-side.
- Require role checks, CSRF tokens and same-origin validation for dashboard mutations.
- Keep Windows code/config/data restricted to SYSTEM/Administrators through the installer.
- Tune watched paths, allowlists and response policy to the monitored environment.
- Disclose collection and restrict access to browsing URLs, command lines and exported evidence.
- Keep credentials and generated artifacts outside version control.

Filesystem protection does not yet include DPAPI encryption. Login throttling exists;
general ingest rate limiting, external audit anchoring and broader deployment hardening
remain future work.

## 12. Full product roadmap retained as future work

The original phased plan is retained below with the submission boundary stated explicitly.
Indicative durations are estimates, not promises that all stages are delivered.

| Phase | Original estimate | Delivered / remaining |
|---|---|---|
| 0. Setup | 0.5 week | Repository, environments, MongoDB integration, CI and platform interface delivered; destinations are operator configuration |
| 1. Core pipeline | 1.5 weeks | Enrollment, heartbeat, buffering, ingest, process collection and forensic chain delivered |
| 2. Collectors | 2 weeks | Eight collectors and installer scripts delivered; file-read/SACL auditing, signing and clean-machine acceptance remain |
| 3. Detection and alerts | 1.5 weeks | Rules, local lists, persistence and delivery outbox delivered; scheduled feed sync remains |
| 4. Dashboard | 2 weeks | Session-based plain-JS dashboard delivered; React migration/WebSockets optional, browser rule editor remains |
| 5. Response | 1 week | Lock/kill, durable queue, roles, Telegram confirmation and opt-in rules delivered; quarantine/restore remains |
| 6. Forensics and reports | 1 week | Chain verification, HTML/JSON reports and CSV delivered; external anchoring and richer exports remain |
| 7. Hardening and packaging | 1 week | Protected installer and security tests delivered; PyInstaller, DPAPI, offline-agent alerting, retention policy, performance measurements and scale remain |
| 8. Testing and demo | 1 week | Tests, synthetic/browser demos, guides and report delivered; live lab acceptance and measured deployment results remain |
| 9. Linux agent (optional) | 2–3 weeks | Native journal/USB/Wi-Fi collectors, responses, systemd and packages remain |
| 10. macOS agent (optional) | 3–4 weeks | Native telemetry, responses, launchd, TCC guide and signed packaging remain |

Further research: Sysmon/ETW, YARA, Sigma import, network isolation, ML anomaly detection,
multi-tenant operation and enterprise integrations. The common event schema and collector
interface are the extension points; unimplemented platform stubs are not complete agents.

## 13. Demo and documentation deliverables

Use [demo.md](demo.md) for the implemented synthetic pipeline and browser walkthrough.
Destructive log clearing, induced account lockouts, disabling protection, changing live Wi-Fi
and terminating real user processes are unnecessary for the submission demo.

Delivered documentation:

- [README](../README.md): setup and current limits.
- [Architecture](architecture.md): flow, persistence, trust and failure handling.
- [Rules](rules.md): syntax, catalog and indicator tuning.
- [User guide](user-guide.md): dashboard investigation and response workflows.
- [Operations](operations.md): installer, local accounts, Telegram and response semantics.
- [Demo](demo.md): reproducible walkthrough, artifacts and separate lab acceptance.
- [Project report](project-report.md): objectives, implementation, validation and limitations.

Do not present CPU/RAM targets, alert latency, accuracy percentages or live acceptance as
measured results until the corresponding deployment experiment has been recorded.
