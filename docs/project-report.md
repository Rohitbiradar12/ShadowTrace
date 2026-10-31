# ShadowTrace project report

**Group 13 — BKIT Bhalki, Department of CSE – Cyber Security**  
**Guide: Prof. PremKumar**  
**Submission build scope: 2026-10-30**

## Abstract

ShadowTrace demonstrates an endpoint detection and response loop for small Windows labs and
offices. A Python agent monitors selected activity, buffers records offline and uploads them
to a FastAPI/MongoDB server. YAML rules identify suspicious behavior, persistent incidents
support investigation, and operators can queue Windows workstation locks or verified process
termination. An authenticated web dashboard combines evidence, timeline, triage, notifications,
response history and printable reports. The implementation prioritizes inspectable rules and
failure recovery within a single-server deployment.

## Problem and objectives

Small shared-computer environments need a central view of endpoint activity and a practical
way to investigate incidents. Raw device logs alone do not connect detection, evidence and
operator actions. The project aims to collect relevant metadata, identify configured patterns,
notify an operator, preserve a verifiable event history and record a controlled response.

The submission does not establish a performance or detection-accuracy advantage over commercial
EDR products. Its contribution is an implemented, understandable workflow with explicit
operating limits and reproducible checks.

## Background and design choices

The design uses established endpoint logging, rule-based detection, durable queues and hash
chaining. Event-time thresholds are useful when an endpoint uploads buffered records late.
An outbox separates reliable incident creation from unreliable external message delivery.
The response journal distinguishes replaying a result from repeating a Windows action.

The original product roadmap proposed React, JWT, external intel synchronization and a PDF
library. For the submission, FastAPI serves plain HTML/CSS/JavaScript with revocable cookie
sessions; intel is file-backed, and browsers print reports to PDF. These choices reduce the
number of processes/dependencies needed during a local demonstration. See [PLAN.md](PLAN.md)
for the retained roadmap and [architecture.md](architecture.md) for the implemented flow.

## Implementation

| Component | Delivered behavior |
|---|---|
| Collection | Process, file, network, browser, Security Event Log, USB, Wi-Fi and Defender collectors |
| Transport | Expiring enrollment, hashed per-device key, heartbeat, batched upload and SQLite offline buffer |
| Evidence | Per-device SHA-256 chain, saved anchor, recovery checks and explicit integrity verification |
| Detection | 27 YAML rules, nine local lists, per-device thresholds, deduplication and persisted detection progress |
| Alerts | Triage status/notes/history, linked evidence and retrying Telegram/SMTP outbox with digests |
| Access | Argon2id passwords, session revocation, login throttling, CSRF and admin/analyst/viewer roles |
| Dashboard | Overview, devices, alerts, events, timeline, commands, reports, rules, settings and account management |
| Responses | Expiring heartbeat command leases, local opt-in, verified Windows kill/lock and persisted results |
| Telegram | Chat/operator allowlists, expiring callbacks, acknowledgement, same-operator action confirmation |
| Reports | Authenticated printable HTML/JSON, bounded incident timeline and filtered CSV export |
| Operations | Fresh-install/uninstall scripts, CLI administration, setup guides and automated CI |

Device processes shown in the dashboard are historical observations. Kill commands must
still match the live executable/start time on Windows and exclude protected processes.
The supplied indicator values are synthetic demonstrations, not a maintained threat feed.

## Validation and results

Tests cover buffer/cursor recovery, duplicate ingestion, chain edits/deletions, event-time
detection, alert/outbox idempotency, retries, command ownership/expiry/journaling, role/session
revocation, CSRF, report escaping and Telegram confirmation/deduplication. A real-browser
walkthrough uses an isolated database and server to exercise desktop/mobile dashboard flows,
exports and printable report output. The workflow and commands are in [demo.md](demo.md).

The automated tests mock workstation effects and Telegram/SMTP transports. Native read-only
Windows process identity and Defender Event Log access are separate checks. Elevated clean
installation, live lock/kill and configured external delivery remain lab acceptance items.
No benchmark, false-positive percentage or detection-rate claim is inferred from synthetic
fixtures. Record those measurements only after a defined deployment experiment.

The generated `artifacts/browser/` screenshots, PDF and summary provide reproducible submission
illustrations. The CI run stores the same artifact directory. Test output belongs to the
specific revision and environment used; retain it with the submitted build.

## Security, privacy and limitations

Passwords and server-side device/session credentials are hashed. Browser mutations require
session, role and CSRF checks. Endpoint files have restricted ACLs when installed through the
script, and responses require explicit local opt-in. Telegram operators require both a valid
chat and a listed user ID. All response channels converge on the same durable command service.

Browsing URLs, executable command lines, file paths and usernames may be sensitive even
without page contents or keystrokes. Collection must be disclosed, access limited and exported
reports handled according to the lab's data policy. Watched directories and local lists must
be configured for that environment.

The server supports one worker. Polling can miss short-lived activity; Windows log retention
can remove unseen events. The hash-chain anchor shares MongoDB with its records and cannot
prevent a fully privileged attacker from rewriting both. Endpoint acknowledgements are not
independent proof of remediation. Reports/exports intentionally bound preview sizes; full
investigation may require narrower filters. DPAPI storage, external signed anchoring,
retention policy and measured scalability remain future work.

## Applications and future work

The current build supports teaching the EDR workflow, small controlled Windows lab trials,
and studying event collection, rule matching, forensic integrity and response reliability.
Deployment acceptance and tuning are required before relying on it for a real environment.

The retained roadmap includes file-read auditing, Authenticode verification, quarantine and
restore, synchronized threat feeds, browser rule editing, packaging, offline-agent alerts,
external audit anchoring, multi-worker coordination and native Linux/macOS support. Longer-term
extensions include Sysmon/ETW, YARA, Sigma import, isolation actions and multi-tenant operation.

## Viva discussion points

- Why does detection use event time while delivery uses receipt/queue state?
- What can a saved hash-chain anchor detect, and what can a database administrator still alter?
- Why persist a command before executing it, and why report an interrupted action as unknown?
- How do a device key, dashboard role and Telegram allowlist authorize different actors?
- Why does PID alone fail to identify a safe process-termination target?
- Which results come from tests, which from read-only native checks, and which still require live acceptance?

## References

The [operations guide](operations.md) links the Microsoft APIs used for task installation,
Defender events and Windows responses. The [rules guide](rules.md) links implemented rule
definitions and their ATT&CK tags. Primary protocol documentation includes
[Telegram Bot API](https://core.telegram.org/bots/api),
[FastAPI](https://fastapi.tiangolo.com/) and
[argon2-cffi](https://argon2-cffi.readthedocs.io/).
