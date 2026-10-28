# ShadowTrace EDR — End-to-End Implementation Plan

> Source: Group 13 project deck (BKIT Bhalki, Dept. of CSE – Cyber Security, Guide: Prof. PremKumar).
> Goal from the deck: a **lightweight, affordable EDR** that runs the full loop
> **Monitor → Detect → Alert → Investigate → Respond** for students, cyber cafés, college labs, startups and small offices.

---

## 0. Submission schedule (deadline: next week)

The full plan below is ~12 weeks of team work. For the submission we build a **demo-ready MVP that still covers the whole Monitor → Detect → Alert → Investigate → Respond loop**; the rest moves to Future work.

| Order | Deliverable | Status |
|---|---|---|
| 1 | Core pipeline: enrollment, heartbeat, event upload, offline buffer, hash chain, process monitor | ✅ Done |
| 2 | Windows monitors: USB, logins & account changes & Defender (Event Log), file activity, network connections, Wi-Fi, browser history & downloads | In progress |
| 3 | Detection rules (YAML, single-event + threshold), local threat-intel lists, alert de-duplication, Telegram + email alerts | |
| 4 | Responses: lock workstation, kill process — from dashboard, Telegram buttons, or automatically by rule | |
| 5 | Dashboard: login, overview, alerts, devices, events, timeline, rules, settings, printable incident report | |
| 6 | Demo scripts, README, CI | |

MVP simplifications vs. the full plan:
- Dashboard is plain **HTML/CSS/JS served by the FastAPI server** (the deck's stack) instead of React — no build step, one process to run, works offline on demo day.
- Dashboard login uses server-side sessions (HttpOnly cookie) instead of JWT — simpler and revocable.
- Incident report is a print-friendly page (browser "Save as PDF") instead of a PDF library.
- Dashboard auto-refreshes every few seconds instead of using WebSockets.
- Threat intel ships as local lists instead of scheduled feed sync.
- Moved to Future work: file *read* auditing (Event 4663), Authenticode signature checks, PyInstaller packaging, in-browser rule editor, Linux/macOS agents.

---

## 1. Scope (what the deck commits to)

| # | Objective (deck slide 04) | How we deliver it |
|---|---|---|
| 1 | Lightweight monitoring | Python agent, < 2% CPU / < 100 MB RAM target, batched uploads |
| 2 | Activity monitoring | 7 collectors: files, USB, processes/executables, browsing, logins, Wi-Fi/network, insider behaviour |
| 3 | Threat detection | YAML rule engine (single-event + threshold/correlation rules), threat-intel lookups, MITRE ATT&CK tags |
| 4 | Forensic logging | Append-only, hash-chained event store; per-device activity timeline; exportable incident report |
| 5 | Real-time alerts | Telegram Bot + email, with severity filter, de-duplication and rate limiting |
| 6 | Centralized dashboard | Web dashboard: overview, devices, alerts, events, timeline, rules, settings |
| 7 | Basic defensive actions | Lock workstation, kill process, quarantine file — triggered manually (dashboard/Telegram) or automatically by rule |

**Out of scope** (matches the deck's "Limitations" slide): kernel drivers, ML-based malware classification, full network isolation, enterprise SIEM integration. These go in "Future work".

**Target platform for the agent:** Windows 10/11 first (the realistic platform for cyber cafés, college labs and small offices). The agent is **designed cross-platform from day one** — Linux and macOS agents are optional phases 9–10 (see §12a). The server and dashboard are OS-independent already.

---

## 2. Architecture

```
┌────────────────────────── Endpoint (Windows PC) ──────────────────────────┐
│  ShadowTrace Agent (Python)                                               │
│   ├─ Collectors: file · usb · process · browser · login · network · wifi │
│   ├─ Normalizer → common Event schema                                     │
│   ├─ Local buffer (SQLite) — survives network outages                     │
│   ├─ Uploader (HTTPS, batched, per-device API key)                        │
│   └─ Responder: lock · kill process · quarantine file                     │
└──────────────┬───────────────────────────────────────▲────────────────────┘
               │ POST /events/batch                    │ heartbeat → pending commands
               ▼                                       │
┌────────────────────────── ShadowTrace Server (FastAPI) ───────────────────┐
│   Ingest API → Forensic store (hash chain) → Detection engine (rules)     │
│        │                                         │                        │
│        ▼                                         ▼                        │
│   MongoDB (events, alerts, devices, …)     Alert manager → Telegram/Email │
│   Command queue (lock/kill/quarantine)  ◄── Auto-response policies        │
│   REST + WebSocket for dashboard                                          │
└──────────────┬────────────────────────────────────────────────────────────┘
               ▼
┌──────── Dashboard (React) ────────┐        ┌──── Telegram ────┐
│ Overview · Devices · Alerts ·     │        │ Alert messages + │
│ Events · Timeline · Rules ·       │        │ inline buttons   │
│ Settings · Reports                │        │ [Lock] [Kill]    │
└───────────────────────────────────┘        └──────────────────┘
```

Detection runs **on the server** so there is one place for rules, correlation across events (e.g. brute force = N failures in T seconds) and auditing. The agent only collects, buffers, uploads and executes signed-off commands.

---

## 3. Tech stack

### 3.1 Agent (runs on each endpoint)

| Concern | Choice | Notes |
|---|---|---|
| Language | **Python 3.12** | Already installed; matches deck |
| Process & network | `psutil` | Process start/stop polling, `net_connections()` per PID |
| File monitoring | `watchdog` | ReadDirectoryChangesW: create/modify/delete/move on watched folders |
| File *read* access | Windows Object Access auditing (Event **4663**) | Enabled via `auditpol` + SACL on configured sensitive folders — watchdog cannot see reads |
| Windows Event Log | `pywin32` (`win32evtlog`) | Security log: 4625, 4624, 4740, 4720, 4732, 1102 |
| USB devices | `wmi` + `pywin32` | `Win32_VolumeChangeEvent` / `Win32_DiskDrive` → VID, PID, serial, label |
| Wi-Fi | `netsh wlan show interfaces` (parsed) | SSID, BSSID, auth type (flags open networks) |
| Browser history | `sqlite3` (stdlib) | Copy-then-read Chrome/Edge/Brave/Firefox `History`/`places.sqlite` |
| File hashing / signing | `hashlib`, WinVerifyTrust via `ctypes` | SHA-256 + Authenticode signed/unsigned |
| Local buffer | SQLite (stdlib) | Queue of unsent events; retry with backoff |
| HTTP | `httpx` | HTTPS, timeouts, retries |
| Config | YAML (`pyyaml`) + `pydantic` | Server URL, watched paths, intervals |
| Responses | `ctypes` (`LockWorkStation`), `psutil.Process.kill`, `shutil.move` | Quarantine = move + strip execute + record hash |
| Packaging | **PyInstaller** → `shadowtrace-agent.exe` | Single exe + installer script |
| Running it | **Scheduled Task**: "At log on", "Run with highest privileges" | Runs in the user's session (needed for lock-screen and per-user browser history) **and** has admin rights (needed for the Security log). A Windows Service would run in Session 0 and could not lock the user's screen. |

### 3.2 Server (central)

| Concern | Choice | Notes |
|---|---|---|
| Framework | **FastAPI** (Python 3.12) + Uvicorn | Async, auto OpenAPI docs at `/docs` |
| Validation | Pydantic v2 | Same models shared conceptually with the agent |
| Database | **MongoDB 8** | Already installed locally; event payloads differ per type → document model fits. MongoDB Atlas free tier for cloud demo |
| ODM / driver | **Beanie** on PyMongo's async API | (Motor is deprecated) |
| Auth (dashboard users) | JWT access + refresh tokens, `argon2` password hashing | Roles: `admin`, `analyst`, `viewer` |
| Auth (agents) | Enrollment token → per-device API key (random 256-bit, stored as SHA-256) | Header `X-Device-Key` |
| Detection | Custom YAML rule engine | Sigma-inspired syntax, MITRE ATT&CK IDs |
| Threat intel | abuse.ch URLhaus + Feodo Tracker, OpenPhish feed, MalwareBazaar recent hashes; optional VirusTotal / Google Safe Browsing API keys | Feeds downloaded on a schedule, cached in Mongo |
| Background jobs | `APScheduler` | Feed refresh, offline-agent check, retention cleanup |
| Live updates | WebSocket (`/ws/live`) | New alerts/events pushed to dashboard |
| Telegram | Telegram Bot API via `httpx` (+ bot long-polling for button callbacks) | Inline buttons: Acknowledge / Lock PC / Kill process |
| Email | SMTP via `aiosmtplib` (Gmail app password or any SMTP) | HTML email template |
| Reports | `reportlab` | Incident/forensic PDF export; CSV export for events |
| Config | `pydantic-settings` + `.env` | Secrets never in git |

### 3.3 Dashboard

| Concern | Choice |
|---|---|
| Build | **Vite + React 18 + TypeScript** (TS is JavaScript with types — fewer bugs) |
| Styling | Tailwind CSS + shadcn/ui components |
| Data fetching | TanStack Query |
| Routing | React Router |
| Charts | Recharts |
| Tables | TanStack Table (filter/sort/paginate events) |
| Live feed | Native WebSocket |

### 3.4 Tooling

| Purpose | Tool |
|---|---|
| Python env / deps | `uv` (fast) — or plain `venv` + `pip` |
| Lint / format | `ruff` (Python), ESLint + Prettier (TS) |
| Tests | `pytest`, `pytest-asyncio`, `mongomock-motor`/test DB; Vitest for dashboard |
| API testing | FastAPI `/docs`, Bruno or Postman |
| DB GUI | MongoDB Compass |
| CI | GitHub Actions: lint + tests on push |
| Attack simulation | Own safe scripts in `scripts/simulate/` + EICAR test file + (optional) Atomic Red Team |

### 3.5 Accounts / keys you will need

- Telegram: create bot with **@BotFather** → bot token; get your chat ID.
- Email: Gmail account with 2FA + **App Password** (or any SMTP provider).
- Optional: VirusTotal free API key, Google Safe Browsing API key.
- Optional (cloud demo): MongoDB Atlas free cluster + Render/Railway (server) + Vercel/Netlify (dashboard).

> **Deviation from the deck:** the deck lists Firebase. We use FastAPI + MongoDB instead because
> (a) Firestore's free tier caps at ~20K writes/day, which a few monitored PCs exceed quickly;
> (b) Cloud Functions (needed for server-side detection and Telegram callbacks) require the paid Blaze plan;
> (c) a Firebase agent would need a service-account key on every endpoint — a credential-theft risk for a security product;
> (d) correlation rules (brute force, mass file copy) need a real server.
> Everything else in the deck's references (HTML/CSS/JS, Python, Telegram Bot API) is kept.

---

## 4. Repository layout

```
ShadowTrace/
├─ agent/
│  ├─ shadowtrace_agent/
│  │  ├─ collectors/
│  │  │  ├─ base.py       Collector interface + platform-aware registry
│  │  │  ├─ common/       process.py file.py network.py browser.py   (psutil/watchdog/sqlite — all OSes)
│  │  │  ├─ windows/      eventlog.py usb.py wifi.py signing.py
│  │  │  ├─ linux/        (phase 9)  journal.py usb.py wifi.py
│  │  │  └─ macos/        (phase 10) unifiedlog.py usb.py wifi.py signing.py
│  │  ├─ response/        lock.py kill.py quarantine.py   (per-OS backends behind one interface)
│  │  ├─ transport/       uploader.py buffer.py commands.py
│  │  ├─ schema.py        common Event model
│  │  ├─ config.py
│  │  └─ main.py          supervisor: starts collectors, uploader, command loop
│  ├─ config.example.yaml
│  ├─ install.ps1         creates scheduled task, enables audit policy
│  └─ tests/
├─ server/
│  ├─ app/
│  │  ├─ api/             auth.py agents.py events.py alerts.py commands.py devices.py rules.py reports.py ws.py
│  │  ├─ models/          Beanie documents
│  │  ├─ detection/       engine.py loader.py intel.py
│  │  ├─ notify/          telegram.py email.py dispatcher.py
│  │  ├─ forensics/       chain.py timeline.py report.py
│  │  ├─ jobs/            scheduler.py
│  │  ├─ core/            config.py security.py db.py
│  │  └─ main.py
│  ├─ .env.example
│  └─ tests/
├─ rules/                 *.yaml detection rules
├─ dashboard/             Vite React app
├─ scripts/simulate/      safe attack-simulation scripts for demo
├─ docs/                  PLAN.md, architecture, user guide, report material
└─ NotGit/                (git-ignored) PPTs, PDFs
```

---

## 5. Data model (MongoDB collections)

**Common event envelope** (every collector emits this):

```json
{
  "event_id": "uuid",
  "device_id": "dev_…",
  "ts": "2026-10-28T10:15:02Z",
  "category": "usb | file | process | browser | auth | network | wifi | system",
  "action": "device_connected | file_deleted | process_started | url_visited | logon_failed | …",
  "user": "DESKTOP\\student",
  "data": { "...type-specific fields..." },
  "seq": 1042,
  "prev_hash": "sha256 of previous event for this device",
  "hash": "sha256(prev_hash + canonical event)"
}
```

| Collection | Key fields | Indexes |
|---|---|---|
| `users` | email, password_hash, role | unique email |
| `devices` | device_id, hostname, os, ip, agent_version, api_key_hash, last_seen, status, tags | device_id, last_seen |
| `enrollment_tokens` | token_hash, expires_at, used | TTL on expires_at |
| `events` | envelope above | (device_id, ts), (category, action, ts), TTL for retention (e.g. 90 days) |
| `alerts` | alert_id, rule_id, severity, device_id, event_ids[], status (new/ack/investigating/resolved/false_positive), assignee, notes[], mitre[] | (status, severity, created_at) |
| `rules` | rule_id, yaml, enabled, version | rule_id |
| `commands` | command_id, device_id, type (lock/kill/quarantine), params, status (pending/sent/done/failed), issued_by, result | (device_id, status) |
| `audit_log` | who did what (logins, commands, rule edits) | ts |
| `intel` | indicator, type (url/domain/ip/hash), source, updated_at | unique indicator |
| `settings` | notification config, allowlists (USB serials, trusted SSIDs, sensitive paths, work hours) | — |

**Forensic integrity:** each device's events form a hash chain. A "Verify integrity" button recomputes the chain and shows the first broken link if anyone edited/deleted events.

---

## 6. Monitoring modules (agent) — detail

| Module | What it collects | Key detections (rule examples) | ATT&CK |
|---|---|---|---|
| **File access** | Create/modify/delete/rename in watched folders (Documents, Desktop, configured sensitive dirs); reads via Event 4663 on sensitive dirs | Access to sensitive folder by non-allowed user; mass delete/rename (> 50 in 60 s → possible ransomware); EICAR / known-bad hash dropped | T1005, T1486 |
| **USB** | Connect/disconnect, VID/PID/serial, label, drive letter; files copied to removable drive | Unknown USB (serial not in allowlist); bulk copy to USB (> N files / > X MB) | T1091, T1052.001 |
| **Suspicious executables / processes** | New processes: path, SHA-256, signer, parent, cmdline | Executable launched from Downloads/Temp/AppData/USB; unsigned binary; hash in MalwareBazaar; Office → PowerShell/cmd; `powershell -enc`; LOLBins (certutil -urlcache, mshta, rundll32 with URL) | T1204, T1059.001, T1218 |
| **Unsafe browsing** | Visited URLs from Chrome/Edge/Brave/Firefox history (polled) | Domain/URL in URLhaus/OpenPhish/blocklist; raw-IP URLs; newly-seen download of .exe/.scr/.js | T1566, T1189 |
| **Failed logins** | Event 4625 (failed), 4624 (success w/ logon type), 4740 (lockout) | ≥ 5 failures in 2 min → brute force; success right after many failures; login outside work hours | T1110 |
| **Wi-Fi & network** | Current SSID/BSSID/auth; new outbound connections (remote IP, port, process) | Connected to open/unknown SSID; connection to IP in Feodo blocklist; unusual ports (4444, 1337, 6667…); process with no history making external connections | T1071, T1571 |
| **Insider misuse** | Derived from the above + 4720/4732 (new user / added to admins), 1102 (log cleared) | Activity outside work hours; new local admin; security log cleared; USB + mass file copy combo; disabling Defender (registry/process) | T1136, T1070.001, T1562 |
| **Agent health** | Heartbeat every 10 s with CPU/RAM | Agent offline > 2 min → "possible tampering" alert | T1562.001 |

---

## 7. Detection engine

Rules live in `rules/*.yaml` and are loaded into Mongo; editable from the dashboard.

```yaml
id: ST-AUTH-001
title: Possible brute-force login
severity: high          # low | medium | high | critical
mitre: [T1110]
match:
  category: auth
  action: logon_failed
threshold:
  count: 5
  within: 120s
  group_by: [device_id, data.target_user]
response:
  notify: [telegram, email]
  auto_action: lock_workstation   # optional
```

Engine features:
- **Single-event rules** — field equals / in / contains / regex / startswith / path-in-list.
- **Threshold rules** — count within a sliding window, grouped by fields (in-memory window + Mongo fallback).
- **Intel rules** — `intel_match: domain|ip|hash`.
- **Allowlists** — global and per-rule suppressions (reduce false positives).
- **Dedup** — same rule + device + group key within 10 min updates the existing alert's count instead of creating a new one.

Starter rule pack: ~20 rules covering every module in §6.

---

## 8. Alerting

- Dispatcher picks channels by severity (default: `high`/`critical` → Telegram + email; `medium` → dashboard only).
- Telegram message: severity emoji, device, user, rule title, key fields, timestamp, dashboard link, inline buttons **[Acknowledge] [Lock PC] [Kill process]**. Callbacks verified against an allowlisted chat ID.
- Rate limit: max N messages/min per device; digest mode if exceeded.
- All notifications recorded on the alert (who was notified, when, delivery status).

---

## 9. Response actions

| Action | Implementation | Safety |
|---|---|---|
| Lock workstation | `ctypes.windll.user32.LockWorkStation()` | Always safe; reversible by user login |
| Kill process | `psutil.Process(pid).kill()` after verifying PID still matches same image path + start time | Protected list: never kill `csrss`, `lsass`, `winlogon`, `services`, `System`, the agent itself |
| Quarantine file | Move to `C:\ProgramData\ShadowTrace\quarantine\<sha256>` with ACL lock-down; metadata stored; restore supported | Only files outside Windows/Program Files |

Flow: dashboard/Telegram/auto-rule creates `command` → agent receives it in its next heartbeat response (≤ 5 s) → executes → reports result → audit log entry.

---

## 10. Dashboard pages

1. **Login** (JWT)
2. **Overview** — KPIs (devices online, open alerts by severity, events/24 h), alerts-over-time chart, top rules, top devices, live feed
3. **Devices** — list with status (online/offline), last seen, risk score; **Device detail**: info, recent alerts, live process list snapshot, action buttons (Lock / Kill / Quarantine)
4. **Alerts** — triage queue, filters, status workflow, notes, linked events, MITRE tags
5. **Events explorer** — filter by device/category/action/time/text, CSV export
6. **Timeline** — per-device forensic timeline (chronological, colour by category), jump from an alert to ±15 min around it
7. **Rules** — list, enable/disable, edit YAML with validation, test rule against recent events
8. **Settings** — notification channels (test buttons), allowlists (USB serials, SSIDs, sensitive paths, work hours), enrollment tokens, users & roles
9. **Reports** — generate incident PDF (alert + timeline + actions taken + hash-chain verification result)

---

## 11. Security of ShadowTrace itself

- HTTPS in deployment (Caddy/NGINX reverse proxy or the hosting platform's TLS).
- Device API keys and user passwords stored hashed (argon2); enrollment tokens single-use + expiring.
- RBAC: only `admin`/`analyst` can issue commands; every command audited.
- Agent config + quarantine in `C:\ProgramData\ShadowTrace` with ACLs restricted to SYSTEM/Administrators.
- Input validation on all ingest (size limits, schema), rate limiting on ingest and login.
- Never collect passwords, keystrokes or page content — only metadata.
- **Privacy & consent:** browsing and activity monitoring must be disclosed to users (login banner / acceptable-use policy). Include this in the report — it's an ethics point examiners like.

---

## 12. Phased roadmap

Each phase ends with something demoable. Weeks are indicative — adjust to your submission date.

| Phase | Weeks | Deliverables |
|---|---|---|
| **0. Setup** | 0.5 | Repo skeleton, `.gitignore`, Python venvs, MongoDB running, ruff/pytest/CI, cross-platform collector interface, Telegram bot created |
| **1. Core pipeline** | 1.5 | Event schema; server ingest API + device enrollment + heartbeat; agent supervisor, SQLite buffer, uploader; **process collector** end-to-end; events visible in Mongo |
| **2. Collectors** | 2 | File, USB, failed-login (Event Log), Wi-Fi/network, browser history collectors; agent config file; install script with audit policy |
| **3. Detection + alerts** | 1.5 | Rule engine (single + threshold + intel), starter rule pack, threat-intel feed jobs, Telegram + email dispatcher with dedup/rate limit |
| **4. Dashboard** | 2 | Vite scaffold, auth, Overview, Devices, Alerts, Events, Timeline, Settings, live WebSocket feed |
| **5. Response** | 1 | Command queue, lock/kill/quarantine in agent, dashboard buttons, Telegram inline buttons, auto-response from rules, audit log |
| **6. Forensics & reports** | 1 | Hash chain + verify, incident PDF, CSV export, rules editor page |
| **7. Hardening & packaging** | 1 | PyInstaller exe + installer, offline-agent alert, performance test (CPU/RAM), security review, retention TTL |
| **8. Testing & demo** | 1 | Unit + integration tests, simulation scripts, demo playbook, screenshots, project report & viva prep |
| *9. Linux agent (optional)* | 2–3 | `collectors/linux/`, systemd unit, `.deb` package, Linux-tagged rules |
| *10. macOS agent (optional)* | 3–4 | `collectors/macos/`, launchd plist, `.pkg`, TCC permission guide |

**Total ≈ 11–12 weeks** for the Windows product with a 4-person team; phases 2 and 4 can run in parallel (agent pair + dashboard pair) to cut ~3 weeks. Phases 9–10 add Linux/macOS without changing the server, dashboard or Windows code.

---

## 12a. Cross-platform design

Every collector emits the **same OS-neutral event** — a failed login is `category: auth, action: logon_failed` whether it came from Windows Event 4625, Linux `journalctl` or the macOS unified log. Only the agent knows which OS it runs on; the server stores `devices.os` and rules may add `platform: windows|linux|macos` when they only make sense on one OS.

At startup the agent detects the OS and loads `common/` collectors plus the matching OS folder. Each collector declares the platforms it supports, so adding Linux means filling in `collectors/linux/` — nothing else changes.

| Monitor | Windows (phase 2) | Linux (phase 9) | macOS (phase 10) |
|---|---|---|---|
| Processes | `psutil` | `psutil` | `psutil` |
| File changes | `watchdog` | `watchdog` | `watchdog` |
| Network connections | `psutil` | `psutil` | `psutil` (root) |
| Browser history | SQLite files | same, Linux paths | same + Safari (Full Disk Access) |
| Failed logins | Event Log 4625 | `journalctl` / `auth.log` (sshd, sudo, login) | unified log (`log stream`) |
| USB | WMI | `pyudev` | IOKit / `diskutil` |
| Wi-Fi | `netsh wlan` | `nmcli` | CoreWLAN (Location permission) |
| Binary signing | Authenticode | hash + package ownership (`dpkg -S`/`rpm -qf`) | `codesign` / `spctl` |
| Lock screen | `LockWorkStation` | `loginctl lock-session` | `pmset displaysleepnow` |
| File-read auditing | audit policy (4663) | `auditd` | limited (Endpoint Security needs Apple entitlement) |
| Background run | Scheduled Task | systemd | launchd |
| Packaging | PyInstaller `.exe` | `.deb` / `.rpm` | `.pkg` (notarisation needs Apple Developer account) |

Suggested team split (4 members):
- **Agent A** — process, file, USB collectors + response actions
- **Agent B** — login, network/Wi-Fi, browser collectors + installer/packaging
- **Backend** — API, DB, rule engine, alerts, forensics
- **Frontend** — dashboard, reports UI, demo playbook

---

## 13. Testing & demo playbook (safe simulations)

| Scenario | How to trigger safely | Expected result |
|---|---|---|
| Brute force | `scripts/simulate/failed_logins.ps1` — 6× `net use \\localhost\IPC$ /user:fakeuser wrongpw` | ST-AUTH-001 high alert → Telegram → auto-lock |
| Unknown USB | Plug in a pen drive not on allowlist | USB alert with serial |
| Data exfil to USB | Copy 100 dummy files to the pen drive | Bulk-copy alert |
| Suspicious executable | Copy a harmless unsigned exe to `%TEMP%` and run it | Exec-from-temp alert, kill from dashboard |
| Malicious file | Drop the **EICAR** test string file in Downloads | Known-bad hash alert, quarantine |
| Encoded PowerShell | `powershell -enc <base64 of "Write-Host hi">` | LOLBin/encoded command alert |
| Unsafe browsing | Visit `testsafebrowsing.appspot.com` test pages / a domain added to the local test blocklist | Unsafe URL alert |
| Open Wi-Fi | Connect to a phone hotspot with no password | Open-network alert |
| Mass deletion | Script creates and deletes 100 files in a watched test folder | Ransomware-like behaviour alert |
| Log tampering | `wevtutil cl Security` on a test VM | Critical alert (Event 1102) |
| Agent tampering | Kill the agent process | Agent-offline alert after 2 min |
| Forensics | Edit one event in Compass, click "Verify integrity" | Chain break detected at that event |

Run destructive scenarios (log clearing, admin creation) **only on a test VM** (VirtualBox/Hyper-V Windows image).

Metrics to report: detection rate per scenario, alert latency (event → Telegram), agent CPU/RAM, false-positive count over a normal day of use.

---

## 14. Deployment options

- **Lab / LAN demo (default):** one laptop runs MongoDB + server + dashboard; other PCs run the agent pointing at `https://<laptop-ip>:8000`. Mirrors the cyber-café/college-lab use case.
- **Cloud demo:** MongoDB Atlas (free) + Render/Railway (FastAPI) + Vercel/Netlify (dashboard). Agents anywhere on the internet.

---

## 15. Documentation deliverables

- `README.md` — quickstart (server, dashboard, agent install)
- `docs/architecture.md` — diagrams from this plan
- `docs/rules.md` — rule syntax + rule catalogue with MITRE mapping
- `docs/user-guide.md` — dashboard walkthrough with screenshots
- Final project report chapters map to the deck: Intro, Problem, Objectives, Literature, Existing vs Proposed, Design, Implementation, Testing/Results, Advantages/Limitations, Applications, Future work

## 16. Future work (for the report)

Linux/macOS agents (if phases 9–10 aren't completed), Sysmon/ETW integration for richer telemetry, ML anomaly detection on user behaviour, network isolation action, YARA scanning, Sigma rule import, multi-tenant support for MSPs.
