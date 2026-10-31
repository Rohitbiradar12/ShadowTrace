# ShadowTrace

Endpoint monitoring for Windows: **monitor → detect → alert → investigate → respond**.

A small Python agent watches each computer and sends activity to a central server. The server
checks it against detection rules, raises alerts, keeps a tamper-evident record of the
evidence, and gives you a web dashboard to investigate and respond.

## Features

- **8 collectors**: processes, files, USB devices, browser history, Windows logons (security log), network, Wi-Fi and Microsoft Defender
- **27 detection rules** written in YAML, plus local indicator lists
- **Web dashboard** with dark/light themes and a command palette (**Ctrl+K**)
- **Forensic hash chain** that shows whether stored evidence was changed or deleted
- **Response actions**: lock a workstation or stop a process (endpoint opt-in required)
- **Notifications** by Telegram and email, with retries
- **Roles**: viewer, analyst and administrator

## Requirements

- Windows 10 or 11
- Python 3.12+
- MongoDB 8, running locally

## Quick start

### 1. Start the server

```powershell
cd server
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
Copy-Item .env.example .env
.\.venv\Scripts\python.exe -m app.cli create-user admin --role admin
.\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Open **http://127.0.0.1:8000** and sign in as `admin`. You choose the password when creating
the account; there is no default login. Forgot it? Run `python -m app.cli reset-password admin`.

### 2. Connect a computer (agent)

Create an enrollment token in the dashboard under **Settings → Endpoint enrollment**, then:

```powershell
cd agent
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
Copy-Item config.example.yaml config.local.yaml
.\.venv\Scripts\python.exe -m shadowtrace_agent -c config.local.yaml enroll --token YOUR_TOKEN
.\.venv\Scripts\python.exe -m shadowtrace_agent -c config.local.yaml run
```

Edit `config.local.yaml` to set the server address and the folders to watch.

> Tell people when their computer is monitored. Browser history and command lines can
> contain personal information.

## Try it with demo data

With the server running, create another enrollment token, then from the repository root:

```powershell
.\server\.venv\Scripts\python.exe scripts/demo_pipeline.py
```

It adds a clearly labelled demo computer with sample events and creates a few alerts. Nothing
is actually done on your machine.

## Accounts and roles

| Role | Can do |
|---|---|
| Viewer | View alerts, events, reports and rules |
| Analyst | Everything a viewer can, plus triage alerts and send responses |
| Administrator | Everything, plus manage accounts, enrollment and settings |

Administrators create accounts in **Settings → Operator accounts**. There is no public sign-up.

## Run the tests

```powershell
# In server/ or agent/
.\.venv\Scripts\python.exe -m pytest -q

# Full browser walkthrough, from the repository root
.\server\.venv\Scripts\python.exe scripts/browser_smoke.py
```

## Documentation

| Guide | What's inside |
|---|---|
| [User guide](docs/user-guide.md) | Using each dashboard page |
| [Operations guide](docs/operations.md) | Installation, deployment, notifications, responses and CLI |
| [Detection rules](docs/rules.md) | Writing and validating rules |
| [Architecture](docs/architecture.md) | How the pieces fit together |
| [Demo playbook](docs/demo.md) | Step-by-step presentation |
| [Project report](docs/project-report.md) · [Plan](docs/PLAN.md) | Design decisions and roadmap |

## Good to know

- Run the server with **one worker** (the default command above). Multiple workers aren't supported yet.
- Restart the server after changing `.env`, rule files or indicator lists.
- Notifications and response actions are **off by default**. See the operations guide to enable them.
- The bad-domain and other indicators in `intel/lists.yaml` are **demo samples**, not a real threat feed.
