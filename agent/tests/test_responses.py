import json
import os
import sys
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from uuid import uuid4

import httpx
import pytest

from shadowtrace_agent import response as module
from shadowtrace_agent.config import ResponseConfig
from shadowtrace_agent.response import Responder
from shadowtrace_agent.transport.client import ServerClient, ServerError
from shadowtrace_agent.transport.loops import Heartbeat

STARTED = datetime(2026, 10, 28, tzinfo=UTC)
EXE = r"C:\Lab\worker.exe"


def command(action="lock_workstation", **changes):
    now = datetime.now(UTC)
    return {
        "command_id": "cmd_" + uuid4().hex,
        "device_id": "dev_test",
        "action": action,
        "created_at": now.isoformat(),
        "expires_at": (now + timedelta(seconds=120)).isoformat(),
        "params": {}
        if action == "lock_workstation"
        else {
            "pid": 424242,
            "exe": EXE,
            "create_time": STARTED.isoformat(),
        },
        **changes,
    }


@pytest.fixture
def effects(monkeypatch):
    state = SimpleNamespace(locks=0, kills=0, identity=(EXE, STARTED.timestamp(), False))

    def lock():
        state.locks += 1

    class Process:
        def __init__(self, pid):
            assert pid == 424242

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def identity(self):
            return state.identity

        def terminate(self):
            state.kills += 1

    monkeypatch.setattr(module, "current_os", lambda: "windows")
    monkeypatch.setattr(module, "lock_workstation", lock)
    monkeypatch.setattr(module, "WindowsProcess", Process)
    return state


@pytest.fixture
def responder(tmp_path, effects):
    runner = Responder(
        tmp_path / "commands.db", "dev_test", ResponseConfig(enabled=True), lambda *a, **k: None
    )
    yield runner
    runner.close()


def test_duplicate_delivery_ack_loss_and_restart_execute_once(tmp_path, effects):
    path, item = tmp_path / "commands.db", command()
    first = Responder(path, "dev_test", ResponseConfig(enabled=True), lambda *a, **k: None)
    first.handle([item, item])
    result = first.pending_results()
    assert effects.locks == 1
    first.close()
    second = Responder(path, "dev_test", ResponseConfig(enabled=True), lambda *a, **k: None)
    try:
        second.handle([item])
        assert second.pending_results() == result
        second.acknowledge([item["command_id"]])
        assert second.pending_results() == []
        second.handle([item])
        assert second.pending_results() == result
        assert effects.locks == 1
    finally:
        second.close()


def test_crash_during_action_is_unknown_and_never_repeated(tmp_path, effects):
    path, item = tmp_path / "commands.db", command()
    runner = Responder(path, "dev_test", ResponseConfig(enabled=True), lambda *a, **k: None)
    runner.db.execute(
        "INSERT INTO commands(id, fingerprint) VALUES (?, 'started')", (item["command_id"],)
    )
    runner.db.commit()
    runner.close()
    runner = Responder(path, "dev_test", ResponseConfig(enabled=True), lambda *a, **k: None)
    try:
        runner.handle([item])
        assert runner.pending_results()[0]["status"] == "unknown"
        assert effects.locks == 0
    finally:
        runner.close()


@pytest.mark.parametrize(
    "change",
    [
        {"device_id": "another"},
        {"action": "shell"},
        {"params": {"run": "calc"}},
        {"expires_at": (datetime.now(UTC) - timedelta(seconds=1)).isoformat()},
        {"created_at": (datetime.now(UTC) + timedelta(minutes=1)).isoformat()},
        {"expires_at": (datetime.now(UTC) + timedelta(hours=1)).isoformat()},
    ],
)
def test_invalid_or_expired_commands_are_rejected(responder, effects, change):
    responder.handle([command(**change)])
    assert responder.pending_results()[0]["status"] == "rejected"
    assert effects.locks == effects.kills == 0


def test_local_opt_in_and_action_allowlist(responder, effects):
    responder.config.enabled = False
    responder.handle([command()])
    responder.config.enabled = True
    responder.config.allowed_actions = ["kill_process"]
    responder.handle([command()])
    assert all(r["status"] == "rejected" for r in responder.pending_results())
    assert effects.locks == 0


@pytest.mark.parametrize(
    "identity",
    [
        (EXE, STARTED.timestamp() + 1, False),
        (r"C:\Other\worker.exe", STARTED.timestamp(), False),
        (EXE, STARTED.timestamp(), True),
        (r"C:\Windows\lsass.exe", STARTED.timestamp(), False),
    ],
)
def test_kill_checks_live_identity_and_protected_processes(responder, effects, identity):
    effects.identity = identity
    responder.handle([command("kill_process")])
    assert responder.pending_results()[0]["status"] == "rejected"
    assert effects.kills == 0


def test_kill_checks_pid_and_rejects_extra_parameters(responder, effects):
    for params in (
        {"pid": os.getpid()},
        {"pid": 4},
        {"shell": "anything"},
        {"exe": "relative.exe"},
    ):
        item = command("kill_process")
        item["params"].update(params)
        responder.handle([item])
    assert all(r["status"] == "rejected" for r in responder.pending_results())
    assert effects.kills == 0


def test_verified_kill_and_lock_success(responder, effects):
    responder.handle([command("kill_process"), command()])
    assert effects.kills == effects.locks == 1
    assert all(r["status"] == "succeeded" for r in responder.pending_results())


def test_action_failure_is_reported_without_exception_contents(responder, effects, monkeypatch):
    def fail():
        raise OSError("private payload")

    monkeypatch.setattr(module, "lock_workstation", fail)
    responder.handle([command()])
    result = responder.pending_results()[0]
    assert result["status"] == "failed"
    assert "private" not in result["detail"]


def test_heartbeat_keeps_results_on_network_failure(responder, effects):
    item = command()
    requests = []

    def transport(request):
        payload = json.loads(request.content)
        requests.append(payload)
        if len(requests) == 1:
            return httpx.Response(200, json={"commands": [item]})
        if len(requests) == 2:
            raise httpx.ConnectError("offline")
        return httpx.Response(200, json={"acknowledged_results": [item["command_id"], "unsent"]})

    client = ServerClient("http://test", transport=httpx.MockTransport(transport))
    heartbeat = Heartbeat(
        client,
        10,
        lambda: {},
        lambda: 1,
        responder.handle,
        responder.pending_results,
        responder.acknowledge,
    )
    try:
        heartbeat.beat_once()
        with pytest.raises(ServerError):
            heartbeat.beat_once()
        assert len(responder.pending_results()) == 1
        heartbeat.beat_once()
        assert responder.pending_results() == []
        assert requests[1]["command_results"] == requests[2]["command_results"]
        assert effects.locks == 1
    finally:
        client.close()


@pytest.mark.skipif(sys.platform != "win32", reason="Windows API")
def test_native_process_identity_is_readable_without_terminating():
    # This is read-only: exercise the ctypes signatures against this test process.
    with module.WindowsProcess(os.getpid()) as process:
        path, started, critical = process.identity()
    # Windows venv python.exe can be a launcher; compare to the actual live image.
    assert os.path.samefile(path, module.psutil.Process().exe())
    assert abs(started - module.psutil.Process().create_time()) < 0.002
    assert not critical
