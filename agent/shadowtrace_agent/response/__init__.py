"""Allowlisted response execution and a crash-safe local result journal."""

import hashlib
import json
import logging
import ntpath
import os
import sqlite3
import threading
from datetime import UTC, datetime
from pathlib import Path, PureWindowsPath

import psutil
from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, ValidationError

from shadowtrace_agent.config import ResponseConfig
from shadowtrace_agent.osinfo import current_os
from shadowtrace_agent.response.windows import WindowsProcess, lock_workstation
from shadowtrace_agent.schema import Category, Emit

log = logging.getLogger(__name__)
PROTECTED_NAMES = {
    "system",
    "registry",
    "memory compression",
    "smss.exe",
    "csrss.exe",
    "lsass.exe",
    "lsaiso.exe",
    "wininit.exe",
    "winlogon.exe",
    "services.exe",
    "svchost.exe",
    "shadowtrace-agent.exe",
}


class Envelope(BaseModel):
    model_config = ConfigDict(extra="forbid")
    command_id: str = Field(pattern=r"^cmd_[a-f0-9]{32}$")
    device_id: str
    action: str = Field(max_length=64)
    params: dict
    created_at: AwareDatetime
    expires_at: AwareDatetime


class KillTarget(BaseModel):
    model_config = ConfigDict(extra="forbid")
    pid: int = Field(strict=True, gt=4)
    exe: str = Field(min_length=1, max_length=32768)
    create_time: AwareDatetime


class Rejected(ValueError):
    pass


class Responder:
    def __init__(
        self,
        path: Path,
        device_id: str,
        config: ResponseConfig,
        emit: Emit,
        stop: threading.Event | None = None,
    ):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.device_id, self.config, self.emit, self.stop = device_id, config, emit, stop
        self._lock = threading.RLock()
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS commands (id TEXT PRIMARY KEY, fingerprint TEXT NOT NULL, "
            "result TEXT, acknowledged INTEGER NOT NULL DEFAULT 0)"
        )
        # An interrupted action has an uncertain outcome. Never execute it again on restart.
        for (command_id,) in self.db.execute("SELECT id FROM commands WHERE result IS NULL"):
            self._save_result(
                command_id, "unknown", "Agent stopped before saving the action result"
            )
        self.db.commit()

    def _save_result(self, command_id: str, status: str, detail: str) -> dict:
        result = {
            "command_id": command_id,
            "status": status,
            "detail": detail,
            "finished_at": datetime.now(UTC).isoformat(),
        }
        self.db.execute(
            "UPDATE commands SET result=?, acknowledged=0 WHERE id=?",
            (json.dumps(result), command_id),
        )
        self.db.commit()
        return result

    def pending_results(self) -> list[dict]:
        with self._lock:
            return [
                json.loads(row[0])
                for row in self.db.execute(
                    "SELECT result FROM commands WHERE acknowledged=0 "
                    "AND result IS NOT NULL LIMIT 100"
                )
            ]

    def acknowledge(self, ids: list[str]) -> None:
        with self._lock, self.db:
            self.db.executemany(
                "UPDATE commands SET acknowledged=1 WHERE id=?", [(i,) for i in ids]
            )

    def handle(self, commands: list[dict]) -> None:
        for raw in commands:
            if self.stop and self.stop.is_set():
                return
            with self._lock:
                self._handle_one(raw)

    def _handle_one(self, raw: dict) -> None:
        try:
            command = Envelope.model_validate(raw)
        except ValidationError:
            log.warning("Ignoring malformed response command")
            return
        fingerprint = hashlib.sha256(command.model_dump_json().encode()).hexdigest()
        row = self.db.execute(
            "SELECT fingerprint FROM commands WHERE id=?", (command.command_id,)
        ).fetchone()
        if row:
            if row[0] != fingerprint:
                log.error("Command identity reused with different contents")
            # Even acknowledged results can be re-sent when a delivery was delayed in transit.
            with self.db:
                self.db.execute(
                    "UPDATE commands SET acknowledged=0 WHERE id=?", (command.command_id,)
                )
            return
        with self.db:
            self.db.execute(
                "INSERT INTO commands(id, fingerprint) VALUES (?, ?)",
                (command.command_id, fingerprint),
            )
        try:
            detail = self._execute(command)
            status = "succeeded"
        except (Rejected, ValidationError) as exc:
            status, detail = (
                "rejected",
                str(exc) if isinstance(exc, Rejected) else "Invalid parameters",
            )
        except TimeoutError:
            status, detail = "unknown", "Action requested but completion could not be confirmed"
        except Exception as exc:
            # No arbitrary exception strings (paths or command contents) in result messages.
            log.warning("Response action failed (%s)", type(exc).__name__)
            status, detail = "failed", f"Action failed: {type(exc).__name__}"
        result = self._save_result(command.command_id, status, detail)
        self.emit(Category.AGENT, "command_result", {**result, "action": command.action})

    def _execute(self, command: Envelope) -> str:
        now = datetime.now(UTC)
        if command.device_id != self.device_id:
            raise Rejected("Command belongs to a different device")
        if not self.config.enabled or command.action not in self.config.allowed_actions:
            raise Rejected("Response action is disabled by local configuration")
        if current_os() != "windows":
            raise Rejected("Responses are supported only on Windows")
        if command.expires_at <= now or (command.created_at - now).total_seconds() > 5:
            raise Rejected("Command expired or the endpoint clock is out of sync")
        if not 0 < (command.expires_at - command.created_at).total_seconds() <= 900:
            raise Rejected("Invalid command lifetime")
        if command.action == "lock_workstation":
            if command.params:
                raise Rejected("Lock does not accept parameters")
            lock_workstation()
            # Windows accepts the request asynchronously; it does not confirm the final lock state.
            return "Windows accepted the workstation lock request"
        if command.action != "kill_process":
            raise Rejected("Unsupported response action")
        target = KillTarget.model_validate(command.params)
        protected_pids = {os.getpid(), *(p.pid for p in psutil.Process().parents())}
        if target.pid in protected_pids:
            raise Rejected("Cannot terminate the agent or its ancestors")
        if not PureWindowsPath(target.exe).is_absolute():
            raise Rejected("Executable path must be absolute")
        with WindowsProcess(target.pid) as process:
            exe, created, critical = process.identity()
            if critical or ntpath.basename(exe).lower() in PROTECTED_NAMES:
                raise Rejected("Cannot terminate a protected Windows process")
            if ntpath.normcase(ntpath.normpath(exe)) != ntpath.normcase(
                ntpath.normpath(target.exe)
            ):
                raise Rejected("Process executable no longer matches")
            if abs(created - target.create_time.timestamp()) > 0.0011:
                raise Rejected("Process start time no longer matches (PID may have been reused)")
            process.terminate()
        return "Process termination confirmed"

    def close(self) -> None:
        with self._lock:
            self.db.close()
