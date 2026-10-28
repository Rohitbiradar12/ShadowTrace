"""Process start/stop monitoring by polling (works on Windows, Linux and macOS).

Each poll takes a cheap whole-system snapshot of (pid, ppid, name, create_time); details
(executable, command line, user, hash) are fetched only for processes new since the last
poll. Processes that start and exit between two polls are missed — a known limit of polling
that ETW (Windows) or auditd (Linux) could close later.
"""

import hashlib
import logging
import os
import threading
from collections import OrderedDict
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import psutil
from pydantic import Field

from shadowtrace_agent.collectors.base import Collector, CollectorContext, CollectorOptions
from shadowtrace_agent.osinfo import current_os, is_removable_path
from shadowtrace_agent.schema import Category, utc_iso

log = logging.getLogger(__name__)

ProcKey = tuple[int, float]  # (pid, create_time) — pid alone is reused by the OS
# Snapshot rows: (pid, ppid, name, create_time)
ProcRow = tuple[int, int, str | None, float]


def _psutil_list_processes() -> list[ProcRow]:
    # On Linux/macOS these attributes come from one cheap read per process.
    return [
        (p.pid, p.info["ppid"] or 0, p.info["name"], p.info["create_time"] or 0.0)
        for p in psutil.process_iter(["ppid", "name", "create_time"])
    ]


def default_lister() -> Callable[[], list[ProcRow]]:
    if current_os() == "windows":
        from shadowtrace_agent.collectors.windows.proclist import list_processes

        return list_processes
    return _psutil_list_processes


@dataclass
class ProcInfo:
    pid: int
    ppid: int
    name: str | None
    create_time: float
    exe: str | None = None
    cmdline: list[str] | None = None
    username: str | None = None


def diff_keys(old: Iterable[ProcKey], new: Iterable[ProcKey]) -> tuple[set[ProcKey], set[ProcKey]]:
    """Return (started, stopped) process keys between two snapshots."""
    old_set, new_set = set(old), set(new)
    return new_set - old_set, old_set - new_set


class HashCache:
    """SHA-256 of executables, cached by (size, mtime) so each binary is hashed once."""

    def __init__(self, max_size_bytes: int, max_entries: int = 2048) -> None:
        self._max_size = max_size_bytes
        self._max_entries = max_entries
        self._entries: OrderedDict[str, tuple[int, int, str]] = OrderedDict()

    def sha256(self, path: str) -> tuple[str | None, int | None]:
        try:
            st = os.stat(path)
        except OSError:
            return None, None
        cached = self._entries.get(path)
        if cached and cached[:2] == (st.st_size, st.st_mtime_ns):
            self._entries.move_to_end(path)
            return cached[2], st.st_size
        if st.st_size > self._max_size:
            return None, st.st_size
        digest = hashlib.sha256()
        try:
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(1024 * 1024), b""):
                    digest.update(chunk)
        except OSError:
            return None, st.st_size
        self._entries[path] = (st.st_size, st.st_mtime_ns, digest.hexdigest())
        if len(self._entries) > self._max_entries:
            self._entries.popitem(last=False)
        return digest.hexdigest(), st.st_size


class ProcessCollector(Collector):
    name = "process"

    class Options(CollectorOptions):
        poll_interval_seconds: float = Field(1.0, ge=0.2)
        hash_executables: bool = True
        max_hash_size_mb: int = Field(200, ge=1)
        emit_exits: bool = True

    options: Options

    def __init__(
        self,
        options: Options,
        emit,
        context: CollectorContext | None = None,
        lister: Callable[[], list[ProcRow]] | None = None,
    ) -> None:
        super().__init__(options, emit, context)
        self._list = lister or default_lister()
        self._hashes = HashCache(options.max_hash_size_mb * 1024 * 1024)

    def run(self, stop: threading.Event) -> None:
        known = self.baseline()
        log.info("Process monitor started (%d running processes)", len(known))
        while not stop.wait(self.options.poll_interval_seconds):
            known = self.poll(known)

    def snapshot(self) -> dict[ProcKey, ProcInfo]:
        return {
            (pid, ctime): ProcInfo(pid, ppid, name, ctime)
            for pid, ppid, name, ctime in self._list()
        }

    def baseline(self) -> dict[ProcKey, ProcInfo]:
        """Processes already running at startup; not reported as new."""
        return self.snapshot()

    def poll(self, known: dict[ProcKey, ProcInfo]) -> dict[ProcKey, ProcInfo]:
        snap = self.snapshot()
        started, stopped = diff_keys(known, snap)
        current = {key: info for key, info in known.items() if key not in stopped}

        for key in sorted(started, key=lambda k: k[1]):
            info = snap[key]
            self._add_details(info)
            current[key] = info
            self.emit(
                Category.PROCESS,
                "process_started",
                self._start_data(info, current),
                user=info.username,
                ts=datetime.fromtimestamp(info.create_time, UTC) if info.create_time else None,
            )

        if self.options.emit_exits:
            now = datetime.now(UTC).timestamp()
            for key in stopped:
                info = known[key]
                runtime = round(now - info.create_time, 1) if info.create_time else None
                self.emit(
                    Category.PROCESS,
                    "process_stopped",
                    {
                        "pid": info.pid,
                        "name": info.name,
                        "exe": info.exe,
                        "runtime_seconds": runtime,
                    },
                    user=info.username,
                )
        return current

    @staticmethod
    def _add_details(info: ProcInfo) -> None:
        """Fill exe/cmdline/username. A process that already exited keeps its snapshot data."""
        try:
            proc = psutil.Process(info.pid)
            # Guard against the pid having been reused since the snapshot.
            if info.create_time and abs(proc.create_time() - info.create_time) > 1:
                return
            with proc.oneshot():
                details = proc.as_dict(["exe", "cmdline", "username"], ad_value=None)
        except psutil.Error:
            return
        info.exe, info.cmdline, info.username = (
            details["exe"],
            details["cmdline"],
            details["username"],
        )

    def _start_data(self, info: ProcInfo, procs: dict[ProcKey, ProcInfo]) -> dict[str, Any]:
        data: dict[str, Any] = {
            "pid": info.pid,
            "ppid": info.ppid,
            "name": info.name,
            "exe": info.exe,
            # One string so detection rules can search it (e.g. "powershell -enc").
            "command_line": " ".join(info.cmdline) if info.cmdline else None,
            "create_time": utc_iso(datetime.fromtimestamp(info.create_time, UTC))
            if info.create_time
            else None,
            "exe_on_removable": is_removable_path(info.exe) if info.exe else False,
            "parent": self._parent(info, procs),
        }
        if self.options.hash_executables and info.exe:
            data["sha256"], data["file_size"] = self._hashes.sha256(info.exe)
        return data

    @staticmethod
    def _parent(info: ProcInfo, procs: dict[ProcKey, ProcInfo]) -> dict[str, Any] | None:
        if not info.ppid:
            return None
        # A parent must have started before its child; otherwise the ppid was reused.
        parent = next(
            (
                p
                for (pid, ctime), p in procs.items()
                if pid == info.ppid and ctime <= info.create_time
            ),
            None,
        )
        return {
            "pid": info.ppid,
            "name": parent.name if parent else None,
            "exe": parent.exe if parent else None,
        }
