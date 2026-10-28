"""Outbound connections and listening ports, per process (psutil; all platforms).

Each (process, remote address, port) is reported once, then again only after
``repeat_after_minutes``, so busy browsers do not flood the server. Connection attempts that
never complete (SYN_SENT) are included: a process repeatedly trying an unreachable address
is itself worth seeing. Loopback traffic is skipped.
"""

import ipaddress
import logging
import socket
import threading
import time
from typing import Any

import psutil
from pydantic import Field

from shadowtrace_agent.collectors.base import Collector, CollectorContext, CollectorOptions
from shadowtrace_agent.schema import Category

log = logging.getLogger(__name__)

TRACKED_STATES = {psutil.CONN_ESTABLISHED, psutil.CONN_SYN_SENT}


def classify_ip(ip: str) -> tuple[bool, bool]:
    """Return (is_loopback, is_private) for an address string."""
    try:
        addr = ipaddress.ip_address(ip.split("%")[0])  # strip IPv6 zone id
    except ValueError:
        return False, False
    if getattr(addr, "ipv4_mapped", None):
        addr = addr.ipv4_mapped
    private = (addr.is_private or addr.is_link_local) and not addr.is_loopback
    return addr.is_loopback, private


class NetworkCollector(Collector):
    name = "network"

    class Options(CollectorOptions):
        poll_interval_seconds: float = Field(5.0, ge=1.0)
        include_private: bool = True
        report_listening: bool = True
        repeat_after_minutes: float = Field(60.0, ge=1.0)

    options: Options

    def __init__(self, options: Options, emit, context: CollectorContext | None = None) -> None:
        super().__init__(options, emit, context)
        self._seen: dict[tuple, float] = {}

    def run(self, stop: threading.Event) -> None:
        # Whatever is already open at startup is recorded as seen, not reported.
        self.poll(report=False)
        log.info("Network monitor started (%d known connections)", len(self._seen))
        while not stop.wait(self.options.poll_interval_seconds):
            self.poll()

    def poll(self, report: bool = True) -> None:
        try:
            connections = psutil.net_connections(kind="tcp")
        except (psutil.AccessDenied, OSError) as exc:
            log.warning("Cannot list connections: %s", exc)
            return

        now = time.monotonic()
        repeat_after = self.options.repeat_after_minutes * 60
        self._seen = {k: t for k, t in self._seen.items() if now - t < repeat_after}
        names: dict[int, tuple[str | None, str | None]] = {}

        for conn in connections:
            if conn.status == psutil.CONN_LISTEN and self.options.report_listening:
                key = ("listen", conn.pid, conn.laddr.ip, conn.laddr.port)
                action = "port_listening"
            elif conn.status in TRACKED_STATES and conn.raddr:
                loopback, private = classify_ip(conn.raddr.ip)
                if loopback or (private and not self.options.include_private):
                    continue
                key = ("conn", conn.pid, conn.raddr.ip, conn.raddr.port)
                action = "connection_opened"
            else:
                continue
            if key in self._seen:
                continue
            self._seen[key] = now
            if report:
                self.emit(Category.NETWORK, action, self._describe(conn, names))

    @staticmethod
    def _describe(conn, names: dict[int, tuple[str | None, str | None]]) -> dict[str, Any]:
        if conn.pid not in names:
            names[conn.pid] = _process_identity(conn.pid)
        process, exe = names[conn.pid]
        data: dict[str, Any] = {
            "pid": conn.pid,
            "process": process,
            "exe": exe,
            "family": "ipv6" if conn.family == socket.AF_INET6 else "ipv4",
            "local_ip": conn.laddr.ip if conn.laddr else None,
            "local_port": conn.laddr.port if conn.laddr else None,
            "status": conn.status.lower(),
        }
        if conn.raddr:
            data["remote_ip"] = conn.raddr.ip
            data["remote_port"] = conn.raddr.port
            data["remote_private"] = classify_ip(conn.raddr.ip)[1]
        return data


def _process_identity(pid: int | None) -> tuple[str | None, str | None]:
    if not pid:
        return None, None
    try:
        proc = psutil.Process(pid)
        name = proc.name()
    except psutil.Error:
        return None, None
    try:
        exe = proc.exe()
    except psutil.Error:
        exe = None
    return name, exe
