import logging
import os
import platform
import socket
import sys
import threading
import time
from datetime import datetime
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any

import psutil

from shadowtrace_agent import __version__
from shadowtrace_agent.collectors import build_collectors
from shadowtrace_agent.collectors.base import Collector, CollectorContext
from shadowtrace_agent.config import AgentConfig
from shadowtrace_agent.osinfo import current_os
from shadowtrace_agent.response import Responder
from shadowtrace_agent.schema import Category, new_event
from shadowtrace_agent.state import EnrollmentState, load_state, save_state
from shadowtrace_agent.transport.buffer import EventBuffer
from shadowtrace_agent.transport.client import ServerClient, ServerError
from shadowtrace_agent.transport.loops import Heartbeat, Uploader

log = logging.getLogger(__name__)

MAX_COLLECTOR_BACKOFF_SECONDS = 300.0


def setup_logging(data_dir: Path, level: str) -> None:
    (data_dir / "logs").mkdir(parents=True, exist_ok=True)
    handlers: list[logging.Handler] = [
        RotatingFileHandler(
            data_dir / "logs" / "agent.log", maxBytes=5_000_000, backupCount=3, encoding="utf-8"
        ),
    ]
    if sys.stderr is not None:  # Scheduled installs use pythonw.exe without a console.
        handlers.append(logging.StreamHandler())
    logging.basicConfig(
        level=level.upper(),
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
        handlers=handlers,
        force=True,
    )
    # httpx logs every request at INFO, which would flood the log every few seconds.
    logging.getLogger("httpx").setLevel(logging.WARNING)


def enroll(config: AgentConfig, token: str) -> EnrollmentState:
    client = ServerClient(config.server_url, config.verify_tls)
    try:
        creds = client.enroll(
            token,
            {
                "hostname": socket.gethostname(),
                "os": current_os(),
                "os_version": platform.platform(),
                "agent_version": __version__,
            },
        )
    finally:
        client.close()
    state = EnrollmentState(creds["device_id"], creds["api_key"], config.server_url)
    save_state(config.resolved_data_dir, state)
    return state


class Agent:
    def __init__(self, config: AgentConfig) -> None:
        self.config = config
        self.data_dir = config.resolved_data_dir
        self.stop_event = threading.Event()
        self.buffer: EventBuffer | None = None
        self._started = time.monotonic()
        self._collector_status: dict[str, str] = {}
        self._process = psutil.Process()

    def emit(
        self,
        category: Category,
        action: str,
        data: dict[str, Any] | None = None,
        user: str | None = None,
        ts: datetime | None = None,
    ) -> None:
        assert self.buffer is not None
        self.buffer.put(new_event(category, action, data, user, ts))

    def run(self) -> None:
        state = load_state(self.data_dir)
        if state is None:
            if not self.config.enrollment_token:
                raise SystemExit("Agent is not enrolled. Run the 'enroll' command first.")
            state = enroll(self.config, self.config.enrollment_token)
        log.info("ShadowTrace agent %s starting as %s", __version__, state.device_id)

        self.buffer = EventBuffer(self.data_dir / "buffer.db", self.config.max_buffered_events)
        collectors = build_collectors(
            self.config.collectors, self.emit, context=CollectorContext(self.data_dir)
        )
        responder = Responder(
            self.data_dir / "commands.db",
            state.device_id,
            self.config.responses,
            self.emit,
            self.stop_event,
        )
        self.emit(
            Category.AGENT,
            "agent_started",
            {
                "version": __version__,
                "os": current_os(),
                "pid": os.getpid(),
                "collectors": [c.name for c in collectors],
            },
        )

        upload_client = ServerClient(state.server_url, self.config.verify_tls, state.api_key)
        heartbeat_client = ServerClient(state.server_url, self.config.verify_tls, state.api_key)
        uploader = Uploader(self.buffer, upload_client, self.config.upload)
        heartbeat = Heartbeat(
            heartbeat_client,
            self.config.heartbeat_interval_seconds,
            stats=self.stats,
            uptime=lambda: round(time.monotonic() - self._started, 1),
            on_commands=responder.handle,
            results=responder.pending_results,
            acknowledge=responder.acknowledge,
        )

        threads = [
            threading.Thread(target=self._supervise, args=(c,), name=f"collector-{c.name}")
            for c in collectors
        ]
        threads += [
            threading.Thread(target=uploader.run, args=(self.stop_event,), name="uploader"),
            threading.Thread(target=heartbeat.run, args=(self.stop_event,), name="heartbeat"),
        ]
        for t in threads:
            t.daemon = True
            t.start()

        try:
            # Short waits keep the main thread responsive to Ctrl+C on Windows.
            while not self.stop_event.wait(1.0):
                pass
        except KeyboardInterrupt:
            log.info("Interrupted")
        finally:
            self.stop_event.set()
            for t in threads:
                t.join(timeout=15)
            self.emit(Category.AGENT, "agent_stopped", {"version": __version__})
            try:
                uploader.flush_once()
            except ServerError:
                log.info(
                    "Server unreachable at shutdown; %d events stay buffered", len(self.buffer)
                )
            upload_client.close()
            heartbeat_client.close()
            responder.close()
            self.buffer.close()
            log.info("Agent stopped")

    def stop(self) -> None:
        self.stop_event.set()

    def stats(self) -> dict[str, Any]:
        assert self.buffer is not None
        return {
            "buffered_events": len(self.buffer),
            "dropped_events": self.buffer.dropped,
            "cpu_percent": self._process.cpu_percent(None),
            "memory_mb": round(self._process.memory_info().rss / 1_048_576, 1),
            "collectors": dict(self._collector_status),
        }

    def _supervise(self, collector: Collector) -> None:
        """Run a collector, restarting it with backoff if it crashes."""
        backoff = 5.0
        while not self.stop_event.is_set():
            self._collector_status[collector.name] = "running"
            try:
                collector.run(self.stop_event)
                self._collector_status[collector.name] = "stopped"
                return
            except Exception as exc:
                log.exception("Collector %s crashed; restarting in %.0fs", collector.name, backoff)
                self._collector_status[collector.name] = "error"
                self.emit(
                    Category.AGENT,
                    "collector_error",
                    {"collector": collector.name, "error": repr(exc)},
                )
                self.stop_event.wait(backoff)
                backoff = min(backoff * 2, MAX_COLLECTOR_BACKOFF_SECONDS)
