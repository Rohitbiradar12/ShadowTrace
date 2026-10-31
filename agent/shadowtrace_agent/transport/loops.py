import logging
import threading
from collections.abc import Callable
from typing import Any

from shadowtrace_agent import __version__
from shadowtrace_agent.config import UploadConfig
from shadowtrace_agent.transport.buffer import EventBuffer
from shadowtrace_agent.transport.client import AuthError, ServerClient, ServerError

log = logging.getLogger(__name__)

MAX_BACKOFF_SECONDS = 60.0


class Uploader:
    """Drains the local buffer to the server in batches, backing off while it is unreachable."""

    def __init__(self, buffer: EventBuffer, client: ServerClient, config: UploadConfig) -> None:
        self._buffer = buffer
        self._client = client
        self._config = config

    def flush_once(self) -> int:
        """Upload one batch. Returns events sent; raises ServerError on failure."""
        batch = self._buffer.peek(self._config.batch_size)
        if not batch:
            return 0
        self._client.upload(batch)
        self._buffer.ack(batch[-1]["seq"])
        return len(batch)

    def run(self, stop: threading.Event) -> None:
        backoff = self._config.interval_seconds
        while not stop.is_set():
            try:
                sent = self.flush_once()
            except AuthError as exc:
                log.error("Server rejected device key; re-enroll this agent (%s)", exc)
                stop.wait(MAX_BACKOFF_SECONDS)
                continue
            except ServerError as exc:
                log.warning("Upload failed, retrying in %.0fs: %s", backoff, exc)
                stop.wait(backoff)
                backoff = min(backoff * 2, MAX_BACKOFF_SECONDS)
                continue
            backoff = self._config.interval_seconds
            # A full batch means more are probably waiting, so loop straight away.
            if sent < self._config.batch_size:
                stop.wait(self._config.interval_seconds)


class Heartbeat:
    """Tells the server the agent is alive; the response will carry response commands."""

    def __init__(
        self,
        client: ServerClient,
        interval_seconds: float,
        stats: Callable[[], dict[str, Any]],
        uptime: Callable[[], float],
        on_commands: Callable[[list[dict[str, Any]]], None],
        results: Callable[[], list[dict]] | None = None,
        acknowledge: Callable[[list[str]], None] | None = None,
    ) -> None:
        self._client = client
        self._interval = interval_seconds
        self._stats = stats
        self._uptime = uptime
        self._on_commands = on_commands
        self._results = results or (lambda: [])
        self._acknowledge = acknowledge or (lambda ids: None)

    def beat_once(self) -> None:
        pending = self._results()
        response = self._client.heartbeat(
            {
                "agent_version": __version__,
                "uptime_seconds": self._uptime(),
                "stats": self._stats(),
                "command_results": pending,
            }
        )
        sent_ids = {result["command_id"] for result in pending}
        self._acknowledge([i for i in response.get("acknowledged_results", []) if i in sent_ids])
        if commands := response.get("commands"):
            self._on_commands(commands)

    def run(self, stop: threading.Event) -> None:
        while not stop.is_set():
            try:
                self.beat_once()
            except ServerError as exc:
                log.warning("Heartbeat failed: %s", exc)
            except Exception:
                log.exception("Heartbeat or response handling failed; will retry")
            stop.wait(self._interval)
