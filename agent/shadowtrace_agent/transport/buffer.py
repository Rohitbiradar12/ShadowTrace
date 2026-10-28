"""Durable local queue so events survive network outages and agent restarts.

The SQLite AUTOINCREMENT rowid doubles as the event's ``seq``: it only ever grows, so the
server can spot gaps (events dropped here when the buffer was full).
"""

import json
import logging
import sqlite3
import threading
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)


class EventBuffer:
    def __init__(self, path: Path, max_events: int = 100_000) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self._max_events = max_events
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS events "
            "(seq INTEGER PRIMARY KEY AUTOINCREMENT, body TEXT NOT NULL)"
        )
        self._count = self._conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        self.dropped = 0

    def put(self, event: dict[str, Any]) -> int:
        with self._lock:
            cur = self._conn.execute("INSERT INTO events (body) VALUES (?)", (json.dumps(event),))
            self._count += 1
            if self._count > self._max_events:
                self._drop_oldest(self._count - self._max_events)
            return cur.lastrowid

    def peek(self, limit: int) -> list[dict[str, Any]]:
        """Oldest events first, each with its ``seq`` filled in."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT seq, body FROM events ORDER BY seq LIMIT ?", (limit,)
            ).fetchall()
        return [json.loads(body) | {"seq": seq} for seq, body in rows]

    def ack(self, up_to_seq: int) -> None:
        with self._lock:
            cur = self._conn.execute("DELETE FROM events WHERE seq <= ?", (up_to_seq,))
            self._count -= cur.rowcount

    def __len__(self) -> int:
        return self._count

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def _drop_oldest(self, n: int) -> None:
        cur = self._conn.execute(
            "DELETE FROM events WHERE seq IN (SELECT seq FROM events ORDER BY seq LIMIT ?)", (n,)
        )
        self._count -= cur.rowcount
        self.dropped += cur.rowcount
        log.warning("Event buffer full; dropped %d oldest event(s)", cur.rowcount)
