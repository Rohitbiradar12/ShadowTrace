import os
import sqlite3
import time
from datetime import UTC, datetime

from shadowtrace_agent.collectors.base import CollectorContext
from shadowtrace_agent.collectors.common.browser import (
    WEBKIT_EPOCH,
    BrowserCollector,
    BrowserRoot,
    describe_url,
)

VISIT_TIME = datetime(2026, 10, 28, 12, 0, tzinfo=UTC)


def webkit(dt: datetime) -> int:
    return int((dt - WEBKIT_EPOCH).total_seconds() * 1_000_000)


class Capture:
    def __init__(self) -> None:
        self.events: list[dict] = []

    def __call__(self, category, action, data=None, user=None, ts=None) -> None:
        self.events.append({"action": action, "ts": ts, **(data or {})})


def make_history(tmp_path):
    profile = tmp_path / "User Data" / "Default"
    profile.mkdir(parents=True)
    db = profile / "History"
    conn = sqlite3.connect(db)
    conn.executescript(
        """
        CREATE TABLE urls(id INTEGER PRIMARY KEY, url TEXT, title TEXT);
        CREATE TABLE visits(id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER);
        CREATE TABLE downloads(id INTEGER PRIMARY KEY, target_path TEXT, tab_url TEXT,
            start_time INTEGER, total_bytes INTEGER, mime_type TEXT, danger_type INTEGER,
            state INTEGER);
        CREATE TABLE downloads_url_chains(id INTEGER, chain_index INTEGER, url TEXT);
        INSERT INTO urls VALUES (1, 'https://old-site.example/', 'Old');
        INSERT INTO visits VALUES (1, 1, 0);
        """
    )
    conn.commit()
    return db, conn


def touch(db) -> None:
    # Make sure the collector sees a new modification time even on coarse filesystems.
    stamp = time.time() + 1
    os.utime(db, (stamp, stamp))


def make_collector(tmp_path, capture):
    return BrowserCollector(
        BrowserCollector.Options(),
        capture,
        CollectorContext(tmp_path / "agent-data"),
        roots=[BrowserRoot("chrome", tmp_path / "User Data", "chromium")],
    )


def test_existing_history_is_skipped_then_new_visits_reported(tmp_path):
    db, conn = make_history(tmp_path)
    capture = Capture()
    collector = make_collector(tmp_path, capture)

    collector.poll()
    assert capture.events == []

    conn.executemany(
        "INSERT INTO urls VALUES (?, ?, ?)",
        [(2, "https://Phish.Example.COM/login", "Login"), (3, "chrome://settings", "Settings")],
    )
    conn.executemany(
        "INSERT INTO visits VALUES (?, ?, ?)",
        [(2, 2, webkit(VISIT_TIME)), (3, 3, webkit(VISIT_TIME))],
    )
    conn.commit()
    touch(db)
    collector.poll()

    assert len(capture.events) == 1  # browser-internal pages are not reported
    visit = capture.events[0]
    assert visit["action"] == "url_visited"
    assert visit["domain"] == "phish.example.com"
    assert visit["ts"] == VISIT_TIME


def test_downloads_reported_only_once_complete_and_in_order(tmp_path):
    db, conn = make_history(tmp_path)
    capture = Capture()
    collector = make_collector(tmp_path, capture)
    collector.poll()

    conn.executemany(
        "INSERT INTO downloads VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        [
            (1, r"C:\Users\demo\Downloads\big.iso", "https://a.example/", 0, 9, "x", 0, 0),
            (2, r"C:\Users\demo\Downloads\tool.exe", "https://b.example/", 0, 5, "x", 0, 1),
        ],
    )
    conn.execute("INSERT INTO downloads_url_chains VALUES (2, 0, 'http://203.0.113.9/tool.exe')")
    conn.commit()
    touch(db)
    collector.poll()
    assert capture.events == []  # download 1 still in progress, so 2 waits behind it

    conn.execute("UPDATE downloads SET state = 1 WHERE id = 1")
    conn.commit()
    touch(db)
    collector.poll()

    assert [e["file_name"] for e in capture.events] == ["big.iso", "tool.exe"]
    tool = capture.events[1]
    assert tool["ext"] == ".exe" and tool["host_is_ip"] is True


def test_progress_survives_agent_restart(tmp_path):
    db, conn = make_history(tmp_path)
    first = Capture()
    make_collector(tmp_path, first).poll()
    conn.execute("INSERT INTO urls VALUES (2, 'https://news.example/', 'News')")
    conn.execute("INSERT INTO visits VALUES (2, 2, ?)", (webkit(VISIT_TIME),))
    conn.commit()
    touch(db)
    collector = make_collector(tmp_path, first)
    collector.poll()
    assert len(first.events) == 1

    second = Capture()
    make_collector(tmp_path, second).poll()  # a fresh agent process
    assert second.events == []


def test_describe_url():
    assert describe_url("https://EXAMPLE.com/a")["domain"] == "example.com"
    assert describe_url("http://198.51.100.7:8080/x")["host_is_ip"] is True
    assert describe_url("edge://settings") is None


def test_backlog_drains_without_another_browser_write(tmp_path):
    db, conn = make_history(tmp_path)
    capture = Capture()
    collector = make_collector(tmp_path, capture)
    collector.options.max_rows_per_poll = 10
    try:
        collector.poll()
        for n in range(2, 27):
            conn.execute("INSERT INTO urls VALUES (?, ?, ?)", (n, "https://demo.example", "Demo"))
            conn.execute("INSERT INTO visits VALUES (?, ?, ?)", (n, n, webkit(VISIT_TIME)))
        conn.commit()
        touch(db)
        for _ in range(3):
            collector.poll()
        assert len(capture.events) == 25
        collector.poll()
        assert len(capture.events) == 25
    finally:
        conn.close()


def test_wal_only_changes_are_reported(tmp_path):
    db, conn = make_history(tmp_path)
    capture = Capture()
    collector = make_collector(tmp_path, capture)
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        collector.poll()
        before = db.stat().st_mtime_ns
        conn.execute("INSERT INTO urls VALUES (2, 'https://wal.example/', 'WAL')")
        conn.execute("INSERT INTO visits VALUES (2, 2, ?)", (webkit(VISIT_TIME),))
        conn.commit()
        assert db.stat().st_mtime_ns == before
        collector.poll()
        assert len(capture.events) == 1
    finally:
        conn.close()
