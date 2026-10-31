"""Browser history and downloads for Chrome, Edge, Brave and Firefox (all platforms).

The browser keeps its history database locked, so each poll copies it and reads only rows
newer than the last one reported. The first time a profile is seen its existing history is
skipped: the agent reports browsing from installation onwards, not the user's past.
"""

import ipaddress
import logging
import os
import shutil
import sqlite3
import tempfile
import threading
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from pydantic import Field

from shadowtrace_agent.collectors.base import Collector, CollectorContext, CollectorOptions
from shadowtrace_agent.osinfo import OsName, current_os, current_user
from shadowtrace_agent.schema import Category

log = logging.getLogger(__name__)

WEBKIT_EPOCH = datetime(1601, 1, 1, tzinfo=UTC)
REPORTED_SCHEMES = {"http", "https", "ftp"}
MAX_URL_LENGTH = 2048
DOWNLOAD_IN_PROGRESS = 0
DOWNLOAD_COMPLETE = 1


@dataclass(frozen=True)
class BrowserRoot:
    browser: str
    path: Path
    kind: str  # "chromium" or "firefox"


@dataclass(frozen=True)
class Profile:
    browser: str
    name: str
    db_path: Path
    kind: str


@dataclass(frozen=True)
class ReadResult:
    cursors: dict[str, int]
    has_more: bool = False


def profile_signature(path: Path) -> tuple:
    """SQLite may change only its WAL while the browser remains open."""
    signature = []
    for source in (path, path.with_name(path.name + "-wal")):
        try:
            stat = source.stat()
            signature.append((stat.st_mtime_ns, stat.st_size))
        except FileNotFoundError:
            signature.append(None)
    return tuple(signature)


def default_roots(os_name: OsName | None = None) -> list[BrowserRoot]:
    home = Path.home()
    match os_name or current_os():
        case "windows":
            local = Path(os.environ.get("LOCALAPPDATA", home / "AppData" / "Local"))
            roaming = Path(os.environ.get("APPDATA", home / "AppData" / "Roaming"))
            return [
                BrowserRoot("chrome", local / "Google" / "Chrome" / "User Data", "chromium"),
                BrowserRoot("edge", local / "Microsoft" / "Edge" / "User Data", "chromium"),
                BrowserRoot(
                    "brave", local / "BraveSoftware" / "Brave-Browser" / "User Data", "chromium"
                ),
                BrowserRoot("firefox", roaming / "Mozilla" / "Firefox" / "Profiles", "firefox"),
            ]
        case "macos":
            support = home / "Library" / "Application Support"
            return [
                BrowserRoot("chrome", support / "Google" / "Chrome", "chromium"),
                BrowserRoot("edge", support / "Microsoft Edge", "chromium"),
                BrowserRoot("brave", support / "BraveSoftware" / "Brave-Browser", "chromium"),
                BrowserRoot("firefox", support / "Firefox" / "Profiles", "firefox"),
            ]
        case _:
            config = home / ".config"
            return [
                BrowserRoot("chrome", config / "google-chrome", "chromium"),
                BrowserRoot("chromium", config / "chromium", "chromium"),
                BrowserRoot("edge", config / "microsoft-edge", "chromium"),
                BrowserRoot("brave", config / "BraveSoftware" / "Brave-Browser", "chromium"),
                BrowserRoot("firefox", home / ".mozilla" / "firefox", "firefox"),
            ]


def discover_profiles(roots: list[BrowserRoot]) -> list[Profile]:
    profiles = []
    for root in roots:
        if not root.path.is_dir():
            continue
        db_name = "History" if root.kind == "chromium" else "places.sqlite"
        for child in sorted(root.path.iterdir()):
            db = child / db_name
            if db.is_file():
                profiles.append(Profile(root.browser, child.name, db, root.kind))
    return profiles


def webkit_to_datetime(value: int | None) -> datetime | None:
    if not value:
        return None
    return WEBKIT_EPOCH + timedelta(microseconds=value)


def unix_us_to_datetime(value: int | None) -> datetime | None:
    if not value:
        return None
    return datetime.fromtimestamp(value / 1_000_000, UTC)


def describe_url(url: str) -> dict[str, Any] | None:
    """Domain details for a URL, or None for browser-internal pages."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return None
    if parts.scheme not in REPORTED_SCHEMES or not parts.hostname:
        return None
    host = parts.hostname.lower()
    try:
        ipaddress.ip_address(host)
        host_is_ip = True
    except ValueError:
        host_is_ip = False
    return {
        "url": url[:MAX_URL_LENGTH],
        "domain": host,
        "scheme": parts.scheme,
        "host_is_ip": host_is_ip,
    }


class BrowserCollector(Collector):
    name = "browser"

    class Options(CollectorOptions):
        poll_interval_seconds: float = Field(30.0, ge=5.0)
        include_titles: bool = True
        max_rows_per_poll: int = Field(500, ge=10)

    options: Options

    def __init__(
        self,
        options: Options,
        emit,
        context: CollectorContext | None = None,
        roots: list[BrowserRoot] | None = None,
    ) -> None:
        super().__init__(options, emit, context)
        self._roots = roots if roots is not None else default_roots()
        self._signatures: dict[str, tuple] = {}
        self._backlog: set[str] = set()
        self._user = current_user()

    def run(self, stop: threading.Event) -> None:
        log.info("Browser monitor started (%d profiles)", len(discover_profiles(self._roots)))
        while not stop.is_set():
            self.poll()
            stop.wait(self.options.poll_interval_seconds)

    def poll(self) -> None:
        state = self.load_state()
        changed = False
        for profile in discover_profiles(self._roots):
            key = str(profile.db_path)
            try:
                signature = profile_signature(profile.db_path)
            except OSError:
                continue
            if self._signatures.get(key) == signature and key in state and key not in self._backlog:
                continue
            try:
                result = self._read_profile(profile, state.get(key))
            except (OSError, sqlite3.Error) as exc:
                log.debug("Skipping %s %s this round: %s", profile.browser, profile.name, exc)
                continue
            self._signatures[key] = signature
            if result.has_more:
                self._backlog.add(key)
            else:
                self._backlog.discard(key)
            if result.cursors != state.get(key):
                state[key] = result.cursors
                changed = True
        if changed:
            self.save_state(state)

    def _read_profile(self, profile: Profile, cursors: dict[str, int] | None) -> ReadResult:
        with tempfile.TemporaryDirectory(prefix="shadowtrace-") as tmp:
            copy = Path(tmp) / profile.db_path.name
            shutil.copy2(profile.db_path, copy)
            wal = profile.db_path.with_name(profile.db_path.name + "-wal")
            if wal.exists():  # Firefox keeps recent visits in its write-ahead log
                shutil.copy2(wal, Path(tmp) / wal.name)
            conn = sqlite3.connect(copy)
            try:
                if profile.kind == "chromium":
                    return self._read_chromium(conn, profile, cursors)
                return self._read_firefox(conn, profile, cursors)
            finally:
                conn.close()

    def _read_chromium(
        self, conn: sqlite3.Connection, profile: Profile, cursors: dict[str, int] | None
    ) -> ReadResult:
        if cursors is None:  # first sight: start from now
            return ReadResult(
                {
                    "visit": conn.execute("SELECT COALESCE(MAX(id), 0) FROM visits").fetchone()[0],
                    "download": _max_id(conn, "downloads"),
                }
            )
        last_visit = cursors.get("visit", 0)
        rows = conn.execute(
            "SELECT visits.id, urls.url, urls.title, visits.visit_time FROM visits "
            "JOIN urls ON urls.id = visits.url WHERE visits.id > ? ORDER BY visits.id LIMIT ?",
            (last_visit, self.options.max_rows_per_poll),
        ).fetchall()
        for visit_id, url, title, visit_time in rows:
            self._emit_visit(profile, url, title, webkit_to_datetime(visit_time))
            last_visit = visit_id

        last_download = cursors.get("download", 0)
        downloads = _chromium_downloads(conn, last_download, self.options.max_rows_per_poll)
        blocked = False
        for row in downloads:
            download_id, target_path, tab_url, start_time, total_bytes, mime, danger, state, url = (
                row
            )
            if state == DOWNLOAD_IN_PROGRESS:
                blocked = True
                break  # report it once finished; later rows wait so none are skipped
            if state == DOWNLOAD_COMPLETE:
                self._emit_download(
                    profile, url or tab_url, tab_url, target_path, total_bytes, mime, danger,
                    webkit_to_datetime(start_time),
                )  # fmt: skip
            last_download = download_id
        return ReadResult(
            {"visit": last_visit, "download": last_download},
            len(rows) == self.options.max_rows_per_poll
            or (not blocked and len(downloads) == self.options.max_rows_per_poll),
        )

    def _read_firefox(
        self, conn: sqlite3.Connection, profile: Profile, cursors: dict[str, int] | None
    ) -> ReadResult:
        if cursors is None:
            return ReadResult({"visit": _max_id(conn, "moz_historyvisits")})
        last_visit = cursors.get("visit", 0)
        rows = conn.execute(
            "SELECT v.id, p.url, p.title, v.visit_date FROM moz_historyvisits v "
            "JOIN moz_places p ON p.id = v.place_id WHERE v.id > ? ORDER BY v.id LIMIT ?",
            (last_visit, self.options.max_rows_per_poll),
        ).fetchall()
        for visit_id, url, title, visit_date in rows:
            self._emit_visit(profile, url, title, unix_us_to_datetime(visit_date))
            last_visit = visit_id
        return ReadResult({"visit": last_visit}, len(rows) == self.options.max_rows_per_poll)

    def _emit_visit(
        self, profile: Profile, url: str, title: str | None, ts: datetime | None
    ) -> None:
        details = describe_url(url or "")
        if details is None:
            return
        data = {"browser": profile.browser, "profile": profile.name, **details}
        if self.options.include_titles and title:
            data["title"] = title[:300]
        self.emit(Category.BROWSER, "url_visited", data, user=self._user, ts=ts)

    def _emit_download(
        self,
        profile: Profile,
        url: str | None,
        referrer: str | None,
        target_path: str | None,
        size: int | None,
        mime: str | None,
        danger: int | None,
        ts: datetime | None,
    ) -> None:
        details = describe_url(url or "") or {"url": url, "domain": None, "host_is_ip": False}
        path = target_path or ""
        data = {
            "browser": profile.browser,
            "profile": profile.name,
            **details,
            "referrer_url": (referrer or "")[:MAX_URL_LENGTH] or None,
            "path": path,
            "file_name": os.path.basename(path),
            "ext": Path(path).suffix.lower(),
            "size": size,
            "mime_type": mime,
            # Chrome's own verdict: 0 = safe; other values mean it flagged the file.
            "danger_type": danger,
        }
        self.emit(Category.BROWSER, "file_downloaded", data, user=self._user, ts=ts)


def _max_id(conn: sqlite3.Connection, table: str) -> int:
    try:
        return conn.execute(f"SELECT COALESCE(MAX(id), 0) FROM {table}").fetchone()[0]
    except sqlite3.OperationalError:  # table missing in this browser version
        return 0


def _chromium_downloads(conn: sqlite3.Connection, after_id: int, limit: int) -> list[tuple]:
    try:
        return conn.execute(
            "SELECT d.id, d.target_path, d.tab_url, d.start_time, d.total_bytes, d.mime_type, "
            "d.danger_type, d.state, (SELECT c.url FROM downloads_url_chains c "
            "WHERE c.id = d.id ORDER BY c.chain_index DESC LIMIT 1) "
            "FROM downloads d WHERE d.id > ? ORDER BY d.id LIMIT ?",
            (after_id, limit),
        ).fetchall()
    except sqlite3.OperationalError:
        return []
