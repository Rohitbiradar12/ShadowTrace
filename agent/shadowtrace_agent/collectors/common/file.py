"""File activity monitoring with watchdog (ReadDirectoryChangesW / inotify / FSEvents).

Watches the user's Desktop, Documents and Downloads, any configured sensitive folders, and
every removable drive while it is plugged in (to spot bulk copying to USB). Bursts of
"modified" notifications for one file are merged, and executables/scripts are hashed once
they stop changing so rules can match known-malicious hashes.

watchdog reports changes, not reads; reading a file needs OS object-access auditing.
"""

import fnmatch
import hashlib
import logging
import os
import queue
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from pydantic import Field
from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer

from shadowtrace_agent.collectors.base import Collector, CollectorContext, CollectorOptions
from shadowtrace_agent.osinfo import current_user, removable_mountpoints, user_folders
from shadowtrace_agent.schema import Category

log = logging.getLogger(__name__)

EXECUTABLE_EXTENSIONS = [
    ".exe", ".dll", ".scr", ".msi", ".com", ".bat", ".cmd", ".ps1", ".vbs", ".vbe",
    ".js", ".jse", ".wsf", ".hta", ".jar", ".lnk", ".sh", ".py", ".apk", ".iso",
]  # fmt: skip
IGNORED_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", ".idea", ".vscode"}


def _normalize(path: str) -> str:
    return os.path.normcase(os.path.abspath(path))


def _under(path: str, root: str) -> bool:
    """True if normalized ``path`` is ``root`` or inside it."""
    return path == root or path.startswith(root.rstrip(os.sep) + os.sep)


@dataclass
class _Pending:
    kind: str  # "created" or "modified"
    last_change: float
    is_dir: bool = False


@dataclass
class _Watch:
    root: str
    removable: bool
    handle: Any = field(default=None)


class _Handler(FileSystemEventHandler):
    def __init__(self, events: "queue.Queue[FileSystemEvent]") -> None:
        self._events = events

    def on_any_event(self, event: FileSystemEvent) -> None:
        if event.event_type in ("created", "modified", "deleted", "moved"):
            self._events.put(event)


class FileCollector(Collector):
    name = "file"

    class Options(CollectorOptions):
        watch_user_folders: bool = True
        paths: list[str] = Field(default_factory=list)
        # Any change inside these folders is flagged with data.sensitive = true.
        sensitive_paths: list[str] = Field(default_factory=list)
        watch_removable: bool = True
        ignore_patterns: list[str] = Field(
            default_factory=lambda: [
                "~$*",
                "*.tmp",
                "*.temp",
                "*.crdownload",
                "*.part",
                "*.partial",
                "*.swp",
                "desktop.ini",
                "thumbs.db",
                ".ds_store",
                "*.lock",
                "*-journal",
                "*-wal",
                "*-shm",
            ]  # fmt: skip
        )
        hash_extensions: list[str] = Field(default_factory=lambda: list(EXECUTABLE_EXTENSIONS))
        max_hash_size_mb: int = Field(50, ge=1)
        settle_seconds: float = Field(2.0, ge=0.1)
        removable_poll_seconds: float = Field(3.0, ge=0.5)

    options: Options

    def __init__(self, options: Options, emit, context: CollectorContext | None = None) -> None:
        super().__init__(options, emit, context)
        self._queue: queue.Queue[FileSystemEvent] = queue.Queue()
        self._pending: dict[str, _Pending] = {}
        self._watches: dict[str, _Watch] = {}
        self._excluded = [_normalize(str(self.context.data_dir))]
        self._sensitive = [_normalize(p) for p in options.sensitive_paths]
        self._hash_exts = {e.lower() for e in options.hash_extensions}
        self._user = current_user()

    def run(self, stop: threading.Event) -> None:
        observer = Observer()
        handler = _Handler(self._queue)
        for root in self._fixed_roots():
            self._watch(observer, handler, root, removable=False)
        observer.start()
        log.info("File monitor watching %s", ", ".join(w.root for w in self._watches.values()))
        try:
            next_drive_check = 0.0
            while not stop.is_set():
                if self.options.watch_removable and time.monotonic() >= next_drive_check:
                    self._sync_removable(observer, handler)
                    next_drive_check = time.monotonic() + self.options.removable_poll_seconds
                self._drain(timeout=0.5)
                self.flush_settled()
        finally:
            observer.stop()
            observer.join(timeout=5)
            self.flush_settled(force=True)

    # --- watch management -------------------------------------------------------------

    def _fixed_roots(self) -> list[str]:
        roots = list(self.options.paths) + list(self.options.sensitive_paths)
        if self.options.watch_user_folders:
            roots += [str(p) for p in user_folders().values()]
        unique: dict[str, str] = {}
        for root in roots:
            path = os.path.expandvars(os.path.expanduser(root))
            if os.path.isdir(path):
                unique.setdefault(_normalize(path), path)
            else:
                log.info("Not watching %s (folder does not exist)", path)
        # Drop folders nested inside another watched folder; recursion already covers them.
        keys = sorted(unique)
        return [
            unique[k] for k in keys if not any(k != o and k.startswith(o + os.sep) for o in keys)
        ]

    def _watch(self, observer, handler, root: str, removable: bool) -> None:
        try:
            handle = observer.schedule(handler, root, recursive=True)
        except OSError as exc:
            log.warning("Cannot watch %s: %s", root, exc)
            return
        self._watches[_normalize(root)] = _Watch(root, removable, handle)

    def _sync_removable(self, observer, handler) -> None:
        mounted = {_normalize(m): m for m in removable_mountpoints()}
        for key, watch in list(self._watches.items()):
            if watch.removable and key not in mounted:
                try:
                    observer.unschedule(watch.handle)
                except (KeyError, OSError):
                    pass
                del self._watches[key]
                log.info("Stopped watching removable drive %s", watch.root)
        for key, mountpoint in mounted.items():
            if key not in self._watches:
                self._watch(observer, handler, mountpoint, removable=True)
                log.info("Watching removable drive %s", mountpoint)

    # --- event processing ---------------------------------------------------------------

    def _drain(self, timeout: float) -> None:
        try:
            event = self._queue.get(timeout=timeout)
        except queue.Empty:
            return
        while True:
            self.handle(event)
            try:
                event = self._queue.get_nowait()
            except queue.Empty:
                return

    def handle(self, event: FileSystemEvent) -> None:
        src = os.fsdecode(event.src_path)
        if event.event_type == "moved":
            dest = os.fsdecode(event.dest_path)
            if self._ignored(src) and self._ignored(dest):
                return
            self._flush_path(src)
            extra = {"old_path": src}
            if not event.is_directory:  # e.g. a finished download renamed to .exe
                extra.update(self._file_details(dest))
            self._emit("file_renamed", dest, event.is_directory, extra)
            return
        if self._ignored(src):
            return
        now = time.monotonic()
        if event.event_type == "deleted":
            self._flush_path(src)
            self._emit("file_deleted", src, event.is_directory)
        elif event.event_type == "created":
            self._pending[src] = _Pending("created", now, event.is_directory)
        elif not event.is_directory:  # modified; directory mtime changes are noise
            pending = self._pending.get(src)
            if pending:
                pending.last_change = now
            else:
                self._pending[src] = _Pending("modified", now)

    def flush_settled(self, force: bool = False) -> None:
        cutoff = time.monotonic() - self.options.settle_seconds
        for path in [p for p, s in self._pending.items() if force or s.last_change <= cutoff]:
            self._flush_path(path)

    def _flush_path(self, path: str) -> None:
        pending = self._pending.pop(path, None)
        if pending is None:
            return
        extra: dict[str, Any] = {}
        if not pending.is_dir:
            extra.update(self._file_details(path))
        self._emit(f"file_{pending.kind}", path, pending.is_dir, extra)

    def _file_details(self, path: str) -> dict[str, Any]:
        try:
            size = os.path.getsize(path)
        except OSError:
            return {}
        details: dict[str, Any] = {"size": size}
        if (
            Path(path).suffix.lower() in self._hash_exts
            and size <= self.options.max_hash_size_mb * 1024 * 1024
        ):
            try:
                digest = hashlib.sha256()
                with open(path, "rb") as f:
                    for chunk in iter(lambda: f.read(1024 * 1024), b""):
                        digest.update(chunk)
                details["sha256"] = digest.hexdigest()
            except OSError:  # locked, or removed by antivirus
                pass
        return details

    def _emit(
        self, action: str, path: str, is_dir: bool, extra: dict[str, Any] | None = None
    ) -> None:
        normalized = _normalize(path)
        watch = next((w for key, w in self._watches.items() if _under(normalized, key)), None)
        data = {
            "path": path,
            "name": os.path.basename(path),
            "ext": "" if is_dir else Path(path).suffix.lower(),
            "is_dir": is_dir,
            "removable": bool(watch and watch.removable),
            "sensitive": any(_under(normalized, s) for s in self._sensitive),
            "watch_root": watch.root if watch else None,
            **(extra or {}),
        }
        self.emit(Category.FILE, action, data, user=self._user)

    def _ignored(self, path: str) -> bool:
        normalized = _normalize(path)
        if any(_under(normalized, x) for x in self._excluded):
            return True
        parts = Path(path).parts
        if any(part.lower() in IGNORED_DIRS for part in parts[:-1]):
            return True
        name = parts[-1].lower() if parts else ""
        return any(fnmatch.fnmatch(name, pattern) for pattern in self.options.ignore_patterns)
