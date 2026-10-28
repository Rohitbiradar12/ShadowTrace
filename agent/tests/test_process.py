import hashlib
import subprocess
import sys
import time

from shadowtrace_agent.collectors.common.process import HashCache, ProcessCollector, diff_keys


class Capture:
    def __init__(self) -> None:
        self.events: list[dict] = []

    def __call__(self, category, action, data=None, user=None, ts=None) -> None:
        self.events.append({"category": category, "action": action, "data": data, "user": user})

    def find(self, action: str, pid: int) -> dict | None:
        return next(
            (e for e in self.events if e["action"] == action and e["data"]["pid"] == pid), None
        )


def test_diff_keys_uses_pid_and_create_time():
    old = {(10, 1.0), (11, 2.0)}
    new = {(10, 1.0), (11, 9.0), (12, 3.0)}  # pid 11 was reused by a new process

    started, stopped = diff_keys(old, new)

    assert started == {(11, 9.0), (12, 3.0)}
    assert stopped == {(11, 2.0)}


def test_detects_process_start_and_stop():
    capture = Capture()
    collector = ProcessCollector(ProcessCollector.Options(), capture)
    known = collector.baseline()

    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
    try:
        time.sleep(0.5)
        known = collector.poll(known)
    finally:
        child.kill()
        child.wait()
    known = collector.poll(known)

    started = capture.find("process_started", child.pid)
    assert started is not None
    assert started["data"]["command_line"].endswith("import time; time.sleep(30)")
    assert started["data"]["parent"]["pid"] == started["data"]["ppid"]
    assert len(started["data"]["sha256"]) == 64
    assert capture.find("process_stopped", child.pid) is not None


def test_running_processes_are_not_reported_at_startup():
    capture = Capture()
    collector = ProcessCollector(ProcessCollector.Options(), capture)

    collector.poll(collector.baseline())

    assert not any(
        e["action"] == "process_started" and e["data"]["pid"] == 1 for e in capture.events
    )


def test_hash_cache_rehashes_when_file_changes(tmp_path):
    path = tmp_path / "tool.exe"
    path.write_bytes(b"version 1")
    cache = HashCache(max_size_bytes=1024)

    first, size = cache.sha256(str(path))
    assert first == hashlib.sha256(b"version 1").hexdigest() and size == 9

    path.write_bytes(b"version 2 (bigger)")
    second, _ = cache.sha256(str(path))
    assert second == hashlib.sha256(b"version 2 (bigger)").hexdigest()


def test_hash_cache_skips_oversized_files(tmp_path):
    path = tmp_path / "big.bin"
    path.write_bytes(b"x" * 2048)

    assert HashCache(max_size_bytes=1024).sha256(str(path)) == (None, 2048)
