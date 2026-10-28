import threading
import time

from shadowtrace_agent.collectors.base import CollectorContext
from shadowtrace_agent.collectors.common.file import FileCollector


class Capture:
    def __init__(self) -> None:
        self.events: list[dict] = []

    def __call__(self, category, action, data=None, user=None, ts=None) -> None:
        self.events.append({"action": action, **(data or {})})

    def actions_for(self, name: str) -> list[str]:
        return [e["action"] for e in self.events if e["name"] == name]


def run_collector(tmp_path, actions, **options):
    watched = tmp_path / "watched"
    watched.mkdir()
    capture = Capture()
    opts = FileCollector.Options(
        watch_user_folders=False,
        watch_removable=False,
        paths=[str(watched)],
        settle_seconds=0.3,
        **options,
    )
    collector = FileCollector(opts, capture, CollectorContext(tmp_path / "agent-data"))
    stop = threading.Event()
    thread = threading.Thread(target=collector.run, args=(stop,))
    thread.start()
    time.sleep(0.5)
    try:
        actions(watched)
        time.sleep(1.5)
    finally:
        stop.set()
        thread.join(timeout=10)
    return capture


def test_create_modify_rename_delete(tmp_path):
    def actions(folder):
        report = folder / "report.txt"
        report.write_text("v1")
        report.write_text("v2")  # merged into the create while the file is still settling
        time.sleep(0.8)
        report.rename(folder / "report.txt.locked")
        time.sleep(0.3)
        (folder / "report.txt.locked").unlink()

    capture = run_collector(tmp_path, actions)

    assert capture.actions_for("report.txt") == ["file_created"]
    assert capture.actions_for("report.txt.locked") == ["file_renamed", "file_deleted"]
    renamed = next(e for e in capture.events if e["action"] == "file_renamed")
    assert renamed["old_path"].endswith("report.txt")


def test_executables_are_hashed(tmp_path):
    capture = run_collector(tmp_path, lambda folder: (folder / "setup.exe").write_bytes(b"MZ demo"))

    created = next(e for e in capture.events if e["name"] == "setup.exe")
    assert created["ext"] == ".exe" and len(created["sha256"]) == 64 and created["size"] == 7


def test_sensitive_folder_is_flagged(tmp_path):
    def actions(folder):
        (folder / "payroll").mkdir()
        time.sleep(0.2)
        (folder / "payroll" / "salaries.xlsx").write_text("x")

    capture = run_collector(
        tmp_path, actions, sensitive_paths=[str(tmp_path / "watched" / "payroll")]
    )

    event = next(e for e in capture.events if e["name"] == "salaries.xlsx")
    assert event["sensitive"] is True


def test_temp_files_and_agent_data_are_ignored(tmp_path):
    def actions(folder):
        (folder / "~$draft.docx").write_text("x")
        (folder / "download.crdownload").write_text("x")

    capture = run_collector(tmp_path, actions)

    assert capture.events == []
