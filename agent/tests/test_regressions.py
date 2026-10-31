from pathlib import Path
from types import SimpleNamespace

from shadowtrace_agent.collectors.base import CollectorContext
from shadowtrace_agent.collectors.windows.eventlog import EventLogCollector


class FakeLog:
    EVENTLOG_FORWARDS_READ = 4
    EVENTLOG_SEEK_READ = 2
    EVENTLOG_SEQUENTIAL_READ = 1

    def __init__(self):
        self.records = [SimpleNamespace(RecordNumber=n) for n in (1, 2, 3)]
        self.position = 0

    def GetOldestEventLogRecord(self, handle):
        return self.records[0].RecordNumber

    def GetNumberOfEventLogRecords(self, handle):
        return len(self.records)

    def ReadEventLog(self, handle, flags, offset):
        if flags & self.EVENTLOG_SEEK_READ:
            self.position = next(
                i for i, record in enumerate(self.records) if record.RecordNumber == offset
            )
        result = self.records[self.position : self.position + 2]
        self.position += len(result)
        return result


def test_eventlog_continues_polling_and_recovers_after_clear(tmp_path):
    collector = EventLogCollector(
        EventLogCollector.Options(), lambda *a, **k: None, CollectorContext(tmp_path)
    )
    collector._last_record = 3
    captured = []
    collector._emit_record = lambda record: captured.append(record.RecordNumber)
    api = FakeLog()
    errors = SimpleNamespace(error=RuntimeError)
    collector._read_new(api, errors, None)
    for n in (4, 5):
        api.records.append(SimpleNamespace(RecordNumber=n))
        collector._read_new(api, errors, None)
    assert captured == [4, 5]
    api.records = [SimpleNamespace(RecordNumber=1), SimpleNamespace(RecordNumber=2)]
    collector._read_new(api, errors, None)
    assert captured == [4, 5, 1, 2]
    assert collector.load_state()["last_record"] == 2


def test_agent_passes_custom_data_directory_to_collectors(tmp_path, monkeypatch):
    from shadowtrace_agent import agent as module
    from shadowtrace_agent.config import AgentConfig
    from shadowtrace_agent.state import EnrollmentState

    config = AgentConfig(data_dir=tmp_path)
    monkeypatch.setattr(module, "load_state", lambda _: EnrollmentState("dev_test", "x", "x"))
    captured = []

    class StopBeforeStarting(Exception):
        pass

    def build(config, emit, *, context):
        captured.append(context.data_dir)
        raise StopBeforeStarting

    monkeypatch.setattr(module, "build_collectors", build)
    instance = module.Agent(config)
    try:
        instance.run()
    except StopBeforeStarting:
        pass
    finally:
        instance.buffer.close()
    assert captured == [Path(tmp_path)]
