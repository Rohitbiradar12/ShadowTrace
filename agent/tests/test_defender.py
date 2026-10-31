import re
import threading
from datetime import UTC, datetime, timedelta

from shadowtrace_agent.collectors.base import CollectorContext
from shadowtrace_agent.collectors.windows.defender import (
    CHANNEL,
    DefenderCollector,
    parse_defender_event,
)


def xml(record_id, event_id=1116, epoch=0):
    ts = (datetime(2026, 10, 28, tzinfo=UTC) + timedelta(seconds=record_id + epoch)).isoformat()
    return f'''<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System><Provider Name="Microsoft-Windows-Windows Defender"/><EventID>{event_id}</EventID>
    <EventRecordID>{record_id}</EventRecordID><TimeCreated SystemTime="{ts}"/></System>
    <EventData><Data Name="Threat Name">Test &amp; fixture</Data><Data Name="Path">C:\\demo</Data>
    <Data Name="Detection User">LAB\\student</Data><Data Name="Action Name">Allow</Data>
    <Data Name="New Value">example</Data></EventData></Event>'''


class Handle:
    def __init__(self, data):
        self.data = data
        self.closed = False

    def Close(self):
        self.closed = True


class FakeApi:
    EvtQueryChannelPath, EvtQueryForwardDirection, EvtQueryReverseDirection = 1, 2, 4
    EvtRenderEventXml = 1

    def __init__(self, records):
        self.records = records
        self.handles = []

    def EvtQuery(self, channel, flags, query):
        assert channel == CHANNEL
        records = list(self.records)
        if match := re.search(r"EventRecordID=(\d+)", query):
            records = [r for r in records if parse_defender_event(r).record_id == int(match[1])]
        if match := re.search(r"EventRecordID>(\d+) and EventRecordID<=(\d+)", query):
            records = [
                r
                for r in records
                if int(match[1]) < parse_defender_event(r).record_id <= int(match[2])
            ]
        if flags & self.EvtQueryReverseDirection:
            records.reverse()
        handle = Handle(iter(records))
        self.handles.append(handle)
        return handle

    def EvtNext(self, handle, count):
        rows = []
        for _ in range(min(count, 2)):  # exercise multiple native result batches
            if (row := next(handle.data, None)) is None:
                break
            event = Handle(row)
            self.handles.append(event)
            rows.append(event)
        return rows

    def EvtRender(self, event, flags):
        return event.data


def collector(tmp_path, captured):
    return DefenderCollector(
        DefenderCollector.Options(),
        lambda *a, **k: captured.append((a, k)),
        CollectorContext(tmp_path),
    )


def test_named_fields_and_action_taken_does_not_claim_remediation():
    event = parse_defender_event(xml(5, 1117))
    assert event.action == "defender_action_taken"
    assert event.data["action_name"] == "Allow"
    assert event.data["threat_name"] == "Test & fixture"
    assert event.timestamp.tzinfo is not None
    assert parse_defender_event(xml(6, 9999)).action is None


def test_poll_baselines_then_catches_backlog_and_restarts(tmp_path):
    emitted = []
    api = FakeApi([xml(1), xml(2)])
    monitor = collector(tmp_path, emitted)
    monitor.poll_once(api)
    assert emitted == []
    api.records.extend([xml(3), xml(4, 9999), xml(5, 5001), xml(6, 1118)])
    collector(tmp_path, emitted).poll_once(api)
    assert [e[0][1] for e in emitted] == [
        "defender_threat_detected",
        "defender_protection_disabled",
        "defender_action_failed",
    ]
    collector(tmp_path, emitted).poll_once(api)
    assert len(emitted) == 3
    assert all(h.closed for h in api.handles)


def test_cleared_log_can_regrow_beyond_saved_record_number(tmp_path):
    emitted = []
    api = FakeApi([xml(1), xml(2)])
    monitor = collector(tmp_path, emitted)
    monitor.poll_once(api)
    api.records = [xml(i, epoch=60) for i in range(1, 5)]
    monitor.poll_once(api)
    assert emitted[0][0][1] == "defender_log_reset"
    assert len(emitted) == 5
    assert monitor.load_state()["last_record"] == 4


def test_initial_empty_log_does_not_skip_first_event(tmp_path):
    emitted, api = [], FakeApi([])
    monitor = collector(tmp_path, emitted)
    monitor.poll_once(api)
    api.records = [xml(1)]
    monitor.poll_once(api)
    assert len(emitted) == 1


def test_read_failure_does_not_advance_cursor(tmp_path):
    import pytest

    emitted, api = [], FakeApi([xml(1)])
    monitor = collector(tmp_path, emitted)
    monitor.poll_once(api)
    api.records.append(xml(2))

    def fail(*args, **kwargs):
        raise RuntimeError("buffer unavailable")

    monitor.emit = fail
    with pytest.raises(RuntimeError):
        monitor.poll_once(api)
    assert monitor.load_state()["last_record"] == 1
    assert all(h.closed for h in api.handles)


def test_missing_channel_reports_once_and_stops_cleanly(tmp_path, monkeypatch):
    import sys

    class ChannelMissing(Exception):
        winerror = 15007

    emitted, stop = [], threading.Event()
    monitor = collector(tmp_path, emitted)
    monkeypatch.setitem(sys.modules, "win32evtlog", FakeApi([]))

    def fail(api):
        stop.set()
        raise ChannelMissing

    monkeypatch.setattr(monitor, "poll_once", fail)
    monitor.run(stop)
    assert emitted[0][0][1] == "defender_unavailable"
