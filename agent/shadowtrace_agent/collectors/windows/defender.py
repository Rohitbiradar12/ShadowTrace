"""Defender Operational events, read with the modern Windows Event Log API."""

import threading
from dataclasses import dataclass
from datetime import datetime
from xml.etree import ElementTree as ET

from pydantic import Field

from shadowtrace_agent.collectors.base import Collector, CollectorContext, CollectorOptions
from shadowtrace_agent.schema import Category, Emit

CHANNEL = "Microsoft-Windows-Windows Defender/Operational"
NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
# https://learn.microsoft.com/en-us/defender-endpoint/troubleshoot-microsoft-defender-antivirus
ACTIONS = {
    1116: "defender_threat_detected",
    1117: "defender_action_taken",
    1118: "defender_action_failed",
    1119: "defender_action_failed",
    5000: "defender_protection_enabled",
    5001: "defender_protection_disabled",
    5007: "defender_config_changed",
    5010: "defender_protection_disabled",
    5012: "defender_protection_disabled",
    5013: "defender_tamper_blocked",
}
FIELDS = {
    "Threat ID": "threat_id",
    "Threat Name": "threat_name",
    "Severity Name": "severity",
    "Category Name": "threat_category",
    "Path": "path",
    "Process Name": "process_name",
    "Detection User": "detection_user",
    "Action Name": "action_name",
    "Error Code": "error_code",
    "Error Description": "error_description",
    "Old Value": "old_value",
    "New Value": "new_value",
}


@dataclass
class DefenderRecord:
    record_id: int
    timestamp: datetime
    action: str | None
    data: dict


def parse_defender_event(xml: str) -> DefenderRecord:
    root = ET.fromstring(xml)
    system = root.find("e:System", NS)
    if system is None:
        raise ValueError("Event has no System element")
    event_id = int(system.findtext("e:EventID", namespaces=NS))
    record_id = int(system.findtext("e:EventRecordID", namespaces=NS))
    timestamp = datetime.fromisoformat(system.find("e:TimeCreated", NS).attrib["SystemTime"])
    if timestamp.tzinfo is None:
        raise ValueError("Event timestamp must include a timezone")
    data = {"event_id": event_id, "record_id": record_id, "channel": CHANNEL}
    for field in root.findall("e:EventData/e:Data", NS):
        if name := FIELDS.get(field.get("Name")):
            data[name] = (field.text or "")[:8192]
    provider = system.find("e:Provider", NS)
    action = (
        ACTIONS.get(event_id)
        if (provider is not None and provider.get("Name") == CHANNEL.split("/")[0])
        else None
    )
    return DefenderRecord(record_id, timestamp, action, data)


class DefenderOptions(CollectorOptions):
    poll_interval_seconds: float = Field(5.0, ge=1)


class DefenderCollector(Collector):
    name = "defender"
    platforms = frozenset({"windows"})
    Options = DefenderOptions

    def __init__(
        self, options: DefenderOptions, emit: Emit, context: CollectorContext | None = None
    ):
        super().__init__(options, emit, context)
        self._cursor = self.load_state()

    @staticmethod
    def _read(api, query: str, *, reverse: bool = False, limit: int = 1024):
        flags = api.EvtQueryChannelPath
        flags |= api.EvtQueryReverseDirection if reverse else api.EvtQueryForwardDirection
        handle = api.EvtQuery(CHANNEL, flags, query)
        try:
            remaining = limit
            while remaining:
                try:
                    events = api.EvtNext(handle, min(remaining, 128))
                except Exception as exc:
                    if getattr(exc, "winerror", None) == 259:  # ERROR_NO_MORE_ITEMS
                        return
                    raise
                if not events:
                    return
                try:
                    for event in events:
                        yield parse_defender_event(api.EvtRender(event, api.EvtRenderEventXml))
                finally:
                    for event in events:
                        event.Close()
                remaining -= len(events)
        finally:
            handle.Close()

    def _save(self, record: DefenderRecord | None) -> None:
        self._cursor = {
            "last_record": record.record_id if record else 0,
            "timestamp": record.timestamp.isoformat() if record else None,
        }
        self.save_state(self._cursor)

    def poll_once(self, api) -> None:
        latest = list(self._read(api, "*", reverse=True, limit=1))
        newest = latest[0] if latest else None
        if not self._cursor:  # First install starts at the tail; restarts resume the saved cursor.
            self._save(newest)
            return
        last = self._cursor["last_record"]
        reset = bool(last and (newest is None or newest.record_id < last))
        if last and not reset:
            anchor = list(self._read(api, f"*[System[EventRecordID={last}]]", limit=1))
            reset = bool(anchor and anchor[0].timestamp.isoformat() != self._cursor["timestamp"])
        if reset:
            self.emit(Category.SYSTEM, "defender_log_reset", {"channel": CHANNEL})
            self._save(None)
            last = 0
        if newest is None or newest.record_id <= last:
            return
        query = f"*[System[EventRecordID>{last} and EventRecordID<={newest.record_id}]]"
        for record in self._read(api, query):
            if record.action:
                self.emit(
                    Category.SYSTEM,
                    record.action,
                    record.data,
                    user=record.data.get("detection_user"),
                    ts=record.timestamp,
                )
            # Move only after the event is safely handed to the local buffer.
            self._save(record)

    def run(self, stop: threading.Event) -> None:
        import win32evtlog

        unavailable = False
        while not stop.is_set():
            try:
                self.poll_once(win32evtlog)
                unavailable = False
            except Exception as exc:
                if getattr(exc, "winerror", None) not in {5, 15007}:  # denied / channel not found
                    raise
                if not unavailable:
                    self.emit(Category.AGENT, "defender_unavailable", {"error_code": exc.winerror})
                unavailable = True
            stop.wait(
                max(30, self.options.poll_interval_seconds)
                if unavailable
                else self.options.poll_interval_seconds
            )
