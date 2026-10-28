"""Windows Security event log monitor (pywin32).

Covers the deck's "failed logins" and "insider misuse": failed/successful logons, account
lockouts, new accounts, additions to the Administrators group, and clearing of the audit log
itself. Reading the Security log needs administrator rights; without them the collector logs
one warning and stops instead of crash-looping.

Event parsing is split into pure functions so it is unit-tested without the real log.
"""

import logging
import threading
from datetime import UTC, datetime
from typing import Any

from pydantic import Field

from shadowtrace_agent.collectors.base import Collector, CollectorContext, CollectorOptions
from shadowtrace_agent.schema import Category

log = logging.getLogger(__name__)

# https://learn.microsoft.com/windows/security/threat-protection/auditing/
LOGON_TYPES = {
    2: "interactive",
    3: "network",
    4: "batch",
    5: "service",
    7: "unlock",
    8: "network_cleartext",
    9: "new_credentials",
    10: "remote_interactive",  # RDP
    11: "cached_interactive",
}
# Failures hint at why: a bad password reads differently from a disabled account.
FAILURE_SUBSTATUS = {
    0xC0000064: "user_does_not_exist",
    0xC000006A: "wrong_password",
    0xC0000234: "account_locked",
    0xC0000072: "account_disabled",
    0xC0000070: "workstation_restriction",
    0xC000006F: "outside_logon_hours",
    0xC0000193: "account_expired",
    0xC0000071: "password_expired",
}
ADMIN_GROUP_HINTS = ("admin",)  # Administrators, Administratoren, etc.


def _text(inserts: list | None, index: int) -> str | None:
    if not inserts or index >= len(inserts):
        return None
    value = inserts[index]
    if value in (None, "", "-", "%1793", "%%1793"):
        return None
    return str(value)


def _int(value: str | None) -> int | None:
    if value is None:
        return None
    try:
        return int(value, 0) if value.lower().startswith("0x") else int(value)
    except (ValueError, AttributeError):
        return None


def _account(user: str | None, domain: str | None) -> str | None:
    if user and domain:
        return f"{domain}\\{user}"
    return user


def _logon_type_name(value: str | None) -> str | int | None:
    code = _int(value)
    return LOGON_TYPES.get(code, code)


def parse_security_event(
    event_id: int, inserts: list | None
) -> tuple[Category, str, dict[str, Any]] | None:
    """Map a Security event to (category, action, data), or None to ignore it."""
    match event_id:
        case 4625:  # failed logon
            substatus = _int(_text(inserts, 9))
            return (
                Category.AUTH,
                "logon_failed",
                {
                    "target_user": _account(_text(inserts, 5), _text(inserts, 6)),
                    "logon_type": _logon_type_name(_text(inserts, 10)),
                    "workstation": _text(inserts, 13),
                    "source_ip": _text(inserts, 19),
                    "reason": FAILURE_SUBSTATUS.get(substatus),
                },
            )
        case 4624:  # successful logon
            return (
                Category.AUTH,
                "logon_success",
                {
                    "target_user": _account(_text(inserts, 5), _text(inserts, 6)),
                    "logon_type": _logon_type_name(_text(inserts, 8)),
                    "workstation": _text(inserts, 11),
                    "source_ip": _text(inserts, 18),
                },
            )
        case 4634 | 4647:  # logoff
            return (
                Category.AUTH,
                "logoff",
                {
                    "target_user": _account(_text(inserts, 1), _text(inserts, 2)),
                    "logon_type": _logon_type_name(_text(inserts, 4)),
                },
            )
        case 4740:  # account locked out
            return (
                Category.AUTH,
                "account_locked",
                {
                    "target_user": _text(inserts, 0),
                    "source_workstation": _text(inserts, 1),
                },
            )
        case 4720:  # user account created
            return (
                Category.SYSTEM,
                "account_created",
                {
                    "new_account": _account(_text(inserts, 0), _text(inserts, 1)),
                    "created_by": _account(_text(inserts, 4), _text(inserts, 5)),
                },
            )
        case 4726:  # user account deleted
            return (
                Category.SYSTEM,
                "account_deleted",
                {
                    "target_account": _account(_text(inserts, 0), _text(inserts, 1)),
                    "deleted_by": _account(_text(inserts, 4), _text(inserts, 5)),
                },
            )
        case 4732:  # member added to a security-enabled local group
            group = _text(inserts, 2)
            is_admin = bool(group and any(h in group.lower() for h in ADMIN_GROUP_HINTS))
            return (
                Category.SYSTEM,
                "member_added_to_group",
                {
                    "group": group,
                    "member": _text(inserts, 0),
                    "added_by": _account(_text(inserts, 6), _text(inserts, 7)),
                    "is_admin_group": is_admin,
                },
            )
        case 1102:  # the security audit log was cleared
            return (
                Category.SYSTEM,
                "audit_log_cleared",
                {
                    "cleared_by": _account(_text(inserts, 1), _text(inserts, 2)),
                },
            )
        case _:
            return None


class EventLogCollector(Collector):
    name = "eventlog"
    platforms = frozenset({"windows"})

    class Options(CollectorOptions):
        poll_interval_seconds: float = Field(5.0, ge=1.0)
        channel: str = "Security"
        # Interactive, unlock and RDP are real user logons; network/service logons are noise.
        report_logon_success_types: list[int] = Field(default_factory=lambda: [2, 7, 10, 11])

    options: Options

    def __init__(self, options: Options, emit, context: CollectorContext | None = None) -> None:
        super().__init__(options, emit, context)
        self._last_record = self.load_state().get("last_record", 0)
        self._access_denied = False

    def run(self, stop: threading.Event) -> None:
        import pywintypes
        import win32evtlog

        try:
            handle = win32evtlog.OpenEventLog(None, self.options.channel)
        except pywintypes.error as exc:
            self._handle_open_error(exc)
            return

        try:
            if not self._last_record:
                # First run on this machine: start from the newest record, skip history.
                self._last_record = self._newest_record(win32evtlog, handle)
                self.save_state({"last_record": self._last_record})
            log.info(
                "Event log monitor started on %s (record %d)",
                self.options.channel,
                self._last_record,
            )
            while not stop.is_set():
                self._read_new(win32evtlog, pywintypes, handle)
                stop.wait(self.options.poll_interval_seconds)
        finally:
            win32evtlog.CloseEventLog(handle)

    def _read_new(self, win32evtlog, pywintypes, handle) -> None:
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        newest = self._newest_record(win32evtlog, handle)
        if newest < self._last_record:
            # Log was cleared or wrapped; resync without replaying the whole log.
            log.info("Event log reset detected (newest %d < last %d)", newest, self._last_record)
            self._last_record = 0
        collected: list[tuple[int, Any]] = []
        try:
            while True:
                records = win32evtlog.ReadEventLog(handle, flags, 0)
                if not records:
                    break
                done = False
                for record in records:
                    if record.RecordNumber <= self._last_record:
                        done = True
                        break
                    collected.append((record.RecordNumber, record))
                if done:
                    break
        except pywintypes.error as exc:
            log.warning("Reading event log failed: %s", exc)
            return

        # Collected newest-first; emit oldest-first so the forensic timeline stays ordered.
        for _, record in sorted(collected, key=lambda item: item[0]):
            self._emit_record(record)
        if collected:
            self._last_record = max(self._last_record, max(num for num, _ in collected))
            self.save_state({"last_record": self._last_record})

    def _emit_record(self, record) -> None:
        event_id = record.EventID & 0xFFFF
        parsed = parse_security_event(event_id, record.StringInserts)
        if parsed is None:
            return
        category, action, data = parsed
        if action == "logon_success":
            logon_code = _int(_text(record.StringInserts, 8))
            if logon_code not in self.options.report_logon_success_types:
                return
        data["event_id"] = event_id
        user = data.get("target_user")
        self.emit(category, action, data, user=user, ts=_record_time(record))

    @staticmethod
    def _newest_record(win32evtlog, handle) -> int:
        try:
            oldest = win32evtlog.GetOldestEventLogRecord(handle)
            count = win32evtlog.GetNumberOfEventLogRecords(handle)
        except Exception:
            return 0
        return oldest + count - 1 if count else 0

    def _handle_open_error(self, exc) -> None:
        import winerror

        # 5 = access denied, 1314 = required privilege not held — both mean "not elevated".
        needs_admin = (winerror.ERROR_ACCESS_DENIED, winerror.ERROR_PRIVILEGE_NOT_HELD)
        if exc.winerror in needs_admin:
            log.warning(
                "Cannot read the %s log without administrator rights; "
                "login and account monitoring is disabled. Run the agent elevated.",
                self.options.channel,
            )
            if not self._access_denied:
                self._access_denied = True
                self.emit(
                    Category.AGENT,
                    "eventlog_access_denied",
                    {"channel": self.options.channel},
                )
        else:
            log.warning("Cannot open the %s log: %s", self.options.channel, exc)


def _record_time(record) -> datetime | None:
    value = getattr(record, "TimeGenerated", None)
    if value is None:
        return None
    try:
        # pywintypes datetime is timezone-aware local time.
        return value.astimezone(UTC)
    except (ValueError, OSError, AttributeError):
        try:
            return datetime.fromtimestamp(int(value), UTC)
        except (ValueError, OSError, TypeError):
            return None
