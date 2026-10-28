"""Windows-only collectors: Event Log (logins & account changes), USB (WMI), Wi-Fi (netsh)."""

from shadowtrace_agent.collectors.windows.eventlog import EventLogCollector
from shadowtrace_agent.collectors.windows.usb import UsbCollector
from shadowtrace_agent.collectors.windows.wifi import WifiCollector

COLLECTORS = [EventLogCollector, UsbCollector, WifiCollector]
