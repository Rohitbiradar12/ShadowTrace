"""Wi-Fi monitor (Windows, ``netsh wlan show interfaces``).

Reports each time the machine joins a different network, carrying SSID, BSSID, signal and the
security type. Open (unencrypted) networks are flagged so a rule can warn the user — the
deck's "Wi-Fi & network activity". No admin rights required.
"""

import logging
import subprocess
import threading
from typing import Any

from pydantic import Field

from shadowtrace_agent.collectors.base import Collector, CollectorContext, CollectorOptions
from shadowtrace_agent.schema import Category

log = logging.getLogger(__name__)

# netsh field labels we keep (English Windows). Lowercased keys.
_FIELDS = {
    "name": "interface",
    "ssid": "ssid",
    "bssid": "bssid",
    "ap bssid": "bssid",
    "state": "state",
    "authentication": "authentication",
    "cipher": "cipher",
    "signal": "signal",
    "radio type": "radio_type",
    "channel": "channel",
}


def _is_open(authentication: str | None) -> bool:
    if not authentication:
        return False
    auth = authentication.strip().lower()
    return auth in ("open", "none", "") or (
        "open" in auth and "wpa" not in auth and "wep" not in auth
    )


def parse_netsh_interfaces(output: str) -> list[dict[str, Any]]:
    """Parse ``netsh wlan show interfaces`` into one dict per interface."""
    interfaces: list[dict[str, Any]] = []
    current: dict[str, Any] = {}
    for line in output.splitlines():
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key = key.strip().lower()
        value = value.strip()
        field = _FIELDS.get(key)
        if field is None:
            continue
        if field == "interface":  # a new interface block begins
            if current:
                interfaces.append(current)
            current = {}
        current[field] = value
    if current:
        interfaces.append(current)
    connected = [i for i in interfaces if i.get("state", "").lower() == "connected"]
    for interface in connected:
        interface["is_open"] = _is_open(interface.get("authentication"))
    return connected


def _run_netsh() -> str:
    result = subprocess.run(
        ["netsh", "wlan", "show", "interfaces"],
        capture_output=True,
        text=True,
        timeout=15,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    return result.stdout


class WifiCollector(Collector):
    name = "wifi"
    platforms = frozenset({"windows"})

    class Options(CollectorOptions):
        poll_interval_seconds: float = Field(10.0, ge=2.0)

    options: Options

    def __init__(self, options: Options, emit, context: CollectorContext | None = None) -> None:
        super().__init__(options, emit, context)
        # interface name -> (ssid, bssid) last reported, so roaming between APs is noticed.
        self._connected: dict[str, tuple] = {}

    def run(self, stop: threading.Event) -> None:
        log.info("Wi-Fi monitor started")
        while not stop.is_set():
            try:
                self.poll(_run_netsh())
            except (OSError, subprocess.SubprocessError) as exc:
                log.warning("netsh wlan failed: %s", exc)
            stop.wait(self.options.poll_interval_seconds)

    def poll(self, netsh_output: str) -> None:
        seen: dict[str, tuple] = {}
        for interface in parse_netsh_interfaces(netsh_output):
            name = interface.get("interface", "wlan")
            identity = (interface.get("ssid"), interface.get("bssid"))
            seen[name] = identity
            if self._connected.get(name) != identity and interface.get("ssid"):
                self.emit(Category.WIFI, "network_connected", interface)
        for name in self._connected.keys() - seen.keys():
            self.emit(Category.WIFI, "network_disconnected", {"interface": name})
        self._connected = seen
