from shadowtrace_agent.collectors.base import CollectorContext
from shadowtrace_agent.collectors.windows.wifi import (
    WifiCollector,
    _is_open,
    parse_netsh_interfaces,
)

CONNECTED = """
There is 1 interface on the system:

    Name                   : Wi-Fi
    Description            : Intel(R) Wi-Fi 6 AX201
    State                  : connected
    SSID                   : CampusWiFi
    AP BSSID               : fa:d0:0e:09:9d:8e
    Authentication         : WPA3-Personal
    Cipher                 : CCMP
    Signal                 : 95%
    Radio type             : 802.11ax
"""

OPEN_HOTSPOT = """
    Name                   : Wi-Fi
    State                  : connected
    SSID                   : FreeAirportWiFi
    AP BSSID               : 00:11:22:33:44:55
    Authentication         : Open
    Signal                 : 70%
"""

DISCONNECTED = """
    Name                   : Wi-Fi
    State                  : disconnected
"""


def test_parse_connected_interface():
    interfaces = parse_netsh_interfaces(CONNECTED)
    assert len(interfaces) == 1
    wifi = interfaces[0]
    assert wifi["ssid"] == "CampusWiFi"
    assert wifi["bssid"] == "fa:d0:0e:09:9d:8e"
    assert wifi["is_open"] is False


def test_open_network_is_flagged():
    assert parse_netsh_interfaces(OPEN_HOTSPOT)[0]["is_open"] is True


def test_disconnected_interface_is_dropped():
    assert parse_netsh_interfaces(DISCONNECTED) == []


def test_is_open():
    assert _is_open("Open") is True
    assert _is_open("WPA2-Personal") is False
    assert _is_open("WPA3-Personal") is False
    assert _is_open(None) is False


def test_collector_reports_change_and_open_flag(tmp_path):
    captured: list[dict] = []
    collector = WifiCollector(
        WifiCollector.Options(),
        lambda category, action, data=None, user=None, ts=None: captured.append(
            {"action": action, **(data or {})}
        ),
        CollectorContext(tmp_path),
    )

    collector.poll(CONNECTED)
    collector.poll(CONNECTED)  # unchanged, no new event
    collector.poll(OPEN_HOTSPOT)  # roamed to an open network
    collector.poll(DISCONNECTED)

    actions = [e["action"] for e in captured]
    assert actions == ["network_connected", "network_connected", "network_disconnected"]
    assert captured[0]["ssid"] == "CampusWiFi"
    assert captured[1]["ssid"] == "FreeAirportWiFi" and captured[1]["is_open"] is True
