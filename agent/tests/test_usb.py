from shadowtrace_agent.collectors.base import CollectorContext
from shadowtrace_agent.collectors.windows.usb import UsbCollector, parse_usbstor_id


class Capture:
    def __init__(self) -> None:
        self.events: list[dict] = []

    def __call__(self, category, action, data=None, user=None, ts=None) -> None:
        self.events.append({"action": action, **(data or {})})


def test_parse_usbstor_id_extracts_vendor_product_serial():
    pnp = r"USBSTOR\DISK&VEN_SANDISK&PROD_ULTRA&REV_1.00\4C530001071129117362&0"
    result = parse_usbstor_id(pnp)
    assert result["vendor"] == "SANDISK"
    assert result["product"] == "ULTRA"
    assert result["revision"] == "1.00"
    assert result["serial"] == "4C530001071129117362"


def test_parse_usbstor_id_handles_missing_data():
    assert parse_usbstor_id(None)["serial"] is None
    assert parse_usbstor_id("garbage")["vendor"] is None


def make_collector(tmp_path):
    return UsbCollector(
        UsbCollector.Options(), Capture(), CollectorContext(tmp_path / "agent-data")
    )


def test_connect_then_disconnect(tmp_path, monkeypatch):
    collector = make_collector(tmp_path)
    capture = collector.emit
    drives = {"E:"}
    monkeypatch.setattr(
        "shadowtrace_agent.collectors.windows.usb.removable_mountpoints",
        lambda: {d + "\\" for d in drives},
    )
    monkeypatch.setattr(
        "shadowtrace_agent.collectors.windows.usb._volume_details",
        lambda drive: {"label": "KINGSTON", "filesystem": "FAT32", "size_bytes": 1000},
    )

    collector.poll(
        drive_info={"E:": {"serial": "SER123", "model": "Kingston DT", "vendor": "KINGSTON"}}
    )
    drives.clear()
    collector.poll(drive_info={})

    assert [e["action"] for e in capture.events] == ["device_connected", "device_disconnected"]
    connected = capture.events[0]
    assert connected["drive"] == "E:" and connected["serial"] == "SER123"
    assert connected["label"] == "KINGSTON"
    assert capture.events[1]["serial"] == "SER123"


def test_drive_present_at_startup_is_not_reported(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "shadowtrace_agent.collectors.windows.usb.removable_mountpoints", lambda: {"E:\\"}
    )
    collector = make_collector(tmp_path)
    collector._present = {"E:": {}}  # as run() seeds it

    collector.poll(drive_info={})

    assert collector.emit.events == []
