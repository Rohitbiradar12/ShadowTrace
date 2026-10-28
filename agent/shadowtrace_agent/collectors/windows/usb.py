"""USB removable-storage monitor (Windows, WMI via win32com).

Detects a USB stick being plugged in or removed by watching removable drive letters, then
enriches each connect with the disk's serial, model and vendor/product from WMI. The deck's
"unauthorized USB device": the emitted serial lets a rule allow known drives and alert on the
rest. No admin rights required.
"""

import logging
import re
import threading
from typing import Any

from pydantic import Field

from shadowtrace_agent.collectors.base import Collector, CollectorContext, CollectorOptions
from shadowtrace_agent.osinfo import removable_mountpoints
from shadowtrace_agent.schema import Category

log = logging.getLogger(__name__)

# USBSTOR\DISK&VEN_SANDISK&PROD_ULTRA&REV_1.00\<serial>&0
_USBSTOR_RE = re.compile(
    r"VEN_(?P<vendor>[^&\\]*)&PROD_(?P<product>[^&\\]*)(?:&REV_(?P<revision>[^&\\]*))?",
    re.IGNORECASE,
)


def _clean(value: str | None) -> str | None:
    return value.replace("_", " ").strip() if value else None


def parse_usbstor_id(pnp_device_id: str | None) -> dict[str, str | None]:
    """Pull vendor, product, revision and serial out of a USBSTOR PNPDeviceID."""
    if not pnp_device_id:
        return {"vendor": None, "product": None, "revision": None, "serial": None}
    match = _USBSTOR_RE.search(pnp_device_id)
    parts = pnp_device_id.split("\\")
    serial = parts[-1].split("&")[0] if len(parts) >= 3 else None
    return {
        "vendor": _clean(match.group("vendor")) if match else None,
        "product": _clean(match.group("product")) if match else None,
        "revision": _clean(match.group("revision")) if match else None,
        "serial": serial or None,
    }


def _drive_key(mountpoint: str) -> str:
    return mountpoint.rstrip("\\").upper()  # "E:\\" -> "E:"


class UsbCollector(Collector):
    name = "usb"
    platforms = frozenset({"windows"})

    class Options(CollectorOptions):
        poll_interval_seconds: float = Field(3.0, ge=0.5)

    options: Options

    def __init__(self, options: Options, emit, context: CollectorContext | None = None) -> None:
        super().__init__(options, emit, context)
        self._present: dict[str, dict[str, Any]] = {}

    def run(self, stop: threading.Event) -> None:
        import pythoncom

        pythoncom.CoInitialize()
        try:
            # Drives already connected at startup are remembered, not reported.
            self._present = {_drive_key(m): {} for m in removable_mountpoints()}
            log.info("USB monitor started (%d removable drive(s) present)", len(self._present))
            while not stop.is_set():
                self.poll()
                stop.wait(self.options.poll_interval_seconds)
        finally:
            pythoncom.CoUninitialize()

    def poll(self, drive_info: dict[str, dict[str, Any]] | None = None) -> None:
        current = {_drive_key(m) for m in removable_mountpoints()}
        added = current - self._present.keys()
        removed = self._present.keys() - current
        info_map = drive_info if drive_info is not None else (usb_disk_info() if added else {})

        for drive in sorted(added):
            info = info_map.get(drive, {})
            self._present[drive] = info
            self.emit(
                Category.USB,
                "device_connected",
                {"drive": drive, **_volume_details(drive), **info},
            )
        for drive in sorted(removed):
            info = self._present.pop(drive, {})
            self.emit(
                Category.USB,
                "device_disconnected",
                {"drive": drive, "serial": info.get("serial"), "model": info.get("model")},
            )


def _volume_details(drive: str) -> dict[str, Any]:
    details: dict[str, Any] = {"label": None, "filesystem": None, "size_bytes": None}
    try:
        import win32api

        info = win32api.GetVolumeInformation(drive + "\\")
        details["label"] = info[0] or None
        details["filesystem"] = info[4] or None
    except Exception:
        pass
    try:
        import psutil

        details["size_bytes"] = psutil.disk_usage(drive + "\\").total
    except Exception:
        pass
    return details


def usb_disk_info() -> dict[str, dict[str, Any]]:
    """Map each USB drive letter (e.g. 'E:') to its disk serial, model and vendor/product."""
    try:
        import win32com.client
    except ImportError:
        return {}
    try:
        wmi = win32com.client.GetObject("winmgmts:")
        drives: dict[str, dict[str, Any]] = {}
        for disk in wmi.InstancesOf("Win32_DiskDrive"):
            if (getattr(disk, "InterfaceType", "") or "").upper() != "USB":
                continue
            ids = parse_usbstor_id(getattr(disk, "PNPDeviceID", None))
            info = {
                "serial": (getattr(disk, "SerialNumber", None) or ids["serial"] or "").strip()
                or None,
                "model": (getattr(disk, "Model", None) or "").strip() or None,
                "vendor": ids["vendor"],
                "product": ids["product"],
                "pnp_device_id": getattr(disk, "PNPDeviceID", None),
            }
            for letter in _logical_disks_for(wmi, disk.DeviceID):
                drives[letter] = info
        return drives
    except Exception as exc:  # pragma: no cover - needs real WMI
        log.debug("WMI USB lookup failed: %s", exc)
        return {}


def _logical_disks_for(wmi, disk_device_id: str) -> list[str]:
    letters: list[str] = []
    devid = disk_device_id.replace("\\", "\\\\")
    partition_query = (
        f'ASSOCIATORS OF {{Win32_DiskDrive.DeviceID="{devid}"}} '
        "WHERE AssocClass=Win32_DiskDriveToDiskPartition"
    )
    for partition in wmi.ExecQuery(partition_query):
        pdevid = partition.DeviceID.replace("\\", "\\\\")
        logical_query = (
            f'ASSOCIATORS OF {{Win32_DiskPartition.DeviceID="{pdevid}"}} '
            "WHERE AssocClass=Win32_LogicalDiskToPartition"
        )
        for logical in wmi.ExecQuery(logical_query):
            letters.append(logical.DeviceID.upper())
    return letters
