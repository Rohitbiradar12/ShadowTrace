"""Whole-system process snapshot in one syscall.

psutil's ppid() and create_time() each re-scan every process on Windows when the agent
cannot open the target, making a 400-process poll take seconds. NtQuerySystemInformation
returns pid, parent pid, image name and creation time for all processes at once (~1 ms).
"""

import ctypes
from ctypes import wintypes

SYSTEM_PROCESS_INFORMATION_CLASS = 5
STATUS_INFO_LENGTH_MISMATCH = 0xC0000004
# FILETIME counts 100 ns intervals since 1601-01-01; Unix time starts 1970-01-01.
EPOCH_AS_FILETIME = 116_444_736_000_000_000


class _UnicodeString(ctypes.Structure):
    _fields_ = [
        ("Length", wintypes.USHORT),
        ("MaximumLength", wintypes.USHORT),
        ("Buffer", ctypes.c_void_p),
    ]


class _SystemProcessInformation(ctypes.Structure):
    # Leading fields of SYSTEM_PROCESS_INFORMATION (winternl.h); the rest is not needed.
    _fields_ = [
        ("NextEntryOffset", wintypes.ULONG),
        ("NumberOfThreads", wintypes.ULONG),
        ("WorkingSetPrivateSize", ctypes.c_longlong),
        ("HardFaultCount", wintypes.ULONG),
        ("NumberOfThreadsHighWatermark", wintypes.ULONG),
        ("CycleTime", ctypes.c_ulonglong),
        ("CreateTime", ctypes.c_longlong),
        ("UserTime", ctypes.c_longlong),
        ("KernelTime", ctypes.c_longlong),
        ("ImageName", _UnicodeString),
        ("BasePriority", wintypes.LONG),
        ("UniqueProcessId", ctypes.c_void_p),
        ("InheritedFromUniqueProcessId", ctypes.c_void_p),
    ]


_ntdll = ctypes.WinDLL("ntdll")
_query = _ntdll.NtQuerySystemInformation
_query.argtypes = [wintypes.ULONG, ctypes.c_void_p, wintypes.ULONG, ctypes.POINTER(wintypes.ULONG)]
_query.restype = ctypes.c_ulong
_buffer_size = 1024 * 1024


def list_processes() -> list[tuple[int, int, str | None, float]]:
    """Return (pid, ppid, name, create_time) for every process."""
    global _buffer_size
    while True:
        buffer = ctypes.create_string_buffer(_buffer_size)
        needed = wintypes.ULONG()
        status = _query(
            SYSTEM_PROCESS_INFORMATION_CLASS, buffer, _buffer_size, ctypes.byref(needed)
        )
        if status == STATUS_INFO_LENGTH_MISMATCH:
            # Processes may start between calls, so leave headroom.
            _buffer_size = max(_buffer_size * 2, needed.value + 256 * 1024)
            continue
        if status != 0:
            raise OSError(f"NtQuerySystemInformation failed: 0x{status:08X}")
        break

    result = []
    base = ctypes.addressof(buffer)
    offset = 0
    while True:
        info = _SystemProcessInformation.from_address(base + offset)
        pid = info.UniqueProcessId or 0
        image = info.ImageName
        name = ctypes.wstring_at(image.Buffer, image.Length // 2) if image.Buffer else None
        create_time = (info.CreateTime - EPOCH_AS_FILETIME) / 10_000_000 if info.CreateTime else 0.0
        result.append((pid, info.InheritedFromUniqueProcessId or 0, name, create_time))
        if not info.NextEntryOffset:
            return result
        offset += info.NextEntryOffset
