"""Windows response primitives; verify and terminate using the same process handle."""

import ctypes
from ctypes import wintypes

EPOCH_OFFSET = 11644473600


def lock_workstation() -> None:
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    user32.LockWorkStation.argtypes = []
    user32.LockWorkStation.restype = wintypes.BOOL
    if not user32.LockWorkStation():
        raise ctypes.WinError(ctypes.get_last_error())


class WindowsProcess:
    def __init__(self, pid: int):
        self.api = ctypes.WinDLL("kernel32", use_last_error=True)
        signatures = {
            "OpenProcess": ([wintypes.DWORD, wintypes.BOOL, wintypes.DWORD], wintypes.HANDLE),
            "CloseHandle": ([wintypes.HANDLE], wintypes.BOOL),
            "QueryFullProcessImageNameW": (
                [wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)],
                wintypes.BOOL,
            ),
            "GetProcessTimes": (
                [wintypes.HANDLE] + [ctypes.POINTER(wintypes.FILETIME)] * 4,
                wintypes.BOOL,
            ),
            "IsProcessCritical": ([wintypes.HANDLE, ctypes.POINTER(wintypes.BOOL)], wintypes.BOOL),
            "TerminateProcess": ([wintypes.HANDLE, wintypes.UINT], wintypes.BOOL),
            "WaitForSingleObject": ([wintypes.HANDLE, wintypes.DWORD], wintypes.DWORD),
        }
        for name, (args, result) in signatures.items():
            function = getattr(self.api, name)
            function.argtypes, function.restype = args, result
        self.handle = self.api.OpenProcess(0x1000 | 0x0001 | 0x100000, False, pid)
        if not self.handle:
            raise ctypes.WinError(ctypes.get_last_error())

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.api.CloseHandle(self.handle)

    def identity(self) -> tuple[str, float, bool]:
        size = wintypes.DWORD(32768)
        path = ctypes.create_unicode_buffer(size.value)
        self._check(self.api.QueryFullProcessImageNameW(self.handle, 0, path, ctypes.byref(size)))
        times = [wintypes.FILETIME() for _ in range(4)]
        self._check(self.api.GetProcessTimes(self.handle, *(ctypes.byref(t) for t in times)))
        ticks = (times[0].dwHighDateTime << 32) | times[0].dwLowDateTime
        critical = wintypes.BOOL()
        self._check(self.api.IsProcessCritical(self.handle, ctypes.byref(critical)))
        return path.value, ticks / 10_000_000 - EPOCH_OFFSET, bool(critical.value)

    def terminate(self) -> None:
        self._check(self.api.TerminateProcess(self.handle, 1))
        if self.api.WaitForSingleObject(self.handle, 2000) != 0:
            raise TimeoutError("Process termination not confirmed")

    @staticmethod
    def _check(ok) -> None:
        if not ok:
            raise ctypes.WinError(ctypes.get_last_error())
