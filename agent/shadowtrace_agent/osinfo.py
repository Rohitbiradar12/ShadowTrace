import getpass
import os
import sys
from pathlib import Path
from typing import Literal

import psutil

OsName = Literal["windows", "linux", "macos"]


def current_os() -> OsName:
    if sys.platform == "win32":
        return "windows"
    if sys.platform == "darwin":
        return "macos"
    return "linux"


def default_data_dir(os_name: OsName | None = None) -> Path:
    match os_name or current_os():
        case "windows":
            return Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData")) / "ShadowTrace"
        case "macos":
            return Path("/Library/Application Support/ShadowTrace")
        case _:
            return Path("/var/lib/shadowtrace")


def current_user() -> str | None:
    """The logged-in user, formatted like psutil's process usernames (DOMAIN\\user on Windows)."""
    if current_os() == "windows":
        user = os.environ.get("USERNAME")
        domain = os.environ.get("USERDOMAIN")
        return f"{domain}\\{user}" if user and domain else user
    try:
        return getpass.getuser()
    except Exception:
        return None


def user_folders() -> dict[str, Path]:
    """Desktop, Documents and Downloads — following OneDrive/folder redirection on Windows."""
    home = Path.home()
    folders = {
        "desktop": home / "Desktop",
        "documents": home / "Documents",
        "downloads": home / "Downloads",
    }
    if current_os() == "windows":
        import winreg

        registry_names = {
            "desktop": "Desktop",
            "documents": "Personal",
            "downloads": "{374DE290-123F-4565-9164-39C4925E467B}",
        }
        key_path = r"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path) as key:
                for label, value_name in registry_names.items():
                    try:
                        value, _ = winreg.QueryValueEx(key, value_name)
                        folders[label] = Path(os.path.expandvars(value))
                    except OSError:
                        pass
        except OSError:
            pass
    return folders


def removable_mountpoints() -> set[str]:
    """Mount points of removable drives (USB sticks, SD cards), e.g. {'E:\\'}."""
    try:
        partitions = psutil.disk_partitions(all=False)
    except OSError:
        return set()
    return {p.mountpoint for p in partitions if "removable" in p.opts}


def is_removable_path(path: str) -> bool:
    if current_os() == "windows":
        if len(path) < 2 or path[1] != ":":
            return False
        import ctypes

        drive_removable = 2
        return ctypes.windll.kernel32.GetDriveTypeW(f"{path[0]}:\\") == drive_removable
    return any(path.startswith(m) for m in removable_mountpoints() if m != "/")
