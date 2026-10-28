import pytest
from pydantic import ValidationError

from shadowtrace_agent.collectors import build_collectors, collector_classes


def noop_emit(*args, **kwargs) -> None:
    pass


@pytest.mark.parametrize("os_name", ["windows", "linux", "macos"])
def test_every_platform_loads_common_collectors(os_name):
    names = {cls.name for cls in collector_classes(os_name)}
    assert "process" in names


def test_windows_adds_its_own_collectors():
    names = {cls.name for cls in collector_classes("windows")}
    assert {"process", "eventlog", "usb", "wifi"} <= names


def test_windows_only_collectors_are_absent_on_linux():
    names = {cls.name for cls in collector_classes("linux")}
    assert "eventlog" not in names and "usb" not in names


def test_disabled_collector_is_not_built():
    built = build_collectors({"process": {"enabled": False}}, noop_emit, "windows")
    names = {c.name for c in built}
    assert "process" not in names  # disabled
    assert "eventlog" in names  # still enabled


def test_collector_options_are_validated():
    with pytest.raises(ValidationError):
        build_collectors({"process": {"poll_interval_seconds": 0.01}}, noop_emit, "windows")


def test_unknown_option_is_rejected():
    with pytest.raises(ValidationError):
        build_collectors({"process": {"poll_intervall": 1}}, noop_emit, "windows")
