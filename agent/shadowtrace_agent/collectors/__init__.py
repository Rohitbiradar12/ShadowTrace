"""Platform-aware collector registry.

``common`` holds collectors that work everywhere (psutil, watchdog, sqlite). Each OS package
(``windows``, ``linux``, ``macos``) adds collectors that need OS-specific APIs. Adding Linux
support means filling ``linux.COLLECTORS`` — nothing else changes.
"""

import logging
from importlib import import_module
from typing import Any

from shadowtrace_agent.collectors.base import Collector, CollectorContext
from shadowtrace_agent.osinfo import OsName, current_os
from shadowtrace_agent.schema import Emit

log = logging.getLogger(__name__)


def collector_classes(os_name: OsName) -> list[type[Collector]]:
    packages = [import_module(f"{__name__}.common"), import_module(f"{__name__}.{os_name}")]
    return [cls for pkg in packages for cls in pkg.COLLECTORS if os_name in cls.platforms]


def build_collectors(
    config: dict[str, dict[str, Any]],
    emit: Emit,
    os_name: OsName | None = None,
    context: CollectorContext | None = None,
) -> list[Collector]:
    classes = collector_classes(os_name or current_os())
    known = {cls.name for cls in classes}
    for name in config.keys() - known:
        log.warning("Collector %r is configured but not available on this platform", name)

    enabled = [cls for cls in classes if (config.get(cls.name) or {}).get("enabled", True)]
    return [cls.from_config(config.get(cls.name), emit, context) for cls in enabled]
