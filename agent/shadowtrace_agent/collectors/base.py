import json
import threading
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Any, ClassVar

from pydantic import BaseModel, ConfigDict

from shadowtrace_agent.osinfo import OsName, default_data_dir
from shadowtrace_agent.schema import Emit

ALL_PLATFORMS: frozenset[OsName] = frozenset({"windows", "linux", "macos"})


class CollectorOptions(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = True


@dataclass(frozen=True)
class CollectorContext:
    """What a collector may know about the agent it runs in."""

    data_dir: Path


class Collector(ABC):
    """A monitor that watches one kind of activity and emits OS-neutral events.

    Subclasses set ``name`` (the key of their section under ``collectors:`` in the config),
    the ``platforms`` they support, and an ``Options`` model for their settings.
    """

    name: ClassVar[str]
    platforms: ClassVar[frozenset[OsName]] = ALL_PLATFORMS
    Options: ClassVar[type[CollectorOptions]] = CollectorOptions

    def __init__(
        self, options: CollectorOptions, emit: Emit, context: CollectorContext | None = None
    ) -> None:
        self.options = options
        self.emit = emit
        self.context = context or CollectorContext(default_data_dir())

    @abstractmethod
    def run(self, stop: threading.Event) -> None:
        """Monitor until ``stop`` is set. Sleep with ``stop.wait()`` so shutdown is prompt."""

    @classmethod
    def from_config(
        cls, raw: dict[str, Any] | None, emit: Emit, context: CollectorContext | None = None
    ) -> "Collector":
        return cls(cls.Options.model_validate(raw or {}), emit, context)

    # Small JSON state file per collector, e.g. the last event-log record already reported,
    # so a restart neither re-sends old activity nor skips what happened while stopped.
    def load_state(self) -> dict[str, Any]:
        path = self._state_path()
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}

    def save_state(self, state: dict[str, Any]) -> None:
        path = self._state_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(state), encoding="utf-8")
        tmp.replace(path)

    def _state_path(self) -> Path:
        return self.context.data_dir / "collectors" / f"{self.name}.json"
