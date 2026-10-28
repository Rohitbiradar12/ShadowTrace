from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field

from shadowtrace_agent.osinfo import default_data_dir


class UploadConfig(BaseModel):
    batch_size: int = Field(500, ge=1, le=1000)
    interval_seconds: float = Field(2.0, gt=0)


class AgentConfig(BaseModel):
    server_url: str = "http://127.0.0.1:8000"
    # True, False, or a path to a CA bundle (for a self-signed lab server certificate).
    verify_tls: bool | str = True
    data_dir: Path | None = None
    enrollment_token: str | None = None
    heartbeat_interval_seconds: float = Field(10.0, gt=0)
    max_buffered_events: int = Field(100_000, ge=1000)
    log_level: str = "INFO"
    upload: UploadConfig = Field(default_factory=UploadConfig)
    # Per-collector options keyed by collector name; each collector validates its own section.
    collectors: dict[str, dict[str, Any]] = Field(default_factory=dict)

    @property
    def resolved_data_dir(self) -> Path:
        return self.data_dir or default_data_dir()


def load_config(path: Path) -> AgentConfig:
    if not path.exists():
        return AgentConfig()
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    config = AgentConfig.model_validate(raw)
    # Relative data_dir is resolved against the config file, not the working directory.
    if config.data_dir is not None and not config.data_dir.is_absolute():
        config.data_dir = (path.parent / config.data_dir).resolve()
    return config
