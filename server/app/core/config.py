from functools import lru_cache
from pathlib import Path

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="ST_", env_file=".env", extra="ignore")

    mongo_url: str = "mongodb://localhost:27017"
    mongo_db: str = "shadowtrace"
    max_batch_events: int = 1000
    heartbeat_interval_seconds: int = 10
    session_hours: int = Field(8, ge=1, le=24)
    session_cookie_secure: bool = False  # Set true behind HTTPS outside a localhost demo.
    public_url: str = "http://127.0.0.1:8000"
    detection_enabled: bool = True
    rules_dir: Path = Path(__file__).resolve().parents[3] / "rules"
    intel_file: Path = Path(__file__).resolve().parents[3] / "intel" / "lists.yaml"
    alert_dedup_seconds: int = Field(600, ge=1)
    detection_poll_seconds: float = Field(2.0, gt=0)
    auto_response_enabled: bool = False
    auto_response_max_event_age_seconds: int = Field(60, ge=1, le=300)
    # Explicitly enabled after destinations have been configured by the operator.
    notifications_enabled: bool = False
    notifications_per_minute: int = Field(5, ge=1, le=60)
    notification_max_attempts: int = Field(5, ge=1, le=20)
    telegram_bot_token: SecretStr = SecretStr("")
    telegram_chat_id: str = ""
    telegram_controls_enabled: bool = False
    telegram_allowed_user_ids: list[int] = Field(default_factory=list)
    telegram_button_minutes: int = Field(60, ge=1, le=1440)
    smtp_host: str = ""
    smtp_port: int = Field(587, ge=1, le=65535)
    smtp_username: str = ""
    smtp_password: SecretStr = SecretStr("")
    smtp_from: str = ""
    smtp_to: str = ""
    smtp_ssl: bool = False
    smtp_starttls: bool = True


@lru_cache
def get_settings() -> Settings:
    return Settings()
