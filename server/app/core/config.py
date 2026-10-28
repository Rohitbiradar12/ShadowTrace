from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="ST_", env_file=".env", extra="ignore")

    mongo_url: str = "mongodb://localhost:27017"
    mongo_db: str = "shadowtrace"
    max_batch_events: int = 1000
    heartbeat_interval_seconds: int = 10


@lru_cache
def get_settings() -> Settings:
    return Settings()
