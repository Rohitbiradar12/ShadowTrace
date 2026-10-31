from datetime import UTC, datetime
from typing import Annotated, Any, Literal

from beanie import Document, Indexed
from pydantic import Field
from pymongo import IndexModel

Role = Literal["admin", "analyst", "viewer"]


class User(Document):
    username: Annotated[str, Indexed(unique=True)]
    password_hash: str
    role: Role = "viewer"
    disabled: bool = False
    session_version: int = 0
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    last_login: datetime | None = None

    class Settings:
        name = "users"


class Session(Document):
    token_hash: Annotated[str, Indexed(unique=True)]
    username: str
    version: int
    csrf_token: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    expires_at: datetime

    class Settings:
        name = "sessions"
        indexes = [IndexModel([("expires_at", 1)], expireAfterSeconds=0), "username"]


class LoginBucket(Document):
    key: Annotated[str, Indexed(unique=True)]
    attempts: int = 0
    expires_at: datetime

    class Settings:
        name = "login_buckets"
        indexes = [IndexModel([("expires_at", 1)], expireAfterSeconds=0)]


class AuditEntry(Document):
    actor: str
    action: str
    target: str
    details: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    class Settings:
        name = "audit_entries"
        indexes = [IndexModel([("created_at", -1)])]
