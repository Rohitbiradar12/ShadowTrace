"""Argon2 passwords, revocable server-side sessions, CSRF and bounded login attempts."""

import asyncio
import re
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Annotated
from urllib.parse import urlsplit

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from fastapi import Depends, HTTPException, Request
from pymongo import ReturnDocument
from pymongo.errors import DuplicateKeyError

from app.core.config import get_settings
from app.core.security import hash_token
from app.models.user import AuditEntry, LoginBucket, Role, Session, User

COOKIE = "st_session"
PASSWORDS = PasswordHasher()
DUMMY_HASH = PASSWORDS.hash(secrets.token_urlsafe(32))


def normalize_username(value: str) -> str:
    value = value.strip().lower()
    if not re.fullmatch(r"[a-z0-9][a-z0-9_.-]{2,63}", value):
        raise ValueError("Username must be 3..64 letters, numbers, dots, dashes or underscores")
    return value


def validate_password(value: str) -> str:
    if not 12 <= len(value) <= 128:
        raise ValueError("Use a password containing 12..128 characters")
    return value


async def create_user(username: str, password: str, role: Role, actor: str) -> User:
    username = normalize_username(username)
    validate_password(password)
    user = User(
        username=username,
        password_hash=await asyncio.to_thread(PASSWORDS.hash, password),
        role=role,
    )
    try:
        await user.insert()
    except DuplicateKeyError as exc:
        raise ValueError("Username already exists") from exc
    await AuditEntry(
        actor=actor, action="user_created", target=username, details={"role": role}
    ).insert()
    return user


def verify_password(encoded: str, password: str) -> bool:
    try:
        return PASSWORDS.verify(encoded, password)
    except (VerificationError, InvalidHashError):
        return False


def require_same_origin(request: Request) -> None:
    origin = request.headers.get("origin")
    if origin:
        try:
            actual = urlsplit(origin)
        except ValueError as exc:
            raise HTTPException(403, "Cross-origin request rejected") from exc
        expected = urlsplit(str(request.base_url))
        if (actual.scheme, actual.netloc) != (expected.scheme, expected.netloc):
            raise HTTPException(403, "Cross-origin request rejected")
    if request.headers.get("sec-fetch-site") == "cross-site":
        raise HTTPException(403, "Cross-site request rejected")


async def limit_login(request: Request, username: str) -> None:
    now = datetime.now(UTC)
    window = int(now.timestamp()) // 900
    ip = request.client.host if request.client else "unknown"
    for scope, limit in (("ip:" + ip, 30), ("user:" + username, 10)):
        key = hash_token(f"{scope}:{window}")
        row = await LoginBucket.get_pymongo_collection().find_one_and_update(
            {"key": key},
            {
                "$inc": {"attempts": 1},
                "$setOnInsert": {
                    "expires_at": datetime.fromtimestamp((window + 1) * 900, UTC),
                },
            },
            upsert=True,
            return_document=ReturnDocument.AFTER,
        )
        if row["attempts"] > limit:
            raise HTTPException(
                429,
                "Too many login attempts. Try again later.",
                headers={"Retry-After": str((window + 1) * 900 - int(now.timestamp()))},
            )


@dataclass
class Principal:
    user: User
    session: Session

    @property
    def actor(self) -> str:
        return "user:" + self.user.username


async def authenticated(request: Request) -> Principal:
    token = request.cookies.get(COOKIE, "")
    if not token or len(token) > 256:
        raise HTTPException(401, "Sign in to continue")
    session = await Session.find_one(
        Session.token_hash == hash_token(token), Session.expires_at > datetime.now(UTC)
    )
    if session is None:
        raise HTTPException(401, "Session expired. Sign in again.")
    user = await User.find_one(User.username == session.username)
    if user is None or user.disabled or user.session_version != session.version:
        raise HTTPException(401, "Session revoked. Sign in again.")
    if request.method not in {"GET", "HEAD", "OPTIONS"}:
        require_same_origin(request)
        supplied_csrf = request.headers.get("x-csrf-token", "")
        if len(supplied_csrf) > 256 or not secrets.compare_digest(
            supplied_csrf.encode(), session.csrf_token.encode()
        ):
            raise HTTPException(403, "Invalid request token. Refresh the page.")
    return Principal(user, session)


CurrentUser = Annotated[Principal, Depends(authenticated)]


async def operator(principal: CurrentUser) -> Principal:
    if principal.user.role not in {"admin", "analyst"}:
        raise HTTPException(403, "An analyst or administrator role is required")
    return principal


async def administrator(principal: CurrentUser) -> Principal:
    if principal.user.role != "admin":
        raise HTTPException(403, "An administrator role is required")
    return principal


Operator = Annotated[Principal, Depends(operator)]
Administrator = Annotated[Principal, Depends(administrator)]


async def new_session(user: User) -> tuple[str, Session]:
    token = secrets.token_urlsafe(32)
    session = Session(
        token_hash=hash_token(token),
        username=user.username,
        version=user.session_version,
        csrf_token=secrets.token_urlsafe(32),
        expires_at=datetime.now(UTC) + timedelta(hours=get_settings().session_hours),
    )
    await session.insert()
    return token, session


def public_user(user: User) -> dict:
    return user.model_dump(
        mode="json", include={"username", "role", "disabled", "created_at", "last_login"}
    )
