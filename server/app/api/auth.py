import asyncio
from datetime import UTC, datetime

from fastapi import APIRouter, HTTPException, Request, Response
from pydantic import BaseModel, Field
from pymongo import ReturnDocument

from app.core.config import get_settings
from app.core.security import hash_token
from app.models.user import AuditEntry, Session, User
from app.services.auth import (
    COOKIE,
    DUMMY_HASH,
    PASSWORDS,
    CurrentUser,
    limit_login,
    new_session,
    public_user,
    require_same_origin,
    validate_password,
    verify_password,
)

router = APIRouter(prefix="/auth", tags=["dashboard authentication"])


class LoginIn(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=128)


class PasswordIn(BaseModel):
    current_password: str = Field(min_length=1, max_length=128)
    new_password: str = Field(min_length=12, max_length=128)


@router.post("/login")
async def login(body: LoginIn, request: Request, response: Response):
    require_same_origin(request)
    username = body.username.strip().lower()
    await limit_login(request, username)
    user = await User.find_one(User.username == username)
    valid = await asyncio.to_thread(
        verify_password, user.password_hash if user else DUMMY_HASH, body.password
    )
    if not valid or user is None or user.disabled:
        raise HTTPException(401, "Invalid username or password")
    changes = {"last_login": datetime.now(UTC)}
    if PASSWORDS.check_needs_rehash(user.password_hash):
        changes["password_hash"] = await asyncio.to_thread(PASSWORDS.hash, body.password)
    # Password verification yields to other requests. Never overwrite a reset password,
    # or issue a current session after the account was disabled/changed in the meantime.
    current = await User.get_pymongo_collection().find_one_and_update(
        {
            "_id": user.id,
            "password_hash": user.password_hash,
            "session_version": user.session_version,
            "disabled": False,
        },
        {"$set": changes},
        return_document=ReturnDocument.AFTER,
    )
    if current is None:
        raise HTTPException(401, "Invalid username or password")
    user = User.model_validate(current)
    old_token = request.cookies.get(COOKIE)
    if old_token:
        await Session.find(Session.token_hash == hash_token(old_token)).delete()
    token, session = await new_session(user)
    settings = get_settings()
    response.set_cookie(
        COOKIE,
        token,
        max_age=settings.session_hours * 3600,
        httponly=True,
        secure=settings.session_cookie_secure,
        samesite="strict",
    )
    await AuditEntry(actor="user:" + username, action="login", target=username).insert()
    return {"user": public_user(user), "csrf_token": session.csrf_token}


@router.get("/me")
async def me(principal: CurrentUser):
    return {"user": public_user(principal.user), "csrf_token": principal.session.csrf_token}


@router.post("/logout")
async def logout(principal: CurrentUser, response: Response):
    await principal.session.delete()
    response.delete_cookie(
        COOKIE, httponly=True, secure=get_settings().session_cookie_secure, samesite="strict"
    )
    return {"ok": True}


@router.post("/password")
async def password(body: PasswordIn, principal: CurrentUser, request: Request, response: Response):
    await limit_login(request, principal.user.username)
    if not await asyncio.to_thread(
        verify_password, principal.user.password_hash, body.current_password
    ):
        raise HTTPException(400, "Current password is incorrect")
    validate_password(body.new_password)
    replacement = await asyncio.to_thread(PASSWORDS.hash, body.new_password)
    changed = await User.get_pymongo_collection().update_one(
        {
            "_id": principal.user.id,
            "password_hash": principal.user.password_hash,
            "session_version": principal.user.session_version,
            "disabled": False,
        },
        {"$set": {"password_hash": replacement}, "$inc": {"session_version": 1}},
    )
    if not changed.modified_count:
        raise HTTPException(409, "Account changed. Sign in again before changing your password.")
    await Session.find(Session.username == principal.user.username).delete()
    response.delete_cookie(COOKIE)
    await AuditEntry(
        actor=principal.actor, action="password_changed", target=principal.user.username
    ).insert()
    return {"ok": True, "message": "Password changed. Sign in again."}
