"""Tests run against a real MongoDB (local install or the CI service container)."""

import os
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta

import httpx
import pytest

from app.core.config import Settings, get_settings
from app.core.db import init_db
from app.core.security import ENROLLMENT_TOKEN_PREFIX, generate_token, hash_token
from app.detection.engine import get_engine
from app.main import app
from app.models import EnrollmentToken


@pytest.fixture(autouse=True)
async def db(monkeypatch) -> AsyncIterator[None]:
    settings = Settings(
        mongo_url=os.environ.get(
            "ST_TEST_MONGO_URL", "mongodb://127.0.0.1:27017/?serverSelectionTimeoutMS=3000"
        ),
        mongo_db="shadowtrace_test_" + uuid.uuid4().hex,
    )
    monkeypatch.setenv("ST_MONGO_URL", settings.mongo_url)
    monkeypatch.setenv("ST_MONGO_DB", settings.mongo_db)
    monkeypatch.setenv("ST_NOTIFICATIONS_ENABLED", "false")
    monkeypatch.setenv("ST_AUTO_RESPONSE_ENABLED", "false")
    monkeypatch.setenv("ST_TELEGRAM_CONTROLS_ENABLED", "false")
    monkeypatch.setenv("ST_SESSION_COOKIE_SECURE", "false")
    get_settings.cache_clear()
    get_engine.cache_clear()
    client = await init_db(settings)
    try:
        yield
    finally:
        await client.drop_database(settings.mongo_db)
        await client.close()
        get_settings.cache_clear()
        get_engine.cache_clear()


@pytest.fixture
async def api() -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        yield client


async def make_enrollment_token(max_uses: int = 1, hours: float = 1) -> str:
    token = generate_token(ENROLLMENT_TOKEN_PREFIX)
    await EnrollmentToken(
        token_hash=hash_token(token),
        expires_at=datetime.now(UTC) + timedelta(hours=hours),
        max_uses=max_uses,
    ).insert()
    return token


async def enroll(api: httpx.AsyncClient, token: str | None = None) -> dict:
    token = token or await make_enrollment_token()
    response = await api.post(
        "/api/v1/agents/enroll",
        json={
            "enrollment_token": token,
            "hostname": "LAB-PC-01",
            "os": "windows",
            "os_version": "Windows-11-10.0.26200",
            "agent_version": "0.1.0",
        },
    )
    assert response.status_code == 201, response.text
    return response.json()
