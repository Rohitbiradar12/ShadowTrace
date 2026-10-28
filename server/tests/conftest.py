"""Tests run against a real MongoDB (local install or the CI service container)."""

import os
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta

import httpx
import pytest

from app.core.config import Settings
from app.core.db import init_db
from app.core.security import ENROLLMENT_TOKEN_PREFIX, generate_token, hash_token
from app.main import app
from app.models import EnrollmentToken

TEST_SETTINGS = Settings(
    mongo_url=os.environ.get("ST_MONGO_URL", "mongodb://localhost:27017"),
    mongo_db="shadowtrace_test",
)


@pytest.fixture(autouse=True)
async def db() -> AsyncIterator[None]:
    client = await init_db(TEST_SETTINGS)
    await client.drop_database(TEST_SETTINGS.mongo_db)
    # Dropping removes indexes too, so initialize again to recreate them.
    await init_db(TEST_SETTINGS)
    yield
    await client.close()


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
