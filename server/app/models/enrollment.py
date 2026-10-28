from datetime import UTC, datetime
from typing import Annotated

from beanie import Document, Indexed
from pydantic import Field
from pymongo import IndexModel


class EnrollmentToken(Document):
    token_hash: Annotated[str, Indexed(unique=True)]
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    expires_at: datetime
    # A lab or café can enroll many PCs with one token by raising max_uses.
    max_uses: int = 1
    uses: int = 0
    note: str | None = None

    class Settings:
        name = "enrollment_tokens"
        indexes = [IndexModel("expires_at", expireAfterSeconds=0)]
