from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from app import __version__
from app.api import agents, events
from app.core.config import get_settings
from app.core.db import init_db


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    client = await init_db(get_settings())
    yield
    await client.close()


app = FastAPI(title="ShadowTrace EDR", version=__version__, lifespan=lifespan)
app.include_router(agents.router, prefix="/api/v1")
app.include_router(events.router, prefix="/api/v1")


@app.get("/api/v1/health", tags=["meta"])
async def health() -> dict[str, str]:
    return {"status": "ok", "version": __version__}
