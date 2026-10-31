import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from app import __version__
from app.api import agents, auth, dashboard, events
from app.core.config import get_settings
from app.core.db import init_db
from app.detection.engine import get_engine
from app.detection.service import detection_loop
from app.notify.dispatcher import notification_loop
from app.notify.telegram import telegram_loop
from app.web.routes import ROOT
from app.web.routes import router as web_router


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    settings = get_settings()
    if settings.detection_enabled:
        get_engine()  # invalid YAML/list references fail startup before accepting events
    client = await init_db(settings)
    stop = asyncio.Event()
    tasks = []
    if settings.detection_enabled:
        tasks.append(asyncio.create_task(detection_loop(stop)))
    if settings.notifications_enabled:
        tasks.append(asyncio.create_task(notification_loop(stop)))
    if settings.telegram_controls_enabled:
        tasks.append(asyncio.create_task(telegram_loop(stop)))
    try:
        yield
    finally:
        stop.set()
        await asyncio.gather(*tasks)
        await client.close()


app = FastAPI(title="ShadowTrace EDR", version=__version__, lifespan=lifespan)
app.include_router(agents.router, prefix="/api/v1")
app.include_router(events.router, prefix="/api/v1")
app.include_router(auth.router, prefix="/api/v1")
app.include_router(dashboard.router, prefix="/api/v1")
app.include_router(web_router)
app.mount("/assets", StaticFiles(directory=ROOT / "static"), name="assets")


@app.middleware("http")
async def browser_headers(request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "same-origin"
    if request.url.path.startswith(("/api/v1/auth", "/api/v1/ui", "/reports")):
        response.headers["Cache-Control"] = "no-store"
    if request.url.path in {"/", "/login"} or request.url.path.startswith(("/assets", "/reports")):
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
            "connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'none'; "
            "frame-ancestors 'none'; form-action 'self'"
        )
    return response


@app.get("/api/v1/health", tags=["meta"])
async def health() -> dict[str, str]:
    return {"status": "ok", "version": __version__}
