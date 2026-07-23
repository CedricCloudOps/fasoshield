"""FasoShield platform API.

Run locally:
    uvicorn fasoshield.api.main:app --reload
"""

from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI

from .. import __version__
from ..db.session import init_db
from .routes import health, reputation, scan, signatures, telemetry


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(
    title="FasoShield API",
    description="National mobile threat analysis platform: APK scanning, "
    "hash reputation, signature distribution and agent telemetry.",
    version=__version__,
    lifespan=lifespan,
)

app.include_router(health.router)
app.include_router(scan.router)
app.include_router(reputation.router)
app.include_router(signatures.router)
app.include_router(telemetry.router)
