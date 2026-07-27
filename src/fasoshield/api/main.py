"""FasoShield platform API.

Run locally:
    uvicorn fasoshield.api.main:app --reload
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .. import __version__
from ..config import settings
from ..db.session import init_db
from ..jobs import ScanWorker
from .deps import get_quarantine, get_scan_engine
from .middleware import (
    RateLimitMiddleware,
    RequestContextMiddleware,
    SecurityHeadersMiddleware,
)
from .routes import (
    auth,
    console,
    governance,
    health,
    intel,
    reputation,
    scan,
    signatures,
    telemetry,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    # The in-process worker makes a single-server deployment self-sufficient.
    # Scaled-out installs run `fasoshield worker` in a dedicated container and
    # both drain the same table safely.
    worker = ScanWorker(engine=get_scan_engine(), quarantine=get_quarantine())
    worker.start()
    app.state.scan_worker = worker
    try:
        yield
    finally:
        worker.stop()


app = FastAPI(
    title="FasoShield API",
    description="National mobile threat analysis platform: APK scanning, "
    "hash reputation, signature distribution, agent telemetry, signature "
    "governance and CERT intelligence sharing.",
    version=__version__,
    lifespan=lifespan,
)

# Middleware order matters: Starlette runs them outermost-first, so the request
# id is assigned before anything can log or reject, and rate limiting happens
# before any route work.
app.add_middleware(RequestContextMiddleware)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(
    RateLimitMiddleware,
    per_minute=settings.rate_limit_per_minute,
    burst=settings.rate_limit_burst,
)
if settings.cors_origin_list:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origin_list,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PATCH"],
        allow_headers=["content-type", "x-api-key"],
    )

app.include_router(health.router)
app.include_router(auth.router)
app.include_router(scan.router)
app.include_router(reputation.router)
app.include_router(signatures.router)
app.include_router(telemetry.router)
app.include_router(governance.router)
app.include_router(intel.router)
app.include_router(console.router)
