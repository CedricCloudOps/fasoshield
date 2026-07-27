"""SOC console: analyst dashboard and its backing statistics endpoint.

The dashboard and its data are analyst-authenticated: agent API keys, which
live on thousands of handsets, must never open the national threat picture.
The HTML page itself is served unauthenticated because it contains no data —
it renders the login form until /v1/auth/me reports a session.
"""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from ...engine.hashdb import HashDB
from .. import stats
from ..deps import ViewerDep, get_db, get_hashdb
from ..schemas import StatsOverview

router = APIRouter(tags=["console"])

_TEMPLATE = Path(__file__).resolve().parents[1] / "templates" / "console.html"


@router.get("/v1/stats/overview", response_model=StatsOverview, dependencies=[ViewerDep])
def stats_overview(
    db: Session = Depends(get_db),
    hashdb: HashDB = Depends(get_hashdb),
) -> StatsOverview:
    return StatsOverview.model_validate(stats.overview(db, hashdb))


@router.get("/console", response_class=HTMLResponse, include_in_schema=False)
def console_page(request: Request) -> HTMLResponse:
    # The strict CSP forbids inline code without a nonce; the security
    # middleware minted one for this response, so stamp it into the markup.
    nonce = getattr(request.state, "csp_nonce", "")
    html = _TEMPLATE.read_text(encoding="utf-8").replace("__CSP_NONCE__", nonce)
    return HTMLResponse(html)
