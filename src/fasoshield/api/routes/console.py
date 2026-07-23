"""SOC console: analyst dashboard and its backing statistics endpoint.

The JSON endpoint reuses the agent authentication dependency, so it is open in
dev mode and key-protected in production. A dedicated analyst identity (SSO /
role-based access for the review-and-publish workflow) is deferred to the next
phase-4 increment.
"""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from ...engine.hashdb import HashDB
from .. import stats
from ..deps import AuthDep, get_db, get_hashdb
from ..schemas import StatsOverview

router = APIRouter(tags=["console"])

_TEMPLATE = Path(__file__).resolve().parents[1] / "templates" / "console.html"


@router.get("/v1/stats/overview", response_model=StatsOverview, dependencies=[AuthDep])
def stats_overview(
    db: Session = Depends(get_db),
    hashdb: HashDB = Depends(get_hashdb),
) -> StatsOverview:
    return StatsOverview.model_validate(stats.overview(db, hashdb))


@router.get("/console", response_class=HTMLResponse, include_in_schema=False)
def console_page() -> HTMLResponse:
    return HTMLResponse(_TEMPLATE.read_text(encoding="utf-8"))
