"""Threat-intelligence export endpoints for partner CERTs.

Only published indicators are exported, and only to authenticated analysts —
sharing IOCs is a deliberate act, recorded in the audit trail.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from ... import intel
from ...accounts import record_audit
from ...config import settings
from ...engine.hashdb import HashDB
from ..deps import Analyst, ViewerDep, client_ip, get_db, get_hashdb

router = APIRouter(prefix="/v1/intel", tags=["intel"])


def _entries(hashdb: HashDB, since: str, limit: int) -> list[dict]:
    """Published indicators to share, newest first."""
    if since and since != "0":
        return hashdb.entries_since(since)[:limit]
    return hashdb.entries(limit=limit)


@router.get("/stix")
def export_stix(
    request: Request,
    since: str = Query(default="0", max_length=14),
    limit: int = Query(default=1000, ge=1, le=10000),
    tlp: str = Query(default=""),
    hashdb: HashDB = Depends(get_hashdb),
    db: Session = Depends(get_db),
    analyst: Analyst = ViewerDep,
) -> JSONResponse:
    """STIX 2.1 bundle of published indicators."""
    entries = _entries(hashdb, since, limit)
    bundle = intel.stix_bundle(
        entries,
        org_name=settings.intel_org_name,
        tlp=tlp or settings.intel_tlp,
    )
    record_audit(
        db,
        actor=analyst.username,
        action="intel.export_stix",
        detail={"indicators": len(entries), "since": since},
        client_ip=client_ip(request),
    )
    return JSONResponse(
        bundle,
        headers={
            "Content-Disposition": 'attachment; filename="fasoshield-stix.json"',
        },
    )


@router.get("/misp")
def export_misp(
    request: Request,
    since: str = Query(default="0", max_length=14),
    limit: int = Query(default=1000, ge=1, le=10000),
    tlp: str = Query(default=""),
    hashdb: HashDB = Depends(get_hashdb),
    db: Session = Depends(get_db),
    analyst: Analyst = ViewerDep,
) -> JSONResponse:
    """MISP event containing the published indicators."""
    entries = _entries(hashdb, since, limit)
    event = intel.misp_event(
        entries,
        org_name=settings.intel_org_name,
        tlp=tlp or settings.intel_tlp,
    )
    record_audit(
        db,
        actor=analyst.username,
        action="intel.export_misp",
        detail={"indicators": len(entries), "since": since},
        client_ip=client_ip(request),
    )
    return JSONResponse(
        event,
        headers={
            "Content-Disposition": 'attachment; filename="fasoshield-misp-event.json"',
        },
    )
