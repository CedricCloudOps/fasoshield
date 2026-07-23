"""Signature distribution: version check and delta updates for agents."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query

from ...engine.hashdb import HashDB
from ..deps import AuthDep, get_hashdb
from ..schemas import SignatureEntry, SignatureUpdateResponse, SignatureVersionResponse

router = APIRouter(tags=["signatures"])


@router.get(
    "/v1/signatures/version",
    response_model=SignatureVersionResponse,
    dependencies=[AuthDep],
)
def signature_version(hashdb: HashDB = Depends(get_hashdb)) -> SignatureVersionResponse:
    stats = hashdb.stats()
    return SignatureVersionResponse(
        version=stats["version"],
        blocklist_entries=stats["blocklist"],
        official_apps=stats["official_apps"],
    )


@router.get(
    "/v1/signatures/updates",
    response_model=SignatureUpdateResponse,
    dependencies=[AuthDep],
)
def signature_updates(
    since: str = Query(default="0", max_length=14),
    hashdb: HashDB = Depends(get_hashdb),
) -> SignatureUpdateResponse:
    entries = hashdb.entries_since(since)
    return SignatureUpdateResponse(
        since=since,
        version=hashdb.version(),
        entries=[SignatureEntry(**entry) for entry in entries],
    )
