from __future__ import annotations

from fastapi import APIRouter, Depends

from ... import __version__
from ...engine.hashdb import HashDB
from ..deps import get_hashdb

router = APIRouter(tags=["health"])


@router.get("/health")
def health(hashdb: HashDB = Depends(get_hashdb)) -> dict:
    stats = hashdb.stats()
    return {
        "status": "ok",
        "engine_version": __version__,
        "signature_db_version": stats["version"],
        "blocklist_entries": stats["blocklist"],
    }
