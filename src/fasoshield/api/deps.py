"""Shared FastAPI dependencies: engine singleton, DB session, agent auth."""

from __future__ import annotations

from functools import lru_cache

from fastapi import Depends, Header, HTTPException, status

from ..config import settings
from ..db.session import get_session
from ..engine.hashdb import HashDB
from ..engine.scanner import ScanEngine
from ..engine.yara_scanner import YaraScanner


@lru_cache(maxsize=1)
def get_hashdb() -> HashDB:
    return HashDB(settings.hashdb_path)


@lru_cache(maxsize=1)
def get_scan_engine() -> ScanEngine:
    return ScanEngine(hashdb=get_hashdb(), yara_scanner=YaraScanner(settings.yara_dir))


def get_db():
    session = get_session()
    try:
        yield session
    finally:
        session.close()


def require_api_key(x_api_key: str = Header(default="")) -> None:
    """Agent authentication. When no key is configured the API runs in open
    dev mode; production deployments must set FASOSHIELD_API_KEYS."""
    keys = settings.api_key_set
    if not keys:
        return
    if x_api_key not in keys:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key",
        )


AuthDep = Depends(require_api_key)
