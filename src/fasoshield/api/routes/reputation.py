"""Hash reputation lookup — the hot path for mobile agents.

An agent hashes every installed/newly installed APK locally and asks the
platform for a verdict before deciding to alert the user, which avoids
uploading APKs over metered mobile data plans.
"""

from __future__ import annotations

import re

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from ...db.models import Sample
from ...engine.hashdb import HashDB
from ..deps import AuthDep, get_db, get_hashdb
from ..schemas import ReputationResponse

router = APIRouter(tags=["reputation"])

_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")


@router.get("/v1/reputation/{sha256}", response_model=ReputationResponse, dependencies=[AuthDep])
def reputation(
    sha256: str,
    hashdb: HashDB = Depends(get_hashdb),
    db: Session = Depends(get_db),
) -> ReputationResponse:
    if not _SHA256_RE.match(sha256):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail="Invalid SHA-256"
        )
    sha256 = sha256.lower()
    version = hashdb.version()

    hit = hashdb.lookup(sha256)
    if hit:
        return ReputationResponse(
            sha256=sha256,
            known=True,
            verdict="MALICIOUS",
            threat_name=hit["threat_name"],
            source="blocklist",
            signature_db_version=version,
        )

    sample = db.get(Sample, sha256)
    if sample:
        return ReputationResponse(
            sha256=sha256,
            known=True,
            verdict=sample.verdict,
            threat_name=sample.threat_name,
            source="scan-history",
            signature_db_version=version,
        )

    return ReputationResponse(sha256=sha256, known=False, signature_db_version=version)
