"""Signature distribution: version check and delta updates for agents."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query

from ...engine.hashdb import HashDB
from ...signing import BundleSigner
from ..deps import AuthDep, get_bundle_signer, get_hashdb
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
    signer: BundleSigner | None = Depends(get_bundle_signer),
) -> SignatureUpdateResponse:
    entries = hashdb.entries_since(since)
    version = hashdb.version()
    # The bundle is signed over the version and the entries themselves, so the
    # agent's trust does not depend on how the bytes reached it.
    signature = signer.sign(version, entries) if signer else None
    return SignatureUpdateResponse(
        since=since,
        version=version,
        entries=[SignatureEntry(**entry) for entry in entries],
        signature=signature,
        key_id=signer.key_id if signer else None,
    )


@router.get("/v1/signatures/rules", dependencies=[AuthDep])
def yara_rule_manifest(hashdb: HashDB = Depends(get_hashdb)) -> dict:
    """Digest of the deployed YARA rule set.

    Agents do not run YARA on device, but analysts and the console need to know
    which rule generation a verdict came from when reviewing a detection.
    """
    from ...config import settings

    rules = sorted(path.name for path in settings.yara_dir.glob("*.yar"))
    return {
        "signature_db_version": hashdb.version(),
        "rule_files": rules,
        "rule_file_count": len(rules),
    }
