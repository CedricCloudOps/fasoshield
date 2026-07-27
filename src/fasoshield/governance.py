"""Signature lifecycle: proposal, review, publication.

Nothing is written to the national blocklist directly. An indicator travels
through this workflow first:

    DRAFT ──submit──> REVIEW ──approve──> PUBLISHED
                        │
                        └──reject───> REJECTED

The reviewer must be a different person from the proposer — a false positive
on a mobile money application would cut thousands of users off from their
funds, so no single analyst can push an indicator to the field alone. Every
transition is written to the audit trail.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from .accounts import record_audit
from .db.models import SignatureProposal
from .engine.hashdb import HashDB
from .security import Role

DRAFT = "DRAFT"
REVIEW = "REVIEW"
PUBLISHED = "PUBLISHED"
REJECTED = "REJECTED"

INDICATOR_TYPES = ("sha256", "cert_sha256")
_HEX64 = re.compile(r"^[0-9a-fA-F]{64}$")


class GovernanceError(ValueError):
    """A workflow rule was violated (bad transition, self-approval, ...)."""


def create_proposal(
    db: Session,
    actor: str,
    indicator_type: str,
    value: str,
    threat_name: str,
    source: str,
    justification: str,
    client_ip: str | None = None,
) -> SignatureProposal:
    if indicator_type not in INDICATOR_TYPES:
        raise GovernanceError(f"indicator_type must be one of {INDICATOR_TYPES}")
    value = value.strip().lower()
    if not _HEX64.match(value):
        raise GovernanceError("Indicator value must be a 64-character hexadecimal digest")
    if not threat_name.strip():
        raise GovernanceError("threat_name is required")
    if len(justification.strip()) < 20:
        # A publishable indicator has to carry enough context for a reviewer
        # to make a decision without re-doing the whole analysis.
        raise GovernanceError("justification must describe the evidence (20 characters minimum)")

    proposal = SignatureProposal(
        indicator_type=indicator_type,
        value=value,
        threat_name=threat_name.strip(),
        source=source.strip() or "analyst",
        justification=justification.strip(),
        status=DRAFT,
        created_by=actor,
    )
    db.add(proposal)
    db.commit()
    record_audit(
        db,
        actor=actor,
        action="signature.propose",
        target=str(proposal.id),
        detail={"type": indicator_type, "value": value, "threat": proposal.threat_name},
        client_ip=client_ip,
    )
    return proposal


def submit_for_review(
    db: Session,
    actor: str,
    proposal_id: int,
    actor_role: Role,
    client_ip: str | None = None,
) -> SignatureProposal:
    proposal = _require(db, proposal_id)
    if proposal.status != DRAFT:
        raise GovernanceError(
            f"Only a DRAFT proposal can be submitted (current: {proposal.status})"
        )
    if proposal.created_by != actor and actor_role is not Role.ADMIN:
        raise GovernanceError("Only the author or an administrator can submit this proposal")

    proposal.status = REVIEW
    proposal.submitted_at = datetime.now(timezone.utc)
    db.commit()
    record_audit(
        db,
        actor=actor,
        action="signature.submit",
        target=str(proposal.id),
        client_ip=client_ip,
    )
    return proposal


def approve(
    db: Session,
    actor: str,
    proposal_id: int,
    hashdb: HashDB,
    note: str | None = None,
    client_ip: str | None = None,
) -> SignatureProposal:
    """Approve and publish: the indicator lands in the blocklist and reaches
    agents at their next delta synchronisation."""
    proposal = _require(db, proposal_id)
    if proposal.status != REVIEW:
        raise GovernanceError(
            f"Only a proposal under REVIEW can be approved (current: {proposal.status})"
        )
    if proposal.created_by == actor:
        raise GovernanceError(
            "Four-eyes rule: the proposal must be approved by a different analyst"
        )

    _publish(hashdb, proposal)

    proposal.status = PUBLISHED
    proposal.reviewed_by = actor
    proposal.reviewed_at = datetime.now(timezone.utc)
    proposal.review_note = note
    db.commit()
    record_audit(
        db,
        actor=actor,
        action="signature.publish",
        target=str(proposal.id),
        detail={
            "type": proposal.indicator_type,
            "value": proposal.value,
            "threat": proposal.threat_name,
            "proposed_by": proposal.created_by,
            "signature_db_version": hashdb.version(),
        },
        client_ip=client_ip,
    )
    return proposal


def reject(
    db: Session,
    actor: str,
    proposal_id: int,
    note: str,
    client_ip: str | None = None,
) -> SignatureProposal:
    proposal = _require(db, proposal_id)
    if proposal.status != REVIEW:
        raise GovernanceError(
            f"Only a proposal under REVIEW can be rejected (current: {proposal.status})"
        )
    if proposal.created_by == actor:
        raise GovernanceError(
            "Four-eyes rule: the proposal must be reviewed by a different analyst"
        )
    if not note.strip():
        raise GovernanceError("A rejection must carry a reason")

    proposal.status = REJECTED
    proposal.reviewed_by = actor
    proposal.reviewed_at = datetime.now(timezone.utc)
    proposal.review_note = note.strip()
    db.commit()
    record_audit(
        db,
        actor=actor,
        action="signature.reject",
        target=str(proposal.id),
        detail={"reason": proposal.review_note},
        client_ip=client_ip,
    )
    return proposal


def list_proposals(
    db: Session, status: str | None = None, limit: int = 100
) -> list[SignatureProposal]:
    query = select(SignatureProposal).order_by(SignatureProposal.id.desc()).limit(limit)
    if status:
        query = query.where(SignatureProposal.status == status.upper())
    return list(db.execute(query).scalars())


def workflow_counts(db: Session) -> dict[str, int]:
    """Proposal count per status, used by the console header."""
    counts = {DRAFT: 0, REVIEW: 0, PUBLISHED: 0, REJECTED: 0}
    from sqlalchemy import func

    for status, count in db.execute(
        select(SignatureProposal.status, func.count()).group_by(SignatureProposal.status)
    ).all():
        counts[status] = count
    return counts


def _publish(hashdb: HashDB, proposal: SignatureProposal) -> None:
    """Write an approved indicator into the distribution database."""
    source = f"{proposal.source}/reviewed"
    if proposal.indicator_type == "sha256":
        hashdb.add(proposal.value, proposal.threat_name, source=source)
    else:
        # A certificate IOC has no file hash of its own. It is stored under a
        # synthetic key so the row can carry the certificate for agent-side
        # matching, while never colliding with a real sample hash.
        hashdb.add(
            _certificate_row_key(proposal.value),
            proposal.threat_name,
            source=source,
            cert_sha256=proposal.value,
        )


def _certificate_row_key(cert_sha256: str) -> str:
    """Deterministic 64-hex key derived from a certificate hash.

    Agents and the engine match certificate IOCs on the cert_sha256 column,
    never on this key; it exists only to satisfy the blocklist's primary key.
    The namespace prefix makes a collision with a genuine sample digest
    computationally infeasible.
    """
    import hashlib

    return hashlib.sha256(f"fasoshield:cert:{cert_sha256}".encode()).hexdigest()


def _require(db: Session, proposal_id: int) -> SignatureProposal:
    proposal = db.get(SignatureProposal, proposal_id)
    if proposal is None:
        raise GovernanceError(f"Unknown proposal {proposal_id}")
    return proposal
