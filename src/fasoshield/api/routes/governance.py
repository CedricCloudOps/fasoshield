"""Signature review workflow, exposed to the console.

Read access requires the viewer role; proposing, submitting and reviewing
require the analyst role. The four-eyes rule is enforced in the service layer
(``fasoshield.governance``) so the CLI cannot bypass it either.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.orm import Session

from ... import governance
from ...engine.hashdb import HashDB
from ..deps import Analyst, AnalystDep, ViewerDep, client_ip, get_db, get_hashdb
from ..schemas import ProposalCreate, ProposalOut, ProposalReview

router = APIRouter(prefix="/v1/signatures/proposals", tags=["governance"])


def _out(proposal) -> ProposalOut:
    return ProposalOut.model_validate(proposal, from_attributes=True)


def _guard(call):
    """Translate a workflow violation into a 409 rather than a 500."""
    try:
        return call()
    except governance.GovernanceError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc


@router.get("", response_model=list[ProposalOut], dependencies=[ViewerDep])
def list_proposals(
    status_filter: str | None = Query(default=None, alias="status", max_length=16),
    limit: int = Query(default=100, ge=1, le=500),
    db: Session = Depends(get_db),
) -> list[ProposalOut]:
    return [_out(p) for p in governance.list_proposals(db, status=status_filter, limit=limit)]


@router.post("", response_model=ProposalOut, status_code=status.HTTP_201_CREATED)
def create_proposal(
    payload: ProposalCreate,
    request: Request,
    db: Session = Depends(get_db),
    analyst: Analyst = AnalystDep,
) -> ProposalOut:
    return _out(
        _guard(
            lambda: governance.create_proposal(
                db,
                actor=analyst.username,
                indicator_type=payload.indicator_type,
                value=payload.value,
                threat_name=payload.threat_name,
                source=payload.source,
                justification=payload.justification,
                client_ip=client_ip(request),
            )
        )
    )


@router.post("/{proposal_id}/submit", response_model=ProposalOut)
def submit(
    proposal_id: int,
    request: Request,
    db: Session = Depends(get_db),
    analyst: Analyst = AnalystDep,
) -> ProposalOut:
    return _out(
        _guard(
            lambda: governance.submit_for_review(
                db,
                actor=analyst.username,
                proposal_id=proposal_id,
                actor_role=analyst.role,
                client_ip=client_ip(request),
            )
        )
    )


@router.post("/{proposal_id}/approve", response_model=ProposalOut)
def approve(
    proposal_id: int,
    payload: ProposalReview,
    request: Request,
    db: Session = Depends(get_db),
    hashdb: HashDB = Depends(get_hashdb),
    analyst: Analyst = AnalystDep,
) -> ProposalOut:
    return _out(
        _guard(
            lambda: governance.approve(
                db,
                actor=analyst.username,
                proposal_id=proposal_id,
                hashdb=hashdb,
                note=payload.note,
                client_ip=client_ip(request),
            )
        )
    )


@router.post("/{proposal_id}/reject", response_model=ProposalOut)
def reject(
    proposal_id: int,
    payload: ProposalReview,
    request: Request,
    db: Session = Depends(get_db),
    analyst: Analyst = AnalystDep,
) -> ProposalOut:
    return _out(
        _guard(
            lambda: governance.reject(
                db,
                actor=analyst.username,
                proposal_id=proposal_id,
                note=payload.note or "",
                client_ip=client_ip(request),
            )
        )
    )
