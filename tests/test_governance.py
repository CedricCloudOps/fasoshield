"""Signature review workflow: transitions, four-eyes rule, publication."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from fasoshield import governance
from fasoshield.engine.hashdb import HashDB

from .conftest import login, make_analyst

JUSTIFICATION = (
    "Clone d'Orange Money diffusé par WhatsApp : capture le PIN saisi et "
    "l'exfiltre vers un serveur de commande."
)


@pytest.fixture()
def client(isolated_settings):
    from fasoshield.api.main import app

    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture()
def hashdb_at(isolated_settings) -> HashDB:
    from fasoshield.api.deps import get_hashdb

    return get_hashdb()


def _propose(db, actor="alice", value="a" * 64, indicator_type="sha256"):
    return governance.create_proposal(
        db,
        actor=actor,
        indicator_type=indicator_type,
        value=value,
        threat_name="Trojan.FakeOM",
        source="cert-bf",
        justification=JUSTIFICATION,
    )


# -- service layer ---------------------------------------------------------


def test_proposal_starts_as_draft(db_session):
    proposal = _propose(db_session)
    assert proposal.status == governance.DRAFT
    assert proposal.created_by == "alice"


def test_indicator_value_must_be_a_digest(db_session):
    with pytest.raises(governance.GovernanceError):
        _propose(db_session, value="pas-un-hash")


def test_justification_must_be_substantial(db_session):
    """A reviewer has to be able to decide without redoing the analysis."""
    with pytest.raises(governance.GovernanceError):
        governance.create_proposal(
            db_session,
            actor="alice",
            indicator_type="sha256",
            value="a" * 64,
            threat_name="Trojan.FakeOM",
            source="cert-bf",
            justification="rien",
        )


def test_unknown_indicator_type_rejected(db_session):
    with pytest.raises(governance.GovernanceError):
        _propose(db_session, indicator_type="domain")


def test_cannot_approve_a_draft(db_session, hashdb_at):
    proposal = _propose(db_session)
    with pytest.raises(governance.GovernanceError):
        governance.approve(db_session, "bob", proposal.id, hashdb_at)


def test_four_eyes_rule_blocks_self_approval(db_session, hashdb_at):
    from fasoshield.security import Role

    proposal = _propose(db_session, actor="alice")
    governance.submit_for_review(db_session, "alice", proposal.id, Role.ANALYST)
    with pytest.raises(governance.GovernanceError, match="Four-eyes"):
        governance.approve(db_session, "alice", proposal.id, hashdb_at)


def test_four_eyes_rule_blocks_self_rejection(db_session):
    from fasoshield.security import Role

    proposal = _propose(db_session, actor="alice")
    governance.submit_for_review(db_session, "alice", proposal.id, Role.ANALYST)
    with pytest.raises(governance.GovernanceError, match="Four-eyes"):
        governance.reject(db_session, "alice", proposal.id, note="doublon")


def test_approval_publishes_to_the_blocklist(db_session, hashdb_at):
    from fasoshield.security import Role

    proposal = _propose(db_session, actor="alice")
    governance.submit_for_review(db_session, "alice", proposal.id, Role.ANALYST)
    published = governance.approve(db_session, "bob", proposal.id, hashdb_at, note="confirmé")

    assert published.status == governance.PUBLISHED
    assert published.reviewed_by == "bob"
    hit = hashdb_at.lookup("a" * 64)
    assert hit is not None
    assert hit["threat_name"] == "Trojan.FakeOM"
    assert hit["source"].endswith("/reviewed")


def test_certificate_indicator_is_published_for_agent_matching(db_session, hashdb_at):
    """A certificate IOC must be findable by certificate, which is what the
    on-device scanner has available without hashing the whole APK."""
    from fasoshield.security import Role

    cert = "c" * 64
    proposal = _propose(db_session, actor="alice", value=cert, indicator_type="cert_sha256")
    governance.submit_for_review(db_session, "alice", proposal.id, Role.ANALYST)
    governance.approve(db_session, "bob", proposal.id, hashdb_at)

    hit = hashdb_at.lookup_cert(cert)
    assert hit is not None
    assert hit["cert_sha256"] == cert
    # It must not masquerade as a file hash.
    assert hashdb_at.lookup(cert) is None


def test_rejection_requires_a_reason(db_session):
    from fasoshield.security import Role

    proposal = _propose(db_session, actor="alice")
    governance.submit_for_review(db_session, "alice", proposal.id, Role.ANALYST)
    with pytest.raises(governance.GovernanceError):
        governance.reject(db_session, "bob", proposal.id, note="   ")


def test_rejected_proposal_never_reaches_the_blocklist(db_session, hashdb_at):
    from fasoshield.security import Role

    proposal = _propose(db_session, actor="alice")
    governance.submit_for_review(db_session, "alice", proposal.id, Role.ANALYST)
    governance.reject(db_session, "bob", proposal.id, note="faux positif : app officielle")
    assert hashdb_at.lookup("a" * 64) is None


def test_transitions_are_audited(db_session, hashdb_at):
    from fasoshield.accounts import recent_audit
    from fasoshield.security import Role

    proposal = _propose(db_session, actor="alice")
    governance.submit_for_review(db_session, "alice", proposal.id, Role.ANALYST)
    governance.approve(db_session, "bob", proposal.id, hashdb_at)

    actions = [event.action for event in recent_audit(db_session)]
    assert {"signature.propose", "signature.submit", "signature.publish"} <= set(actions)


def test_workflow_counts(db_session):
    _propose(db_session, value="a" * 64)
    _propose(db_session, value="b" * 64)
    counts = governance.workflow_counts(db_session)
    assert counts[governance.DRAFT] == 2
    assert counts[governance.PUBLISHED] == 0


def test_only_author_or_admin_submits(db_session):
    from fasoshield.security import Role

    proposal = _propose(db_session, actor="alice")
    with pytest.raises(governance.GovernanceError):
        governance.submit_for_review(db_session, "bob", proposal.id, Role.ANALYST)
    # An administrator may unblock a colleague's draft.
    governance.submit_for_review(db_session, "bob", proposal.id, Role.ADMIN)
    assert db_session.get(type(proposal), proposal.id).status == governance.REVIEW


# -- HTTP surface ----------------------------------------------------------


def test_viewer_cannot_propose(client, db_session):
    make_analyst(db_session, "watcher", role="viewer")
    login(client, "watcher")
    response = client.post(
        "/v1/signatures/proposals",
        json={
            "value": "a" * 64,
            "threat_name": "Trojan.FakeOM",
            "justification": JUSTIFICATION,
        },
    )
    assert response.status_code == 403


def test_anonymous_cannot_list_proposals(client):
    assert client.get("/v1/signatures/proposals").status_code == 401


def test_full_workflow_over_http(client, db_session):
    make_analyst(db_session, "alice")
    make_analyst(db_session, "bob")

    login(client, "alice")
    created = client.post(
        "/v1/signatures/proposals",
        json={
            "value": "d" * 64,
            "threat_name": "Spy.SmsThief",
            "source": "cert-bf",
            "justification": JUSTIFICATION,
        },
    )
    assert created.status_code == 201
    proposal_id = created.json()["id"]
    assert client.post(f"/v1/signatures/proposals/{proposal_id}/submit").status_code == 200
    # Alice cannot approve her own proposal.
    assert (
        client.post(
            f"/v1/signatures/proposals/{proposal_id}/approve", json={"note": "ok"}
        ).status_code
        == 409
    )

    login(client, "bob")
    approved = client.post(
        f"/v1/signatures/proposals/{proposal_id}/approve", json={"note": "confirmé"}
    )
    assert approved.status_code == 200
    assert approved.json()["status"] == "PUBLISHED"

    # The indicator now reaches agents through the normal delta channel.
    updates = client.get("/v1/signatures/updates", params={"since": "0"}).json()
    assert "d" * 64 in [entry["sha256"] for entry in updates["entries"]]


def test_filter_proposals_by_status(client, db_session):
    make_analyst(db_session, "alice")
    login(client, "alice")
    for value in ("a" * 64, "b" * 64):
        client.post(
            "/v1/signatures/proposals",
            json={"value": value, "threat_name": "T", "justification": JUSTIFICATION},
        )
    drafts = client.get("/v1/signatures/proposals", params={"status": "DRAFT"}).json()
    published = client.get("/v1/signatures/proposals", params={"status": "PUBLISHED"}).json()
    assert len(drafts) == 2
    assert published == []
