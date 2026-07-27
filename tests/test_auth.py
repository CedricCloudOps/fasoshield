"""Analyst identity: password hashing, sessions, roles and the audit trail."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from fasoshield.accounts import (
    AccountError,
    authenticate,
    close_session,
    create_account,
    open_session,
    purge_expired_sessions,
    resolve_session,
    set_active,
    set_password,
)
from fasoshield.db.models import AnalystSession
from fasoshield.security import (
    PasswordPolicyError,
    Role,
    hash_password,
    hash_token,
    verify_password,
)

from .conftest import login, make_analyst


@pytest.fixture()
def client(isolated_settings):
    from fasoshield.api.main import app

    with TestClient(app) as test_client:
        yield test_client


# -- password hashing ------------------------------------------------------


def test_password_roundtrip():
    stored = hash_password("un-mot-de-passe-solide")
    assert stored.startswith("scrypt$")
    assert verify_password("un-mot-de-passe-solide", stored)
    assert not verify_password("un-mot-de-passe-solidf", stored)


def test_same_password_hashes_differently():
    """Distinct salts: two analysts sharing a password must not be visible as
    such in the database."""
    assert hash_password("mot-de-passe-commun") != hash_password("mot-de-passe-commun")


def test_short_password_rejected():
    with pytest.raises(PasswordPolicyError):
        hash_password("court")


def test_malformed_digest_denies_access_without_raising():
    assert verify_password("peu importe", "not-a-digest") is False


# -- roles -----------------------------------------------------------------


def test_role_ordering():
    assert Role.ADMIN.covers(Role.ANALYST)
    assert Role.ANALYST.covers(Role.VIEWER)
    assert not Role.VIEWER.covers(Role.ANALYST)


# -- accounts and sessions -------------------------------------------------


def test_duplicate_account_rejected(db_session):
    make_analyst(db_session, "alice")
    with pytest.raises(AccountError):
        make_analyst(db_session, "alice")


def test_authenticate_rejects_disabled_account(db_session):
    password = make_analyst(db_session, "bob")
    assert authenticate(db_session, "bob", password) is not None
    set_active(db_session, "bob", False)
    assert authenticate(db_session, "bob", password) is None


def test_authenticate_unknown_user_returns_none(db_session):
    assert authenticate(db_session, "ghost", "whatever-password") is None


def test_session_token_is_never_stored_in_clear(db_session):
    make_analyst(db_session, "carol")
    token = open_session(db_session, "carol")
    assert db_session.get(AnalystSession, token) is None  # the raw token is not a key
    assert db_session.get(AnalystSession, hash_token(token)) is not None
    assert resolve_session(db_session, token).username == "carol"


def test_password_change_revokes_live_sessions(db_session):
    make_analyst(db_session, "dave")
    token = open_session(db_session, "dave")
    set_password(db_session, "dave", "nouveau-mot-de-passe")
    assert resolve_session(db_session, token) is None


def test_expired_session_is_rejected_and_purged(db_session, monkeypatch):
    from fasoshield.config import settings

    make_analyst(db_session, "erin")
    monkeypatch.setattr(settings, "session_ttl_minutes", -1)  # already expired
    token = open_session(db_session, "erin")
    assert resolve_session(db_session, token) is None
    assert db_session.get(AnalystSession, hash_token(token)) is None


def test_purge_expired_sessions_counts_removals(db_session, monkeypatch):
    from fasoshield.config import settings

    make_analyst(db_session, "frank")
    monkeypatch.setattr(settings, "session_ttl_minutes", -1)
    open_session(db_session, "frank")
    monkeypatch.setattr(settings, "session_ttl_minutes", 60)
    open_session(db_session, "frank")
    assert purge_expired_sessions(db_session) == 1


def test_close_session_is_idempotent(db_session):
    make_analyst(db_session, "grace")
    token = open_session(db_session, "grace")
    close_session(db_session, token)
    close_session(db_session, token)
    assert resolve_session(db_session, token) is None


# -- HTTP surface ----------------------------------------------------------


def test_login_sets_httponly_cookie_and_me_reports_role(client, db_session):
    make_analyst(db_session, "helen", role="admin")
    response = client.post(
        "/v1/auth/login", json={"username": "helen", "password": "Correct-Horse-42"}
    )
    assert response.status_code == 200
    cookie_header = response.headers["set-cookie"].lower()
    assert "httponly" in cookie_header  # unreadable from JavaScript
    assert "samesite=lax" in cookie_header  # not sent on cross-site POSTs

    me = client.get("/v1/auth/me").json()
    assert me == {
        "username": "helen",
        "display_name": "helen",
        "role": "admin",
        "authenticated": True,
    }


def test_login_failure_is_uniform(client, db_session):
    """Wrong password and unknown user must be indistinguishable, otherwise
    the endpoint enumerates console operators."""
    make_analyst(db_session, "ivan")
    wrong = client.post("/v1/auth/login", json={"username": "ivan", "password": "mauvais-mdp!!"})
    unknown = client.post(
        "/v1/auth/login", json={"username": "nobody", "password": "mauvais-mdp!!"}
    )
    assert wrong.status_code == unknown.status_code == 401
    assert wrong.json() == unknown.json()


def test_me_without_session_is_anonymous_not_an_error(client):
    body = client.get("/v1/auth/me").json()
    assert body["authenticated"] is False


def test_logout_invalidates_the_session(client, db_session):
    make_analyst(db_session, "judy")
    login(client, "judy")
    assert client.get("/v1/auth/me").json()["authenticated"] is True
    assert client.post("/v1/auth/logout").status_code == 204
    assert client.get("/v1/auth/me").json()["authenticated"] is False


def test_viewer_cannot_reach_admin_endpoints(client, db_session):
    make_analyst(db_session, "karl", role="viewer")
    login(client, "karl")
    assert client.get("/v1/accounts").status_code == 403


def test_admin_can_create_and_disable_accounts(client, db_session):
    make_analyst(db_session, "root", role="admin")
    login(client, "root")

    created = client.post(
        "/v1/accounts",
        json={"username": "newbie", "password": "un-mot-de-passe-long", "role": "analyst"},
    )
    assert created.status_code == 201
    assert created.json()["role"] == "analyst"

    disabled = client.patch("/v1/accounts/newbie", json={"is_active": False})
    assert disabled.status_code == 200
    assert disabled.json()["is_active"] is False


def test_admin_cannot_disable_themselves(client, db_session):
    """Locking out the last administrator would leave the console
    unrecoverable without database surgery."""
    make_analyst(db_session, "root", role="admin")
    login(client, "root")
    assert client.patch("/v1/accounts/root", json={"is_active": False}).status_code == 409


def test_weak_password_rejected_by_the_api(client, db_session):
    make_analyst(db_session, "root", role="admin")
    login(client, "root")
    response = client.post(
        "/v1/accounts", json={"username": "weak", "password": "short", "role": "viewer"}
    )
    assert response.status_code == 422


def test_login_events_are_audited(client, db_session):
    make_analyst(db_session, "liam", role="admin")
    client.post("/v1/auth/login", json={"username": "liam", "password": "wrong-password-x"})
    login(client, "liam")

    actions = [event["action"] for event in client.get("/v1/audit").json()]
    assert "auth.login" in actions
    assert "auth.login_failed" in actions


def test_sso_header_mode_grants_a_role(client, isolated_settings, monkeypatch):
    """Behind an OIDC gateway the API trusts a header instead of a cookie."""
    monkeypatch.setattr(isolated_settings, "sso_user_header", "X-Auth-User")
    monkeypatch.setattr(isolated_settings, "sso_role_header", "X-Auth-Role")
    body = client.get(
        "/v1/auth/me", headers={"X-Auth-User": "mia", "X-Auth-Role": "analyst"}
    ).json()
    assert body["authenticated"] is True
    assert body["role"] == "analyst"


def test_sso_header_ignored_when_not_configured(client):
    """Without the setting, forging the header must grant nothing."""
    body = client.get("/v1/auth/me", headers={"X-Auth-User": "mallory"}).json()
    assert body["authenticated"] is False


def test_account_creation_requires_admin(client, db_session):
    make_analyst(db_session, "nina", role="analyst")
    login(client, "nina")
    response = client.post(
        "/v1/accounts", json={"username": "x", "password": "un-mot-de-passe-long"}
    )
    assert response.status_code == 403


def test_unknown_account_update_is_404(client, db_session):
    make_analyst(db_session, "root", role="admin")
    login(client, "root")
    assert client.patch("/v1/accounts/ghost", json={"role": "viewer"}).status_code == 404


def test_create_account_conflict(client, db_session):
    make_analyst(db_session, "root", role="admin")
    make_analyst(db_session, "taken")
    login(client, "root")
    response = client.post(
        "/v1/accounts", json={"username": "taken", "password": "un-mot-de-passe-long"}
    )
    assert response.status_code == 409


def test_created_account_carries_its_role(db_session):
    account = create_account(
        db_session, "olga", "un-mot-de-passe-long", Role.ANALYST, display_name="Olga K."
    )
    assert account.role == "analyst"
    assert account.display_name == "Olga K."
    assert account.is_active is True
