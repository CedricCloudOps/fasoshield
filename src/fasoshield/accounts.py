"""Analyst account, session and audit services.

Shared by the API and the CLI so that an account created from the command line
behaves exactly like one created through the console.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from .config import settings
from .db.models import AnalystAccount, AnalystSession, AuditEvent
from .security import (
    Role,
    hash_password,
    hash_token,
    new_session_token,
    session_expiry,
    verify_password,
)


class AccountError(ValueError):
    """Account operation rejected (duplicate, unknown user, weak password)."""


# -- accounts --------------------------------------------------------------


def create_account(
    db: Session,
    username: str,
    password: str,
    role: Role,
    display_name: str | None = None,
) -> AnalystAccount:
    username = username.strip().lower()
    if not username:
        raise AccountError("Username must not be empty")
    if db.get(AnalystAccount, username) is not None:
        raise AccountError(f"Account '{username}' already exists")
    account = AnalystAccount(
        username=username,
        display_name=display_name or username,
        password_hash=hash_password(password),
        role=role.value,
        is_active=True,
    )
    db.add(account)
    db.commit()
    return account


def set_password(db: Session, username: str, password: str) -> None:
    account = _require(db, username)
    account.password_hash = hash_password(password)
    # A password change invalidates every live session for that analyst.
    revoke_sessions(db, username)
    db.commit()


def set_active(db: Session, username: str, active: bool) -> None:
    account = _require(db, username)
    account.is_active = active
    if not active:
        revoke_sessions(db, username)
    db.commit()


def set_role(db: Session, username: str, role: Role) -> None:
    account = _require(db, username)
    account.role = role.value
    db.commit()


def list_accounts(db: Session) -> list[AnalystAccount]:
    return list(db.execute(select(AnalystAccount).order_by(AnalystAccount.username)).scalars())


def _require(db: Session, username: str) -> AnalystAccount:
    account = db.get(AnalystAccount, username.strip().lower())
    if account is None:
        raise AccountError(f"Unknown account '{username}'")
    return account


# -- authentication --------------------------------------------------------


def authenticate(db: Session, username: str, password: str) -> AnalystAccount | None:
    """Verify credentials. Returns None for unknown, disabled or wrong-password
    accounts — the caller must not tell them apart in its response."""
    account = db.get(AnalystAccount, (username or "").strip().lower())
    if account is None:
        # Spend comparable time on unknown users so response timing does not
        # disclose which usernames exist.
        verify_password(password, _DUMMY_HASH)
        return None
    if not verify_password(password, account.password_hash):
        return None
    if not account.is_active:
        return None
    account.last_login_at = datetime.now(timezone.utc)
    db.commit()
    return account


# Pre-computed digest of a random password, used only to equalise timing.
_DUMMY_HASH = (
    "scrypt$65536$8$1$"
    "00000000000000000000000000000000$"
    "0000000000000000000000000000000000000000000000000000000000000000"
)


def open_session(db: Session, username: str, client_ip: str | None = None) -> str:
    """Create a session and return the token to hand to the client."""
    token, digest = new_session_token()
    db.add(
        AnalystSession(
            token_hash=digest,
            username=username,
            expires_at=session_expiry(settings.session_ttl_minutes),
            client_ip=client_ip,
        )
    )
    db.commit()
    return token


def resolve_session(db: Session, token: str) -> AnalystAccount | None:
    """Return the account behind a session token, or None if the token is
    unknown, expired, or its account has since been disabled."""
    if not token:
        return None
    session = db.get(AnalystSession, hash_token(token))
    if session is None:
        return None
    if _aware(session.expires_at) <= datetime.now(timezone.utc):
        db.delete(session)
        db.commit()
        return None
    account = db.get(AnalystAccount, session.username)
    if account is None or not account.is_active:
        return None
    return account


def close_session(db: Session, token: str) -> None:
    session = db.get(AnalystSession, hash_token(token))
    if session is not None:
        db.delete(session)
        db.commit()


def revoke_sessions(db: Session, username: str) -> None:
    db.execute(delete(AnalystSession).where(AnalystSession.username == username))


def purge_expired_sessions(db: Session) -> int:
    result = db.execute(
        delete(AnalystSession).where(AnalystSession.expires_at <= datetime.now(timezone.utc))
    )
    db.commit()
    return result.rowcount or 0


def _aware(value: datetime) -> datetime:
    """SQLite hands back naive datetimes; treat them as UTC."""
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


# -- audit trail -----------------------------------------------------------


def record_audit(
    db: Session,
    actor: str,
    action: str,
    target: str | None = None,
    detail: dict | None = None,
    client_ip: str | None = None,
) -> None:
    db.add(
        AuditEvent(
            actor=actor,
            action=action,
            target=target,
            detail=json.dumps(detail, ensure_ascii=False) if detail else None,
            client_ip=client_ip,
        )
    )
    db.commit()


def recent_audit(db: Session, limit: int = 50) -> list[AuditEvent]:
    return list(
        db.execute(
            select(AuditEvent).order_by(AuditEvent.created_at.desc(), AuditEvent.id.desc())
            .limit(limit)
        ).scalars()
    )
