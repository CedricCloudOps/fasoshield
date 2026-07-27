"""Persistence models.

Privacy by design: telemetry stores no direct identifier (no MSISDN, no IMEI,
no account data). Agents are identified by an opaque, self-generated UUID so
national statistics can be computed without tracking individuals.

Analyst accounts are the one place where a natural person is identified. They
exist to make signature publication accountable (who proposed, who approved)
and every analyst action is written to the audit trail.
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


class Sample(Base):
    """One row per unique file ever scanned by the platform."""

    __tablename__ = "samples"

    sha256: Mapped[str] = mapped_column(String(64), primary_key=True)
    file_name: Mapped[str] = mapped_column(String(255))
    file_size: Mapped[int] = mapped_column(Integer)
    verdict: Mapped[str] = mapped_column(String(16), index=True)
    score: Mapped[int] = mapped_column(Integer)
    threat_name: Mapped[str] = mapped_column(String(255), nullable=True)
    report_json: Mapped[str] = mapped_column(Text)
    engine_version: Mapped[str] = mapped_column(String(32))
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_scanned: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )
    scan_count: Mapped[int] = mapped_column(Integer, default=1)


class TelemetryEvent(Base):
    """Detection event reported by a mobile agent (anonymised)."""

    __tablename__ = "telemetry_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    agent_id: Mapped[str] = mapped_column(String(64), index=True)  # opaque UUID
    event_type: Mapped[str] = mapped_column(String(32))  # detection | scan_summary
    sha256: Mapped[str] = mapped_column(String(64), nullable=True, index=True)
    package_name: Mapped[str] = mapped_column(String(255), nullable=True)
    verdict: Mapped[str] = mapped_column(String(16), nullable=True)
    threat_name: Mapped[str] = mapped_column(String(255), nullable=True)
    region: Mapped[str] = mapped_column(String(64), nullable=True)  # coarse, declarative
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, index=True
    )


class AnalystAccount(Base):
    """Console operator. Distinct from agent API keys: agents are devices,
    analysts are accountable people."""

    __tablename__ = "analyst_accounts"

    username: Mapped[str] = mapped_column(String(64), primary_key=True)
    display_name: Mapped[str] = mapped_column(String(128))
    # scrypt digest, self-describing: scrypt$n$r$p$salt_hex$hash_hex.
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(16))  # viewer | analyst | admin
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_login_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True)


class AnalystSession(Base):
    """Server-side session. Only the SHA-256 of the token is stored, so a
    database read cannot be replayed as a valid session."""

    __tablename__ = "analyst_sessions"

    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    username: Mapped[str] = mapped_column(String(64), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    client_ip: Mapped[str] = mapped_column(String(64), nullable=True)


class AuditEvent(Base):
    """Append-only trail of analyst actions. Required by the signature
    governance workflow: every publication must be attributable."""

    __tablename__ = "audit_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    actor: Mapped[str] = mapped_column(String(64), index=True)
    action: Mapped[str] = mapped_column(String(64), index=True)
    target: Mapped[str] = mapped_column(String(255), nullable=True)
    detail: Mapped[str] = mapped_column(Text, nullable=True)
    client_ip: Mapped[str] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, index=True
    )


class SignatureProposal(Base):
    """A candidate indicator moving through the review workflow.

    Nothing reaches the national blocklist without passing through this table:
    DRAFT -> REVIEW -> PUBLISHED (or REJECTED), with the proposer and the
    reviewer being necessarily two different people.
    """

    __tablename__ = "signature_proposals"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    indicator_type: Mapped[str] = mapped_column(String(16))  # sha256 | cert_sha256
    value: Mapped[str] = mapped_column(String(64), index=True)
    threat_name: Mapped[str] = mapped_column(String(255))
    source: Mapped[str] = mapped_column(String(64))
    justification: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(16), index=True, default="DRAFT")
    created_by: Mapped[str] = mapped_column(String(64), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    submitted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True)
    reviewed_by: Mapped[str] = mapped_column(String(64), nullable=True)
    reviewed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True)
    review_note: Mapped[str] = mapped_column(Text, nullable=True)


class ScanJob(Base):
    """Deferred scan of a large upload.

    The table *is* the queue: workers claim a job with a conditional UPDATE, so
    several API processes can share the workload without a message broker.
    """

    __tablename__ = "scan_jobs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)  # uuid4
    file_name: Mapped[str] = mapped_column(String(255))
    file_size: Mapped[int] = mapped_column(Integer)
    staged_path: Mapped[str] = mapped_column(String(512))
    status: Mapped[str] = mapped_column(String(16), index=True, default="QUEUED")
    sha256: Mapped[str] = mapped_column(String(64), nullable=True, index=True)
    verdict: Mapped[str] = mapped_column(String(16), nullable=True)
    report_json: Mapped[str] = mapped_column(Text, nullable=True)
    error: Mapped[str] = mapped_column(Text, nullable=True)
    submitted_by: Mapped[str] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, index=True
    )
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True)
