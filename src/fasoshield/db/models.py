"""Persistence models.

Privacy by design: telemetry stores no direct identifier (no MSISDN, no IMEI,
no account data). Agents are identified by an opaque, self-generated UUID so
national statistics can be computed without tracking individuals.
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import DateTime, Integer, String, Text
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
