"""API request/response contracts (agent-facing)."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field

from ..engine.models import Verdict


class ReputationResponse(BaseModel):
    sha256: str
    known: bool
    verdict: Verdict | None = None
    threat_name: str | None = None
    source: str | None = None  # blocklist | scan-history
    signature_db_version: str


class SignatureVersionResponse(BaseModel):
    version: str
    blocklist_entries: int
    official_apps: int


class SignatureEntry(BaseModel):
    sha256: str
    threat_name: str
    source: str
    added_at: str


class SignatureUpdateResponse(BaseModel):
    since: str
    version: str
    entries: list[SignatureEntry]


class TelemetryIn(BaseModel):
    agent_id: str = Field(min_length=8, max_length=64)  # opaque UUID, no device identifier
    event_type: str = Field(pattern="^(detection|scan_summary)$")
    sha256: str | None = Field(default=None, min_length=64, max_length=64)
    package_name: str | None = Field(default=None, max_length=255)
    verdict: Verdict | None = None
    threat_name: str | None = Field(default=None, max_length=255)
    region: str | None = Field(default=None, max_length=64)


class TelemetryAck(BaseModel):
    accepted: bool
    received_at: datetime
