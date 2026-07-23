"""API request/response contracts (agent-facing)."""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field

from ..engine.models import Verdict


class ReputationResponse(BaseModel):
    sha256: str
    known: bool
    verdict: Optional[Verdict] = None
    threat_name: Optional[str] = None
    source: Optional[str] = None  # blocklist | scan-history
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
    sha256: Optional[str] = Field(default=None, min_length=64, max_length=64)
    package_name: Optional[str] = Field(default=None, max_length=255)
    verdict: Optional[Verdict] = None
    threat_name: Optional[str] = Field(default=None, max_length=255)
    region: Optional[str] = Field(default=None, max_length=64)


class TelemetryAck(BaseModel):
    accepted: bool
    received_at: datetime
