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


# -- SOC console -----------------------------------------------------------


class VerdictCount(BaseModel):
    verdict: str
    count: int


class NamedCount(BaseModel):
    label: str
    count: int


class TimelinePoint(BaseModel):
    date: str
    count: int


class SignatureStatsOut(BaseModel):
    version: str
    blocklist: int
    official_apps: int


class CorpusStatsOut(BaseModel):
    samples: int
    detections: int
    verdicts: list[VerdictCount]


class FieldStatsOut(BaseModel):
    events: int
    agents: int
    detections: int
    by_region: list[NamedCount]
    top_threats: list[NamedCount]
    timeline: list[TimelinePoint]


class RecentDetection(BaseModel):
    created_at: datetime
    verdict: str | None = None
    threat_name: str | None = None
    package_name: str | None = None
    region: str | None = None


class StatsOverview(BaseModel):
    generated_at: datetime
    signatures: SignatureStatsOut
    corpus: CorpusStatsOut
    field: FieldStatsOut
    recent_detections: list[RecentDetection]
