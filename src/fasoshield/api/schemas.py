"""API request/response contracts (agent-facing)."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field

from ..engine.models import ScanReport, Verdict


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
    # Present when the indicator is expressed at signing-certificate
    # granularity; this is what the on-device scanner matches against.
    cert_sha256: str | None = None


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


class WorkflowCounts(BaseModel):
    DRAFT: int = 0
    REVIEW: int = 0
    PUBLISHED: int = 0
    REJECTED: int = 0


class StatsOverview(BaseModel):
    generated_at: datetime
    signatures: SignatureStatsOut
    corpus: CorpusStatsOut
    field: FieldStatsOut
    recent_detections: list[RecentDetection]
    workflow: WorkflowCounts = Field(default_factory=WorkflowCounts)


# -- analyst identity ------------------------------------------------------


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)


class SessionInfo(BaseModel):
    username: str
    display_name: str
    role: str
    authenticated: bool


class AccountCreate(BaseModel):
    username: str = Field(min_length=1, max_length=64, pattern=r"^[a-zA-Z0-9._-]+$")
    password: str = Field(min_length=12, max_length=256)
    role: str = Field(default="viewer", pattern="^(viewer|analyst|admin)$")
    display_name: str | None = Field(default=None, max_length=128)


class AccountUpdate(BaseModel):
    password: str | None = Field(default=None, min_length=12, max_length=256)
    role: str | None = Field(default=None, pattern="^(viewer|analyst|admin)$")
    is_active: bool | None = None


class AccountOut(BaseModel):
    username: str
    display_name: str
    role: str
    is_active: bool
    created_at: datetime
    last_login_at: datetime | None = None


class AuditEventOut(BaseModel):
    id: int
    actor: str
    action: str
    target: str | None = None
    detail: str | None = None
    client_ip: str | None = None
    created_at: datetime


# -- signature governance --------------------------------------------------


class ProposalCreate(BaseModel):
    indicator_type: str = Field(default="sha256", pattern="^(sha256|cert_sha256)$")
    value: str = Field(min_length=64, max_length=64, pattern="^[0-9a-fA-F]{64}$")
    threat_name: str = Field(min_length=1, max_length=255)
    source: str = Field(default="analyst", max_length=64)
    justification: str = Field(min_length=20, max_length=4000)


class ProposalReview(BaseModel):
    note: str | None = Field(default=None, max_length=2000)


class ProposalOut(BaseModel):
    id: int
    indicator_type: str
    value: str
    threat_name: str
    source: str
    justification: str
    status: str
    created_by: str
    created_at: datetime
    submitted_at: datetime | None = None
    reviewed_by: str | None = None
    reviewed_at: datetime | None = None
    review_note: str | None = None


# -- deferred scanning -----------------------------------------------------


class ScanJobOut(BaseModel):
    id: str
    file_name: str
    file_size: int
    status: str
    sha256: str | None = None
    verdict: str | None = None
    error: str | None = None
    created_at: datetime
    started_at: datetime | None = None
    finished_at: datetime | None = None
    # Populated once the job reaches DONE; the full engine report.
    report: ScanReport | None = None
