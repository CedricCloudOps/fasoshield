"""Core data models shared by the scan engine, the CLI and the API."""

from __future__ import annotations

import enum
from datetime import datetime, timezone

from pydantic import BaseModel, Field


class Verdict(str, enum.Enum):
    CLEAN = "CLEAN"
    SUSPICIOUS = "SUSPICIOUS"
    MALICIOUS = "MALICIOUS"
    ERROR = "ERROR"


class Severity(str, enum.Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


# Score contributed by each severity level when computing the global risk score.
SEVERITY_WEIGHTS = {
    Severity.INFO: 0,
    Severity.LOW: 10,
    Severity.MEDIUM: 25,
    Severity.HIGH: 45,
    Severity.CRITICAL: 100,
}

# Global score thresholds for the final verdict.
SUSPICIOUS_THRESHOLD = 30
MALICIOUS_THRESHOLD = 70


class Finding(BaseModel):
    """A single detection or observation produced by one of the engine layers."""

    rule_id: str
    title: str
    severity: Severity
    category: str  # signature | yara | permission | certificate | impersonation | manifest
    description: str
    evidence: str | None = None


class ApkFacts(BaseModel):
    """Facts extracted by static analysis, consumed by the heuristics layer."""

    package_name: str | None = None
    app_name: str | None = None
    version_name: str | None = None
    version_code: str | None = None
    min_sdk: int | None = None
    target_sdk: int | None = None
    debuggable: bool = False
    permissions: list[str] = Field(default_factory=list)
    exported_components: list[str] = Field(default_factory=list)
    cert_sha256: str | None = None
    cert_issuer: str | None = None
    cert_subject: str | None = None
    cert_self_signed: bool = False
    is_valid_apk: bool = False
    parse_error: str | None = None


class ScanReport(BaseModel):
    """Full result of a scan, serialisable as JSON for the CLI and the API."""

    sha256: str
    file_name: str
    file_size: int
    scanned_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    engine_version: str
    signature_db_version: str | None = None
    verdict: Verdict
    score: int
    threat_name: str | None = None
    facts: ApkFacts | None = None
    findings: list[Finding] = Field(default_factory=list)

    @property
    def is_detection(self) -> bool:
        return self.verdict in (Verdict.SUSPICIOUS, Verdict.MALICIOUS)


def compute_verdict(findings: list[Finding]) -> tuple[Verdict, int]:
    """Derive the global verdict from individual findings.

    A CRITICAL finding (signature hit, confirmed impersonation) is enough to
    classify the sample as MALICIOUS on its own; otherwise severities are
    accumulated and compared to fixed thresholds.
    """
    score = sum(SEVERITY_WEIGHTS[f.severity] for f in findings)
    score = min(score, 100)
    if any(f.severity == Severity.CRITICAL for f in findings) or score >= MALICIOUS_THRESHOLD:
        return Verdict.MALICIOUS, score
    if score >= SUSPICIOUS_THRESHOLD:
        return Verdict.SUSPICIOUS, score
    return Verdict.CLEAN, score
