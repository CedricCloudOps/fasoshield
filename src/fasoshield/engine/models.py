"""Core data models shared by the scan engine, the CLI and the API."""

from __future__ import annotations

import enum
from datetime import datetime, timezone
from typing import Optional

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
    evidence: Optional[str] = None


class ApkFacts(BaseModel):
    """Facts extracted by static analysis, consumed by the heuristics layer."""

    package_name: Optional[str] = None
    app_name: Optional[str] = None
    version_name: Optional[str] = None
    version_code: Optional[str] = None
    min_sdk: Optional[int] = None
    target_sdk: Optional[int] = None
    debuggable: bool = False
    permissions: list[str] = Field(default_factory=list)
    exported_components: list[str] = Field(default_factory=list)
    cert_sha256: Optional[str] = None
    cert_issuer: Optional[str] = None
    cert_subject: Optional[str] = None
    cert_self_signed: bool = False
    is_valid_apk: bool = False
    parse_error: Optional[str] = None


class ScanReport(BaseModel):
    """Full result of a scan, serialisable as JSON for the CLI and the API."""

    sha256: str
    file_name: str
    file_size: int
    scanned_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    engine_version: str
    signature_db_version: Optional[str] = None
    verdict: Verdict
    score: int
    threat_name: Optional[str] = None
    facts: Optional[ApkFacts] = None
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
