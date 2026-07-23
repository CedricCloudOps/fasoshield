"""Scan pipeline orchestration.

Order of the layers, from cheapest to most expensive:

1. SHA-256 lookup against the national blocklist (known samples);
2. YARA rule set over the raw archive content;
3. Androguard static analysis (manifest, permissions, certificate);
4. Behavioural heuristics on the extracted facts.

The pipeline always completes: a corrupt or non-APK file still produces a
report (hash + YARA verdict) so the platform can classify arbitrary payloads
submitted by agents or analysts.
"""

from __future__ import annotations

import hashlib
import zipfile
from pathlib import Path

from .. import __version__
from .hashdb import HashDB
from .models import Finding, ScanReport, Severity, Verdict, compute_verdict
from .static_apk import analyze_apk
from .yara_scanner import YaraScanner

_CHUNK = 1024 * 1024


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(_CHUNK), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _dedupe(findings: list[Finding]) -> list[Finding]:
    """Keep one finding per rule (the same YARA rule may fire on the archive
    and on several DEX entries)."""
    seen: set[str] = set()
    unique: list[Finding] = []
    for finding in findings:
        if finding.rule_id not in seen:
            seen.add(finding.rule_id)
            unique.append(finding)
    return unique


class ScanEngine:
    # DEX entries larger than this are truncated before the in-memory YARA
    # pass to bound memory usage on hostile inputs.
    MAX_DEX_BYTES = 64 * 1024 * 1024

    def __init__(self, hashdb: HashDB, yara_scanner: YaraScanner) -> None:
        self.hashdb = hashdb
        self.yara = yara_scanner

    def _scan_dex_entries(self, path: Path) -> list[Finding]:
        findings: list[Finding] = []
        try:
            with zipfile.ZipFile(path) as archive:
                dex_names = [n for n in archive.namelist() if n.endswith(".dex") and "/" not in n]
                for name in dex_names[:10]:  # multidex apps rarely exceed this
                    with archive.open(name) as entry:
                        data = entry.read(self.MAX_DEX_BYTES)
                    findings.extend(self.yara.scan_bytes(data, context=name))
        except (zipfile.BadZipFile, OSError):
            pass  # corrupt archive: the raw-file YARA pass already ran
        return findings

    def scan_file(self, path: Path, file_name: str | None = None) -> ScanReport:
        path = Path(path)
        sha256 = sha256_file(path)
        findings: list[Finding] = []
        threat_name: str | None = None

        # Layer 1: known-sample lookup.
        hit = self.hashdb.lookup(sha256)
        if hit:
            threat_name = hit["threat_name"]
            findings.append(
                Finding(
                    rule_id="sig.hash_blocklist",
                    title="Known malicious sample",
                    severity=Severity.CRITICAL,
                    category="signature",
                    description=f"SHA-256 matches {threat_name} "
                    f"(source: {hit['source']}).",
                    evidence=sha256,
                )
            )

        # Layer 2: YARA on the raw file, then on extracted DEX entries —
        # classes.dex is DEFLATE-compressed inside the APK, so bytecode
        # strings are only visible after extraction.
        findings.extend(self.yara.scan_file(path))

        facts = None
        if zipfile.is_zipfile(path):
            findings.extend(self._scan_dex_entries(path))
            # Layers 3 and 4 only make sense for APK containers.
            facts = analyze_apk(path)
            from .heuristics import run_heuristics

            findings.extend(run_heuristics(facts, self.hashdb))
        findings = _dedupe(findings)

        verdict, score = compute_verdict(findings)
        if threat_name is None and verdict is Verdict.MALICIOUS:
            # Name the threat after the strongest non-signature detection.
            top = max(findings, key=lambda f: (f.severity == Severity.CRITICAL, f.rule_id))
            threat_name = top.rule_id

        return ScanReport(
            sha256=sha256,
            file_name=file_name or path.name,
            file_size=path.stat().st_size,
            engine_version=__version__,
            signature_db_version=self.hashdb.version(),
            verdict=verdict,
            score=score,
            threat_name=threat_name,
            facts=facts,
            findings=findings,
        )
