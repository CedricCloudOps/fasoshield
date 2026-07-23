"""YARA layer: compiles the national rule set and scans raw file content.

Rules live in ``signatures/yara/*.yar``. Each rule is expected to declare
``meta.description`` and ``meta.severity`` (INFO/LOW/MEDIUM/HIGH/CRITICAL);
missing metadata falls back to MEDIUM so a sloppy rule never silences itself.
"""

from __future__ import annotations

from pathlib import Path

import yara

from .models import Finding, Severity


class YaraScanner:
    def __init__(self, rules_dir: Path) -> None:
        self.rules_dir = Path(rules_dir)
        self._rules = self._compile()

    def _compile(self) -> yara.Rules | None:
        sources = {
            path.stem: str(path)
            for path in sorted(self.rules_dir.glob("*.yar"))
        }
        if not sources:
            return None
        return yara.compile(filepaths=sources)

    def reload(self) -> None:
        self._rules = self._compile()

    @property
    def rule_count(self) -> int:
        return sum(1 for _ in self._rules) if self._rules else 0

    def scan_file(self, path: Path) -> list[Finding]:
        """Match rules against the raw file on disk."""
        if self._rules is None:
            return []
        return self._to_findings(self._rules.match(str(path)))

    def scan_bytes(self, data: bytes, context: str = "") -> list[Finding]:
        """Match rules against an in-memory buffer (extracted DEX entries)."""
        if self._rules is None:
            return []
        return self._to_findings(self._rules.match(data=data), context=context)

    def _to_findings(self, matches, context: str = "") -> list[Finding]:
        findings: list[Finding] = []
        for match in matches:
            meta = match.meta or {}
            try:
                severity = Severity(str(meta.get("severity", "MEDIUM")).upper())
            except ValueError:
                severity = Severity.MEDIUM
            strings_hit = sorted({s.identifier for s in match.strings})[:5]
            evidence = ", ".join(strings_hit)
            if context:
                evidence = f"[{context}] {evidence}" if evidence else f"[{context}]"
            findings.append(
                Finding(
                    rule_id=f"yara.{match.rule}",
                    title=match.rule.replace("_", " "),
                    severity=severity,
                    category="yara",
                    description=str(meta.get("description", "YARA rule match")),
                    evidence=evidence or None,
                )
            )
        return findings
