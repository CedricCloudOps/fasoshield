"""Heuristic layer: behavioural risk scoring from static facts.

Each heuristic targets a technique observed in the West-African mobile threat
landscape: OTP interception against mobile money accounts, overlay banking
trojans, sideloaded droppers and brand impersonation of financial apps.
"""

from __future__ import annotations

from difflib import SequenceMatcher

from .hashdb import HashDB
from .models import ApkFacts, Finding, Severity

P = "android.permission."

# Distinctive financial brand tokens used in impersonation campaigns.
# Deliberately specific (no single generic word) to keep false positives low.
BRAND_TOKENS = (
    "orange money",
    "orangemoney",
    "moov money",
    "moovmoney",
    "wave money",
    "wave senegal",
    "corismoney",
    "coris money",
    "sank money",
    "sankmoney",
    "mobicash",
    "telecel money",
)

# Similarity above which a package name is considered a lookalike of an
# official one (e.g. com.orange.mymoney vs com.orange.money).
PACKAGE_SIMILARITY_THRESHOLD = 0.88

DANGEROUS_PERMISSIONS = {
    P + name
    for name in (
        "READ_SMS",
        "RECEIVE_SMS",
        "SEND_SMS",
        "READ_CONTACTS",
        "READ_CALL_LOG",
        "RECORD_AUDIO",
        "CAMERA",
        "ACCESS_FINE_LOCATION",
        "READ_PHONE_STATE",
        "SYSTEM_ALERT_WINDOW",
        "REQUEST_INSTALL_PACKAGES",
        "READ_EXTERNAL_STORAGE",
        "WRITE_EXTERNAL_STORAGE",
    )
}


def run_heuristics(facts: ApkFacts, hashdb: HashDB) -> list[Finding]:
    if not facts.is_valid_apk:
        return []

    official = hashdb.official_app(facts.package_name) if facts.package_name else None
    if official and official.get("cert_sha256") and official["cert_sha256"] == facts.cert_sha256:
        # Genuine official application: certificate matches the national
        # allowlist, no impersonation heuristics apply.
        return [
            Finding(
                rule_id="heur.official_app",
                title="Official application",
                severity=Severity.INFO,
                category="certificate",
                description=f"Signing certificate matches the allowlist entry "
                f"for {official['label']}.",
            )
        ]

    findings: list[Finding] = []
    findings.extend(_impersonation(facts, hashdb, official))
    findings.extend(_permission_combos(facts))
    findings.extend(_manifest_hygiene(facts))
    return findings


# -- impersonation ---------------------------------------------------------


def _impersonation(facts: ApkFacts, hashdb: HashDB, official: dict | None) -> list[Finding]:
    findings: list[Finding] = []

    if official and official.get("cert_sha256") and facts.cert_sha256:
        # Same package name as an official app but signed by another key:
        # repackaged / trojanised clone. Strongest impersonation signal.
        findings.append(
            Finding(
                rule_id="heur.cert_mismatch",
                title="Official package signed by unknown certificate",
                severity=Severity.CRITICAL,
                category="impersonation",
                description=f"Package {facts.package_name} claims to be "
                f"{official['label']} but its signing certificate does not match "
                f"the registered official certificate.",
                evidence=f"cert_sha256={facts.cert_sha256}",
            )
        )
        return findings

    if facts.package_name and not official:
        for entry in hashdb.official_packages():
            ratio = SequenceMatcher(None, facts.package_name, entry["package_name"]).ratio()
            if ratio >= PACKAGE_SIMILARITY_THRESHOLD:
                findings.append(
                    Finding(
                        rule_id="heur.package_lookalike",
                        title="Package name imitates an official application",
                        severity=Severity.HIGH,
                        category="impersonation",
                        description=f"Package {facts.package_name} closely resembles "
                        f"{entry['package_name']} ({entry['label']}), "
                        f"similarity {ratio:.2f}.",
                        evidence=facts.package_name,
                    )
                )
                break

    label = (facts.app_name or "").lower()
    if label and not official:
        for token in BRAND_TOKENS:
            if token in label:
                findings.append(
                    Finding(
                        rule_id="heur.brand_in_label",
                        title="Financial brand name used by unofficial package",
                        severity=Severity.HIGH,
                        category="impersonation",
                        description=f'Application label "{facts.app_name}" uses the brand '
                        f'"{token}" while the package is not in the official registry.',
                        evidence=facts.app_name,
                    )
                )
                break
    return findings


# -- permission combinations ----------------------------------------------


def _permission_combos(facts: ApkFacts) -> list[Finding]:
    findings: list[Finding] = []
    perms = set(facts.permissions)
    has = perms.__contains__

    if (has(P + "RECEIVE_SMS") or has(P + "READ_SMS")) and has(P + "INTERNET"):
        findings.append(
            Finding(
                rule_id="heur.sms_exfiltration",
                title="SMS interception with network access",
                severity=Severity.HIGH,
                category="permission",
                description="The application can read incoming SMS (mobile money OTP, "
                "bank codes) and relay them over the network.",
                evidence="RECEIVE_SMS/READ_SMS + INTERNET",
            )
        )
    if has(P + "SEND_SMS"):
        findings.append(
            Finding(
                rule_id="heur.send_sms",
                title="Can send SMS autonomously",
                severity=Severity.MEDIUM,
                category="permission",
                description="SEND_SMS enables premium-rate fraud and USSD-based "
                "mobile money transfers without user interaction.",
                evidence="SEND_SMS",
            )
        )
    if has(P + "SYSTEM_ALERT_WINDOW"):
        findings.append(
            Finding(
                rule_id="heur.overlay",
                title="Screen overlay capability",
                severity=Severity.MEDIUM,
                category="permission",
                description="Overlay windows are the primary technique used by banking "
                "trojans to display fake PIN entry screens on top of "
                "legitimate applications.",
                evidence="SYSTEM_ALERT_WINDOW",
            )
        )
    if has(P + "RECORD_AUDIO") and has(P + "INTERNET") and (
        has(P + "ACCESS_FINE_LOCATION") or has(P + "READ_CONTACTS")
    ):
        findings.append(
            Finding(
                rule_id="heur.spyware_combo",
                title="Spyware permission profile",
                severity=Severity.HIGH,
                category="permission",
                description="Microphone capture combined with location or contacts "
                "access and network exfiltration capability.",
                evidence="RECORD_AUDIO + INTERNET + LOCATION/CONTACTS",
            )
        )
    if has(P + "REQUEST_INSTALL_PACKAGES"):
        findings.append(
            Finding(
                rule_id="heur.dropper",
                title="Can install other packages",
                severity=Severity.MEDIUM,
                category="permission",
                description="REQUEST_INSTALL_PACKAGES is characteristic of droppers "
                "that pull a second-stage payload after installation.",
                evidence="REQUEST_INSTALL_PACKAGES",
            )
        )

    dangerous = perms & DANGEROUS_PERMISSIONS
    if len(dangerous) >= 8:
        findings.append(
            Finding(
                rule_id="heur.permission_hoarding",
                title="Excessive dangerous permissions",
                severity=Severity.MEDIUM,
                category="permission",
                description=f"The application requests {len(dangerous)} dangerous "
                "permissions, far beyond a typical single-purpose app.",
                evidence=", ".join(sorted(p.removeprefix(P) for p in dangerous)),
            )
        )
    return findings


# -- manifest hygiene ------------------------------------------------------


def _manifest_hygiene(facts: ApkFacts) -> list[Finding]:
    findings: list[Finding] = []
    if facts.debuggable:
        findings.append(
            Finding(
                rule_id="heur.debuggable",
                title="Application is debuggable",
                severity=Severity.LOW,
                category="manifest",
                description="android:debuggable=true in a distributed APK indicates a "
                "development build or a repackaged application.",
            )
        )
    if facts.target_sdk is not None and facts.target_sdk < 23:
        findings.append(
            Finding(
                rule_id="heur.legacy_target_sdk",
                title="Targets a pre-runtime-permission SDK",
                severity=Severity.MEDIUM,
                category="manifest",
                description=f"targetSdkVersion={facts.target_sdk} (< 23) grants all "
                "permissions at install time, a common evasion for malware "
                "distributed outside official stores.",
            )
        )
    return findings
