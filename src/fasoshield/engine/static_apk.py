"""Static APK analysis built on Androguard.

Extracts manifest-level and certificate-level facts only; deep bytecode
inspection is delegated to the YARA layer (rules matching on classes.dex),
which keeps scan latency compatible with an API use case.
"""

from __future__ import annotations

import binascii
from pathlib import Path

from loguru import logger

from .models import ApkFacts

# Androguard is extremely chatty through loguru by default.
logger.disable("androguard")

ANDROID_NS = "{http://schemas.android.com/apk/res/android}"


def analyze_apk(path: Path) -> ApkFacts:
    """Parse an APK and return static facts. Never raises: parsing failures
    are recorded in ``parse_error`` so the caller can still emit a report."""
    from androguard.core.apk import APK  # deferred: heavy import

    try:
        apk = APK(str(path))
    except Exception as exc:  # noqa: BLE001 - androguard raises broadly on malformed files
        return ApkFacts(is_valid_apk=False, parse_error=f"{type(exc).__name__}: {exc}")

    facts = ApkFacts(is_valid_apk=bool(apk.is_valid_APK()))
    try:
        facts.package_name = apk.get_package() or None
        facts.app_name = _safe(apk.get_app_name)
        facts.version_name = _safe(apk.get_androidversion_name)
        facts.version_code = _safe(apk.get_androidversion_code)
        facts.min_sdk = _to_int(_safe(apk.get_min_sdk_version))
        facts.target_sdk = _to_int(_safe(apk.get_target_sdk_version))
        facts.permissions = sorted(set(apk.get_permissions() or []))
        _extract_manifest_flags(apk, facts)
        _extract_certificate(apk, facts)
    except Exception as exc:  # noqa: BLE001
        facts.parse_error = f"{type(exc).__name__}: {exc}"
    return facts


def _safe(getter):
    try:
        value = getter()
    except Exception:  # noqa: BLE001
        return None
    return value or None


def _to_int(value) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _extract_manifest_flags(apk, facts: ApkFacts) -> None:
    manifest = apk.get_android_manifest_xml()
    if manifest is None:
        return
    application = manifest.find("application")
    if application is not None:
        facts.debuggable = application.get(f"{ANDROID_NS}debuggable") == "true"
    exported: list[str] = []
    for tag in ("activity", "service", "receiver"):
        for element in manifest.iter(tag):
            if element.get(f"{ANDROID_NS}exported") == "true":
                name = element.get(f"{ANDROID_NS}name") or "?"
                exported.append(f"{tag}:{name}")
    facts.exported_components = exported


def _extract_certificate(apk, facts: ApkFacts) -> None:
    certificates = apk.get_certificates()
    if not certificates:
        return
    cert = certificates[0]
    facts.cert_sha256 = binascii.hexlify(cert.sha256).decode()
    facts.cert_issuer = cert.issuer.human_friendly
    facts.cert_subject = cert.subject.human_friendly
    facts.cert_self_signed = cert.self_signed != "no"
