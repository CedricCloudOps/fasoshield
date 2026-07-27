"""Threat-intelligence sharing with partner CERTs.

Two interchange formats are produced from the same published indicators:

- **STIX 2.1** — the OASIS standard, consumed by most national CERT platforms;
- **MISP event JSON** — the format of the MISP instances widely deployed across
  African and European CERT communities.

Object identifiers are UUIDv5 values derived from the indicator itself, so
re-exporting the same IOC always yields the same object ID. A partner CERT
importing two successive bundles updates its objects instead of accumulating
duplicates.

Nothing is exported that was not published through the review workflow, and no
telemetry — hence no data relating to an individual — ever leaves the platform
through these endpoints.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

# Fixed namespace for FasoShield-issued identifiers. Constant by design: it is
# what makes an object ID stable across exports and across installations.
NAMESPACE = uuid.UUID("6f1a5d3c-6b6e-5f4a-9c2d-fa50591e1d00")

TLP_LEVELS = ("white", "clear", "green", "amber", "red")

# STIX 2.1 statement markings for TLP, as defined by the specification.
_STIX_TLP_IDS = {
    "white": "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
    "clear": "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
    "green": "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da",
    "amber": "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
    "red": "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed",
}


def _stix_id(kind: str, seed: str) -> str:
    return f"{kind}--{uuid.uuid5(NAMESPACE, f'{kind}:{seed}')}"


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _normalise_tlp(tlp: str) -> str:
    tlp = (tlp or "amber").strip().lower()
    return tlp if tlp in TLP_LEVELS else "amber"


def stix_bundle(entries: list[dict], org_name: str, tlp: str = "amber") -> dict:
    """Build a STIX 2.1 bundle from blocklist entries.

    Each entry becomes an ``indicator`` carrying a STIX pattern, plus a
    ``malware`` object for its threat name and a ``relationship`` tying them
    together — the shape partner platforms expect for actionable IOCs.
    """
    tlp = _normalise_tlp(tlp)
    now = _now()
    identity_id = _stix_id("identity", org_name)
    marking = _STIX_TLP_IDS[tlp]

    objects: list[dict] = [
        {
            "type": "identity",
            "spec_version": "2.1",
            "id": identity_id,
            "created": now,
            "modified": now,
            "name": org_name,
            "identity_class": "organization",
            "sectors": ["government-national"],
        }
    ]

    seen_malware: dict[str, str] = {}
    for entry in entries:
        pattern, seed = _pattern_for(entry)
        if pattern is None:
            continue
        indicator_id = _stix_id("indicator", seed)
        created = _to_stix_time(entry.get("added_at")) or now

        objects.append(
            {
                "type": "indicator",
                "spec_version": "2.1",
                "id": indicator_id,
                "created_by_ref": identity_id,
                "created": created,
                "modified": created,
                "name": entry.get("threat_name") or "Unknown",
                "description": f"FasoShield published indicator "
                f"(source: {entry.get('source') or 'unknown'})",
                "indicator_types": ["malicious-activity"],
                "pattern": pattern,
                "pattern_type": "stix",
                "valid_from": created,
                "labels": ["android", "mobile-malware"],
                "object_marking_refs": [marking],
            }
        )

        threat = entry.get("threat_name") or "Unknown"
        malware_id = seen_malware.get(threat)
        if malware_id is None:
            malware_id = _stix_id("malware", threat)
            seen_malware[threat] = malware_id
            objects.append(
                {
                    "type": "malware",
                    "spec_version": "2.1",
                    "id": malware_id,
                    "created_by_ref": identity_id,
                    "created": now,
                    "modified": now,
                    "name": threat,
                    "is_family": True,
                    "malware_types": ["trojan"],
                    "object_marking_refs": [marking],
                }
            )

        objects.append(
            {
                "type": "relationship",
                "spec_version": "2.1",
                "id": _stix_id("relationship", f"{seed}->{threat}"),
                "created_by_ref": identity_id,
                "created": created,
                "modified": created,
                "relationship_type": "indicates",
                "source_ref": indicator_id,
                "target_ref": malware_id,
                "object_marking_refs": [marking],
            }
        )

    return {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": objects,
    }


def misp_event(entries: list[dict], org_name: str, tlp: str = "amber") -> dict:
    """Build a MISP event (single-event JSON, importable as-is)."""
    tlp = _normalise_tlp(tlp)
    today = datetime.now(timezone.utc).date().isoformat()
    attributes: list[dict] = []

    for entry in entries:
        threat = entry.get("threat_name") or "Unknown"
        cert = entry.get("cert_sha256")
        if cert:
            attributes.append(
                {
                    "type": "sha256",
                    "category": "Payload delivery",
                    "to_ids": True,
                    "value": cert,
                    "comment": f"{threat} — Android signing certificate SHA-256",
                }
            )
        else:
            attributes.append(
                {
                    "type": "sha256",
                    "category": "Payload delivery",
                    "to_ids": True,
                    "value": entry["sha256"],
                    "comment": f"{threat} — APK file SHA-256 "
                    f"(source: {entry.get('source') or 'unknown'})",
                }
            )

    return {
        "Event": {
            "uuid": str(uuid.uuid5(NAMESPACE, f"misp-event:{today}:{len(attributes)}")),
            "info": f"FasoShield — indicateurs de menaces mobiles ({today})",
            "date": today,
            "threat_level_id": "2",  # medium
            "analysis": "2",  # completed
            "published": False,  # the partner CERT decides when to publish
            "Orgc": {"name": org_name},
            "Tag": [
                {"name": f'tlp:{tlp}'},
                {"name": 'type:OSINT'},
                {"name": 'misp-galaxy:mitre-attack-pattern="Impersonation - T1656"'},
            ],
            "Attribute": attributes,
        }
    }


def _pattern_for(entry: dict) -> tuple[str | None, str]:
    """Return the STIX pattern for an entry and the seed for its stable ID."""
    cert = entry.get("cert_sha256")
    if cert:
        # x509-certificate hashes are the right object for a signing-key IOC.
        return (
            f"[x509-certificate:hashes.'SHA-256' = '{cert}']",
            f"cert:{cert}",
        )
    sha256 = entry.get("sha256")
    if not sha256:
        return None, ""
    return f"[file:hashes.'SHA-256' = '{sha256}']", f"file:{sha256}"


def _to_stix_time(value: str | None) -> str | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
