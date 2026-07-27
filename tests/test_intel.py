"""STIX 2.1 and MISP exports for partner CERTs."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from fasoshield.intel import misp_event, stix_bundle

from .conftest import login, make_analyst

ORG = "FasoShield — CERT national"

ENTRIES = [
    {
        "sha256": "a" * 64,
        "threat_name": "Trojan.FakeOM",
        "source": "cert-bf/reviewed",
        "cert_sha256": None,
        "added_at": "2026-07-01T10:00:00+00:00",
    },
    {
        "sha256": "b" * 64,
        "threat_name": "Trojan.FakeOM",
        "source": "cert-bf/reviewed",
        "cert_sha256": None,
        "added_at": "2026-07-02T10:00:00+00:00",
    },
    {
        "sha256": "c" * 64,
        "threat_name": "Spy.SmsThief",
        "source": "partner-feed",
        "cert_sha256": "d" * 64,
        "added_at": "2026-07-03T10:00:00+00:00",
    },
]


@pytest.fixture()
def client(isolated_settings):
    from fasoshield.api.main import app

    with TestClient(app) as test_client:
        yield test_client


def _by_type(bundle: dict, kind: str) -> list[dict]:
    return [obj for obj in bundle["objects"] if obj["type"] == kind]


# -- STIX ------------------------------------------------------------------


def test_stix_bundle_shape():
    bundle = stix_bundle(ENTRIES, org_name=ORG)
    assert bundle["type"] == "bundle"
    assert len(_by_type(bundle, "identity")) == 1
    assert len(_by_type(bundle, "indicator")) == 3
    # One malware object per distinct threat name, not per indicator.
    assert len(_by_type(bundle, "malware")) == 2
    assert len(_by_type(bundle, "relationship")) == 3


def test_stix_file_pattern():
    indicator = _by_type(stix_bundle(ENTRIES[:1], org_name=ORG), "indicator")[0]
    assert indicator["pattern"] == f"[file:hashes.'SHA-256' = '{'a' * 64}']"
    assert indicator["pattern_type"] == "stix"
    assert indicator["spec_version"] == "2.1"


def test_stix_certificate_indicator_uses_the_x509_object():
    """A signing-key IOC is not a file hash; exporting it as one would make
    partners hunt for a sample that does not exist."""
    indicator = _by_type(stix_bundle(ENTRIES[2:], org_name=ORG), "indicator")[0]
    assert indicator["pattern"] == f"[x509-certificate:hashes.'SHA-256' = '{'d' * 64}']"


def test_stix_ids_are_stable_across_exports():
    """Re-exporting the same IOC must update the partner's object, not
    duplicate it."""
    first = _by_type(stix_bundle(ENTRIES, org_name=ORG), "indicator")
    second = _by_type(stix_bundle(ENTRIES, org_name=ORG), "indicator")
    assert [obj["id"] for obj in first] == [obj["id"] for obj in second]


def test_stix_relationships_link_indicator_to_malware():
    bundle = stix_bundle(ENTRIES[:1], org_name=ORG)
    indicator = _by_type(bundle, "indicator")[0]
    malware = _by_type(bundle, "malware")[0]
    relationship = _by_type(bundle, "relationship")[0]
    assert relationship["relationship_type"] == "indicates"
    assert relationship["source_ref"] == indicator["id"]
    assert relationship["target_ref"] == malware["id"]


def test_stix_applies_a_tlp_marking():
    indicator = _by_type(stix_bundle(ENTRIES[:1], org_name=ORG, tlp="red"), "indicator")[0]
    assert indicator["object_marking_refs"] == [
        "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed"
    ]


def test_unknown_tlp_falls_back_to_amber():
    indicator = _by_type(stix_bundle(ENTRIES[:1], org_name=ORG, tlp="purple"), "indicator")[0]
    assert indicator["object_marking_refs"] == [
        "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82"
    ]


def test_empty_export_is_still_a_valid_bundle():
    bundle = stix_bundle([], org_name=ORG)
    assert _by_type(bundle, "identity")  # the producer is always declared
    assert _by_type(bundle, "indicator") == []


# -- MISP ------------------------------------------------------------------


def test_misp_event_attributes():
    event = misp_event(ENTRIES, org_name=ORG)["Event"]
    assert len(event["Attribute"]) == 3
    assert all(attr["type"] == "sha256" for attr in event["Attribute"])
    assert all(attr["to_ids"] is True for attr in event["Attribute"])
    assert event["Orgc"]["name"] == ORG


def test_misp_event_is_not_auto_published():
    """The receiving CERT decides when an event becomes visible to its own
    community."""
    assert misp_event(ENTRIES, org_name=ORG)["Event"]["published"] is False


def test_misp_carries_the_tlp_tag():
    tags = [tag["name"] for tag in misp_event(ENTRIES, org_name=ORG, tlp="green")["Event"]["Tag"]]
    assert "tlp:green" in tags


def test_misp_certificate_attribute_uses_the_certificate_hash():
    attribute = misp_event(ENTRIES[2:], org_name=ORG)["Event"]["Attribute"][0]
    assert attribute["value"] == "d" * 64
    assert "certificate" in attribute["comment"].lower()


# -- HTTP surface ----------------------------------------------------------


def test_intel_exports_require_authentication(client):
    assert client.get("/v1/intel/stix").status_code == 401
    assert client.get("/v1/intel/misp").status_code == 401


def test_stix_endpoint_returns_published_indicators(client, db_session, isolated_settings):
    from fasoshield.api.deps import get_hashdb

    get_hashdb().add("e" * 64, "Trojan.FakeOM", source="cert-bf/reviewed")
    make_analyst(db_session, "viewer", role="viewer")
    login(client, "viewer")

    response = client.get("/v1/intel/stix")
    assert response.status_code == 200
    assert "attachment" in response.headers["content-disposition"]
    patterns = [
        obj["pattern"] for obj in response.json()["objects"] if obj["type"] == "indicator"
    ]
    assert f"[file:hashes.'SHA-256' = '{'e' * 64}']" in patterns


def test_exports_are_audited(client, db_session, isolated_settings):
    from fasoshield.accounts import recent_audit
    from fasoshield.api.deps import get_hashdb

    get_hashdb().add("f" * 64, "Trojan.FakeOM")
    make_analyst(db_session, "viewer", role="viewer")
    login(client, "viewer")
    client.get("/v1/intel/misp")

    actions = [event.action for event in recent_audit(db_session)]
    assert "intel.export_misp" in actions
