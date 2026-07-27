from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from .conftest import EICAR, EICAR_SHA256, write_eicar


@pytest.fixture()
def client(isolated_settings):
    from fasoshield.api.main import app

    with TestClient(app) as test_client:
        yield test_client


def test_health(client):
    body = client.get("/health").json()
    assert body["status"] == "ok"
    assert "engine_version" in body


def test_reputation_rejects_bad_hash(client):
    assert client.get("/v1/reputation/nothex").status_code == 422


def test_reputation_unknown_hash(client):
    body = client.get(f"/v1/reputation/{'0' * 64}").json()
    assert body["known"] is False
    assert body["verdict"] is None


def test_scan_upload_eicar_then_reputation(client, tmp_path):
    # The engine writes the upload to disk before scanning it, so a desktop AV
    # on the developer's machine can snatch the file mid-flight.
    write_eicar(tmp_path / "eicar-probe.com")
    response = client.post(
        "/v1/scan", files={"file": ("eicar.com", EICAR.encode(), "application/octet-stream")}
    )
    assert response.status_code == 200
    report = response.json()
    assert report["sha256"] == EICAR_SHA256
    assert report["verdict"] == "MALICIOUS"

    # The verdict is now served from scan history without re-uploading.
    body = client.get(f"/v1/reputation/{EICAR_SHA256}").json()
    assert body["known"] is True
    assert body["verdict"] == "MALICIOUS"
    assert body["source"] == "scan-history"


def test_scan_rejects_empty_file(client):
    response = client.post("/v1/scan", files={"file": ("empty.apk", b"", "application/o")})
    assert response.status_code == 422


def test_signature_version_and_updates(client, isolated_settings):
    from fasoshield.api.deps import get_hashdb

    version = client.get("/v1/signatures/version").json()
    assert version["version"] == "0"
    get_hashdb().add("e" * 64, "Test.Threat", source="unit-test")
    updates = client.get("/v1/signatures/updates", params={"since": "0"}).json()
    assert [e["sha256"] for e in updates["entries"]] == ["e" * 64]
    assert updates["version"] != "0"


def test_signature_updates_are_unsigned_without_a_key(client):
    body = client.get("/v1/signatures/updates", params={"since": "0"}).json()
    assert body["signature"] is None
    assert body["key_id"] is None


def test_signature_updates_carry_a_verifiable_signature(isolated_settings, tmp_path):
    """End-to-end over the wire: what the endpoint serves must verify against
    the published key using only the fields the agent parses."""
    from fastapi.testclient import TestClient

    from fasoshield.api import deps
    from fasoshield.signing import generate_key, key_id, private_key_pem, verify_bundle

    signing_key = generate_key()
    key_path = tmp_path / "bundle-signing.pem"
    key_path.write_bytes(private_key_pem(signing_key))
    isolated_settings.signature_signing_key = str(key_path)
    deps.get_bundle_signer.cache_clear()

    from fasoshield.api.main import app

    with TestClient(app) as client:
        deps.get_hashdb().add("e" * 64, "Test.Threat", source="unit-test", cert_sha256="f" * 64)
        body = client.get("/v1/signatures/updates", params={"since": "0"}).json()

    assert body["key_id"] == key_id(signing_key.public_key())
    assert verify_bundle(
        signing_key.public_key(), body["version"], body["entries"], body["signature"]
    )


def test_served_signature_does_not_cover_a_forged_entry(isolated_settings, tmp_path):
    from fastapi.testclient import TestClient

    from fasoshield.api import deps
    from fasoshield.signing import generate_key, private_key_pem, verify_bundle

    signing_key = generate_key()
    key_path = tmp_path / "bundle-signing.pem"
    key_path.write_bytes(private_key_pem(signing_key))
    isolated_settings.signature_signing_key = str(key_path)
    deps.get_bundle_signer.cache_clear()

    from fasoshield.api.main import app

    with TestClient(app) as client:
        deps.get_hashdb().add("e" * 64, "Test.Threat", source="unit-test")
        body = client.get("/v1/signatures/updates", params={"since": "0"}).json()

    tampered = body["entries"] + [
        {
            "sha256": "d" * 64,
            "threat_name": "Injected",
            "source": "attacker",
            "added_at": "2026-07-27T11:00:00+00:00",
            "cert_sha256": None,
        }
    ]
    assert not verify_bundle(
        signing_key.public_key(), body["version"], tampered, body["signature"]
    )


def test_telemetry_roundtrip(client):
    payload = {
        "agent_id": "3f2c8a90-agent-test",
        "event_type": "detection",
        "sha256": "f" * 64,
        "package_name": "com.bad.app",
        "verdict": "MALICIOUS",
        "threat_name": "Trojan.FakeOM",
        "region": "Centre",
    }
    response = client.post("/v1/telemetry", json=payload)
    assert response.status_code == 200
    assert response.json()["accepted"] is True


def test_api_key_enforced_when_configured(client, isolated_settings, monkeypatch):
    monkeypatch.setattr(isolated_settings, "api_keys", "agent-key-1,agent-key-2")
    denied = client.get(f"/v1/reputation/{'0' * 64}")
    assert denied.status_code == 401
    allowed = client.get(
        f"/v1/reputation/{'0' * 64}", headers={"X-API-Key": "agent-key-2"}
    )
    assert allowed.status_code == 200
    # /health stays open for load balancer probes.
    assert client.get("/health").status_code == 200
