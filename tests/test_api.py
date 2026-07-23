from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from .conftest import EICAR, EICAR_SHA256


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


def test_scan_upload_eicar_then_reputation(client):
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
