from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from .conftest import EICAR


@pytest.fixture()
def client(isolated_settings):
    from fasoshield.api.main import app

    with TestClient(app) as test_client:
        yield test_client


def _detection(agent: str, region: str, threat: str) -> dict:
    return {
        "agent_id": agent,
        "event_type": "detection",
        "package_name": "com.fake.om",
        "verdict": "MALICIOUS",
        "threat_name": threat,
        "region": region,
    }


def _seed_field(client: TestClient) -> None:
    events = [
        _detection("agent-aaaa-0001", "Centre", "Trojan.FakeOM"),
        _detection("agent-aaaa-0001", "Centre", "Trojan.FakeOM"),
        _detection("agent-bbbb-0002", "Hauts-Bassins", "Spy.SmsThief"),
        {"agent_id": "agent-cccc-0003", "event_type": "scan_summary", "region": "Centre"},
    ]
    for event in events:
        assert client.post("/v1/telemetry", json=event).status_code == 200


def test_overview_field_aggregations(client):
    _seed_field(client)
    data = client.get("/v1/stats/overview").json()

    field = data["field"]
    assert field["detections"] == 3  # scan_summary excluded
    assert field["agents"] == 3  # distinct agent_id, including the scan_summary one
    assert field["events"] == 4

    regions = {r["label"]: r["count"] for r in field["by_region"]}
    assert regions == {"Centre": 2, "Hauts-Bassins": 1}

    threats = {t["label"]: t["count"] for t in field["top_threats"]}
    assert threats["Trojan.FakeOM"] == 2
    # top_threats is ordered by descending count.
    assert field["top_threats"][0]["label"] == "Trojan.FakeOM"


def test_overview_timeline_is_zero_filled(client):
    _seed_field(client)
    timeline = client.get("/v1/stats/overview").json()["field"]["timeline"]
    assert len(timeline) == 14  # one point per day over the window
    assert sum(point["count"] for point in timeline) == 3
    # today's bucket holds every detection seeded in this test run.
    assert timeline[-1]["count"] == 3


def test_overview_corpus_reflects_scan_history(client):
    client.post(
        "/v1/scan",
        files={"file": ("eicar.com", EICAR.encode(), "application/octet-stream")},
    )
    corpus = client.get("/v1/stats/overview").json()["corpus"]
    assert corpus["samples"] == 1
    assert corpus["detections"] == 1
    assert {v["verdict"]: v["count"] for v in corpus["verdicts"]} == {"MALICIOUS": 1}


def test_recent_detections_newest_first(client):
    _seed_field(client)
    recent = client.get("/v1/stats/overview").json()["recent_detections"]
    assert len(recent) == 3  # scan_summary is not a detection
    assert recent[0]["verdict"] == "MALICIOUS"
    assert recent[0]["threat_name"] in {"Trojan.FakeOM", "Spy.SmsThief"}


def test_console_page_served(client):
    response = client.get("/console")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    assert "Console SOC" in response.text


def test_stats_endpoint_respects_api_key(client, isolated_settings, monkeypatch):
    monkeypatch.setattr(isolated_settings, "api_keys", "analyst-key")
    assert client.get("/v1/stats/overview").status_code == 401
    ok = client.get("/v1/stats/overview", headers={"X-API-Key": "analyst-key"})
    assert ok.status_code == 200
