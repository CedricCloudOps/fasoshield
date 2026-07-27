from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from .conftest import login, make_analyst, malicious_apk


@pytest.fixture()
def client(isolated_settings, db_session):
    """A client already authenticated as a console viewer: the dashboard and
    its statistics are analyst-only, agent keys give no access to them."""
    from fasoshield.api.main import app

    make_analyst(db_session, "soc-viewer", role="viewer")
    with TestClient(app) as test_client:
        login(test_client, "soc-viewer")
        yield test_client


@pytest.fixture()
def anonymous_client(isolated_settings):
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


def test_overview_corpus_reflects_scan_history(client, tmp_path):
    sample = malicious_apk(tmp_path / "fake-om.apk")
    client.post(
        "/v1/scan",
        files={
            "file": (
                "fake-om.apk",
                sample.read_bytes(),
                "application/vnd.android.package-archive",
            )
        },
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


def test_console_page_served_without_session(anonymous_client):
    """The shell is public — it holds no data and renders the login form."""
    response = anonymous_client.get("/console")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    assert "Console SOC" in response.text
    assert "__CSP_NONCE__" not in response.text  # the nonce was stamped in


def test_stats_require_an_analyst_session(anonymous_client, isolated_settings, monkeypatch):
    """An agent API key must not open the national threat picture: it is
    deployed on every handset, so it is not a secret worth that access."""
    monkeypatch.setattr(isolated_settings, "api_keys", "agent-key")
    assert anonymous_client.get("/v1/stats/overview").status_code == 401
    with_agent_key = anonymous_client.get(
        "/v1/stats/overview", headers={"X-API-Key": "agent-key"}
    )
    assert with_agent_key.status_code == 401


def test_workflow_counts_exposed(client, db_session):
    from fasoshield.governance import create_proposal

    create_proposal(
        db_session,
        actor="soc-viewer",
        indicator_type="sha256",
        value="a" * 64,
        threat_name="Trojan.FakeOM",
        source="cert-bf",
        justification="Clone d'Orange Money collecte le PIN puis l'exfiltre en HTTP.",
    )
    workflow = client.get("/v1/stats/overview").json()["workflow"]
    assert workflow["DRAFT"] == 1
    assert workflow["PUBLISHED"] == 0
