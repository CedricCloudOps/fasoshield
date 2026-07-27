"""Deferred scan queue and quarantine storage."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from fasoshield import jobs
from fasoshield.db.models import ScanJob
from fasoshield.storage import LocalQuarantine, open_quarantine

from .conftest import malicious_apk


@pytest.fixture()
def client(isolated_settings):
    from fasoshield.api.main import app

    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture()
def worker(isolated_settings):
    from fasoshield.api.deps import get_quarantine, get_scan_engine

    return jobs.ScanWorker(engine=get_scan_engine(), quarantine=get_quarantine())


# -- quarantine storage ----------------------------------------------------


def test_local_quarantine_is_content_addressed(tmp_path):
    store = LocalQuarantine(tmp_path / "q")
    sample = tmp_path / "sample.apk"
    sample.write_bytes(b"payload")
    sha = "ab" + "0" * 62

    location = Path(store.put(sha, sample))
    assert store.exists(sha)
    assert location.read_bytes() == b"payload"
    # Two levels of hash prefix keep any single directory small.
    assert location.parent.name == sha[2:4]
    assert location.parent.parent.name == sha[:2]
    assert store.location(sha) == str(location)


def test_local_quarantine_put_is_idempotent(tmp_path):
    store = LocalQuarantine(tmp_path / "q")
    sample = tmp_path / "sample.apk"
    sample.write_bytes(b"payload")
    sha = "cd" + "0" * 62
    assert store.put(sha, sample) == store.put(sha, sample)


def test_open_quarantine_from_file_url(tmp_path):
    store = open_quarantine((tmp_path / "quarantine").as_uri())
    assert isinstance(store, LocalQuarantine)
    assert store.root.exists()


def test_open_quarantine_rejects_unknown_scheme():
    with pytest.raises(ValueError):
        open_quarantine("ftp://example.org/samples")


# -- queue semantics -------------------------------------------------------


def test_claim_next_returns_none_on_empty_queue(db_session):
    assert jobs.claim_next(db_session) is None


def test_claim_marks_the_job_running(db_session, tmp_path):
    staged = malicious_apk(tmp_path / "big.apk")
    job = jobs.enqueue(db_session, "big.apk", staged.stat().st_size, staged, submitted_by="alice")
    assert job.status == jobs.QUEUED

    claimed = jobs.claim_next(db_session)
    assert claimed.id == job.id
    assert claimed.status == jobs.RUNNING
    assert claimed.started_at is not None
    # A second worker finds nothing left to take.
    assert jobs.claim_next(db_session) is None


def test_run_job_scans_persists_and_cleans_up(db_session, tmp_path, worker):
    staged = malicious_apk(tmp_path / "queued.apk")
    jobs.enqueue(db_session, "queued.apk", staged.stat().st_size, staged, None)
    claimed = jobs.claim_next(db_session)
    done = jobs.run_job(db_session, claimed, worker.engine, worker.quarantine)

    assert done.status == jobs.DONE
    assert done.verdict == "MALICIOUS"
    assert done.sha256
    assert not staged.exists()  # the staged upload is not left behind
    assert worker.quarantine.exists(done.sha256)

    from fasoshield.db.models import Sample

    assert db_session.get(Sample, done.sha256) is not None


def test_failed_job_is_recorded_not_raised(db_session, tmp_path, worker):
    missing = tmp_path / "vanished.apk"
    missing.write_bytes(b"x")
    jobs.enqueue(db_session, "vanished.apk", 1, missing, None)
    missing.unlink()  # the staged file disappears before the worker runs

    claimed = jobs.claim_next(db_session)
    done = jobs.run_job(db_session, claimed, worker.engine, worker.quarantine)
    assert done.status == jobs.FAILED
    assert done.error


def test_drain_once_processes_everything_queued(db_session, tmp_path, worker):
    for index in range(3):
        staged = malicious_apk(tmp_path / f"sample-{index}.apk")
        jobs.enqueue(db_session, f"sample-{index}.apk", staged.stat().st_size, staged, None)
    assert worker.drain_once() == 3
    assert worker.drain_once() == 0


# -- HTTP surface ----------------------------------------------------------


def test_small_upload_is_scanned_inline(client, tmp_path):
    sample = malicious_apk(tmp_path / "small.apk")
    response = client.post(
        "/v1/scan", files={"file": ("small.apk", sample.read_bytes(), "application/octet-stream")}
    )
    assert response.status_code == 200
    assert response.json()["verdict"] == "MALICIOUS"


def test_large_upload_is_queued(client, isolated_settings, monkeypatch, tmp_path, db_session):
    # Force every upload over the async threshold.
    monkeypatch.setattr(isolated_settings, "async_scan_threshold_bytes", 1)
    sample = malicious_apk(tmp_path / "large.apk")

    response = client.post(
        "/v1/scan", files={"file": ("large.apk", sample.read_bytes(), "application/octet-stream")}
    )
    assert response.status_code == 202
    body = response.json()
    assert body["status"] == jobs.QUEUED
    assert response.headers["location"] == f"/v1/scan/jobs/{body['id']}"

    # The job is retrievable while it waits.
    polled = client.get(f"/v1/scan/jobs/{body['id']}")
    assert polled.status_code == 200
    assert db_session.get(ScanJob, body["id"]) is not None


def test_queued_job_completes_and_exposes_its_report(
    client, isolated_settings, monkeypatch, tmp_path, db_session, worker
):
    monkeypatch.setattr(isolated_settings, "async_scan_threshold_bytes", 1)
    sample = malicious_apk(tmp_path / "large.apk")
    job_id = client.post(
        "/v1/scan", files={"file": ("large.apk", sample.read_bytes(), "application/octet-stream")}
    ).json()["id"]

    worker.drain_once()

    body = client.get(f"/v1/scan/jobs/{job_id}").json()
    assert body["status"] == jobs.DONE
    assert body["verdict"] == "MALICIOUS"
    assert body["report"]["findings"]


def test_unknown_job_is_404(client):
    assert client.get("/v1/scan/jobs/does-not-exist").status_code == 404


def test_upload_above_the_hard_cap_is_rejected(client, isolated_settings, monkeypatch):
    monkeypatch.setattr(isolated_settings, "max_upload_bytes", 10)
    response = client.post(
        "/v1/scan", files={"file": ("big.apk", b"x" * 100, "application/octet-stream")}
    )
    assert response.status_code == 413


def test_clean_file_is_not_quarantined(client, isolated_settings, tmp_path):
    from fasoshield.api.deps import get_quarantine

    response = client.post(
        "/v1/scan",
        files={"file": ("notes.txt", b"contenu parfaitement anodin", "text/plain")},
    )
    assert response.status_code == 200
    report = response.json()
    assert report["verdict"] == "CLEAN"
    assert not get_quarantine().exists(report["sha256"])
