"""Deferred scan queue.

Large uploads must not hold an HTTP connection open for the duration of a full
static analysis. Above ``async_scan_threshold_bytes`` the API stages the file,
records a ScanJob and answers 202 with a job identifier; a worker picks it up
and the client polls the job.

The ``scan_jobs`` table *is* the queue. A worker claims a job with a
conditional UPDATE (``WHERE status = 'QUEUED'``), which the database serialises
for us — several API processes, or a dedicated worker container, can therefore
share the load without introducing a message broker into a sovereign
deployment that must stay easy to operate.
"""

from __future__ import annotations

import logging
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import update
from sqlalchemy.orm import Session

from .config import settings
from .db.models import Sample, ScanJob
from .db.session import get_session
from .engine.models import ScanReport, Verdict
from .engine.scanner import ScanEngine

logger = logging.getLogger("fasoshield.jobs")

QUEUED = "QUEUED"
RUNNING = "RUNNING"
DONE = "DONE"
FAILED = "FAILED"


def staging_dir() -> Path:
    path = settings.data_dir / "staging"
    path.mkdir(parents=True, exist_ok=True)
    return path


def enqueue(
    db: Session, file_name: str, file_size: int, staged: Path, submitted_by: str | None
) -> ScanJob:
    job = ScanJob(
        id=str(uuid.uuid4()),
        file_name=file_name,
        file_size=file_size,
        staged_path=str(staged),
        status=QUEUED,
        submitted_by=submitted_by,
    )
    db.add(job)
    db.commit()
    return job


def claim_next(db: Session) -> ScanJob | None:
    """Atomically take ownership of one queued job, or return None.

    The UPDATE ... WHERE status = 'QUEUED' is the lock: two workers racing on
    the same row means one of them updates zero rows and moves on.
    """
    candidate = (
        db.query(ScanJob).filter(ScanJob.status == QUEUED).order_by(ScanJob.created_at).first()
    )
    if candidate is None:
        return None
    result = db.execute(
        update(ScanJob)
        .where(ScanJob.id == candidate.id, ScanJob.status == QUEUED)
        .values(status=RUNNING, started_at=datetime.now(timezone.utc))
    )
    db.commit()
    if result.rowcount != 1:
        return None  # another worker won the race
    db.refresh(candidate)
    return candidate


def run_job(db: Session, job: ScanJob, engine: ScanEngine, quarantine=None) -> ScanJob:
    """Execute one claimed job, recording success or failure."""
    staged = Path(job.staged_path)
    try:
        report = engine.scan_file(staged, file_name=job.file_name)
        persist_sample(db, report)
        if quarantine is not None and report.verdict is not Verdict.CLEAN:
            quarantine.put(report.sha256, staged)
        job.status = DONE
        job.sha256 = report.sha256
        job.verdict = report.verdict.value
        job.report_json = report.model_dump_json()
    except Exception as exc:  # noqa: BLE001 - a failed job must not kill the worker
        logger.exception("scan job %s failed", job.id)
        job.status = FAILED
        job.error = f"{type(exc).__name__}: {exc}"
    finally:
        job.finished_at = datetime.now(timezone.utc)
        db.commit()
        staged.unlink(missing_ok=True)  # the sample lives in quarantine now
    return job


def persist_sample(db: Session, report: ScanReport) -> None:
    """Upsert the scan result into the national corpus."""
    sample = db.get(Sample, report.sha256)
    if sample is None:
        db.add(
            Sample(
                sha256=report.sha256,
                file_name=report.file_name,
                file_size=report.file_size,
                verdict=report.verdict.value,
                score=report.score,
                threat_name=report.threat_name,
                report_json=report.model_dump_json(),
                engine_version=report.engine_version,
            )
        )
    else:
        sample.file_name = report.file_name
        sample.file_size = report.file_size
        sample.verdict = report.verdict.value
        sample.score = report.score
        sample.threat_name = report.threat_name
        sample.report_json = report.model_dump_json()
        sample.engine_version = report.engine_version
        sample.scan_count += 1
    db.commit()


class ScanWorker:
    """Background thread draining the queue.

    Runs inside the API process so a single-server deployment needs nothing
    else; the same class is what ``fasoshield worker`` runs standalone when the
    platform is scaled out.
    """

    def __init__(self, engine: ScanEngine, quarantine=None, poll_seconds: float = 2.0) -> None:
        self.engine = engine
        self.quarantine = quarantine
        self.poll_seconds = poll_seconds
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self._thread is not None:
            return
        self._thread = threading.Thread(
            target=self._loop, name="fasoshield-scan-worker", daemon=True
        )
        self._thread.start()
        logger.info("scan worker started")

    def stop(self, timeout: float = 5.0) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=timeout)
            self._thread = None

    def drain_once(self) -> int:
        """Process every job currently queued; returns how many ran.
        Used by the tests and by a cron-style one-shot worker."""
        processed = 0
        db = get_session()
        try:
            while (job := claim_next(db)) is not None:
                run_job(db, job, self.engine, self.quarantine)
                processed += 1
        finally:
            db.close()
        return processed

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                if self.drain_once() == 0:
                    self._stop.wait(self.poll_seconds)
            except Exception:  # noqa: BLE001 - never let the worker thread die
                logger.exception("scan worker iteration failed")
                time.sleep(self.poll_seconds)
