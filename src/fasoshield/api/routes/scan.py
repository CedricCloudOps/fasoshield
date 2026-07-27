"""APK submission endpoints.

Small uploads are scanned inline and answered with the full report. Uploads
above ``async_scan_threshold_bytes`` are staged and queued: the client gets a
202 with a job identifier and polls ``GET /v1/scan/jobs/{id}``, which keeps
request latency bounded whatever the sample size.

Detected samples are copied to quarantine — they feed the national corpus and
let analysts re-examine a verdict later.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Request, Response, UploadFile, status
from sqlalchemy.orm import Session

from ... import jobs
from ...accounts import resolve_session
from ...config import settings
from ...db.models import ScanJob
from ...engine.models import ScanReport, Verdict
from ...engine.scanner import ScanEngine
from ...storage import QuarantineStore
from ..deps import AuthDep, get_db, get_quarantine, get_scan_engine
from ..schemas import ScanJobOut

router = APIRouter(tags=["scan"])


@router.post("/v1/scan", response_model=None, dependencies=[AuthDep])
async def scan_apk(
    file: UploadFile,
    request: Request,
    response: Response,
    engine: ScanEngine = Depends(get_scan_engine),
    quarantine: QuarantineStore = Depends(get_quarantine),
    db: Session = Depends(get_db),
) -> ScanReport | ScanJobOut:
    staged, size = await _stage_upload(file)
    file_name = file.filename or "upload.apk"

    if size > settings.async_scan_threshold_bytes:
        # Keep the staged file: the worker will scan and delete it.
        job = jobs.enqueue(db, file_name, size, staged, submitted_by=_submitter(request, db))
        response.status_code = status.HTTP_202_ACCEPTED
        response.headers["Location"] = f"/v1/scan/jobs/{job.id}"
        return _job_out(job)

    try:
        report = engine.scan_file(staged, file_name=file_name)
        jobs.persist_sample(db, report)
        if report.verdict is not Verdict.CLEAN:
            quarantine.put(report.sha256, staged)
        return report
    finally:
        staged.unlink(missing_ok=True)


@router.get("/v1/scan/jobs/{job_id}", response_model=ScanJobOut, dependencies=[AuthDep])
def scan_job(job_id: str, db: Session = Depends(get_db)) -> ScanJobOut:
    job = db.get(ScanJob, job_id)
    if job is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Unknown job")
    return _job_out(job)


async def _stage_upload(file: UploadFile) -> tuple[Path, int]:
    """Stream the upload to disk, enforcing the size cap as we go.

    The rejection is raised only after the temporary file has been closed:
    Windows refuses to unlink a file whose handle is still open, so cleaning up
    inside the ``with`` block would turn a 413 into a 500.
    """
    staging = jobs.staging_dir()
    size = 0
    too_large = False
    with tempfile.NamedTemporaryFile(dir=staging, suffix=".upload", delete=False) as tmp:
        staged = Path(tmp.name)
        while chunk := await file.read(1024 * 1024):
            size += len(chunk)
            if size > settings.max_upload_bytes:
                too_large = True
                break
            tmp.write(chunk)

    if too_large:
        staged.unlink(missing_ok=True)
        raise HTTPException(
            status_code=status.HTTP_413_CONTENT_TOO_LARGE,
            detail=f"File exceeds {settings.max_upload_bytes} bytes",
        )
    if size == 0:
        staged.unlink(missing_ok=True)
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail="Empty file"
        )
    return staged, size


def _submitter(request: Request, db: Session) -> str | None:
    """Who submitted the job. An analyst uploading from the console is named;
    an agent key is not recorded, because it identifies a fleet of devices
    rather than a person."""
    token = request.cookies.get(settings.session_cookie_name, "")
    if not token:
        return None
    account = resolve_session(db, token)
    return account.username if account else None


def _job_out(job: ScanJob) -> ScanJobOut:
    report = None
    if job.report_json:
        report = ScanReport.model_validate(json.loads(job.report_json))
    return ScanJobOut(
        id=job.id,
        file_name=job.file_name,
        file_size=job.file_size,
        status=job.status,
        sha256=job.sha256,
        verdict=job.verdict,
        error=job.error,
        created_at=job.created_at,
        started_at=job.started_at,
        finished_at=job.finished_at,
        report=report,
    )
