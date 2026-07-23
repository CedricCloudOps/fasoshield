"""APK submission endpoint.

The uploaded file is streamed to a temporary location, scanned by the engine,
persisted in scan history, then quarantined (kept on disk) only when the
verdict is not CLEAN — detected samples feed the national corpus.
"""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, UploadFile, status
from sqlalchemy.orm import Session

from ...config import settings
from ...db.models import Sample
from ...engine.models import ScanReport, Verdict
from ...engine.scanner import ScanEngine
from ..deps import AuthDep, get_db, get_scan_engine

router = APIRouter(tags=["scan"])


@router.post("/v1/scan", response_model=ScanReport, dependencies=[AuthDep])
async def scan_apk(
    file: UploadFile,
    engine: ScanEngine = Depends(get_scan_engine),
    db: Session = Depends(get_db),
) -> ScanReport:
    tmp_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            dir=_upload_dir(), suffix=".upload", delete=False
        ) as tmp:
            tmp_path = Path(tmp.name)
            size = 0
            while chunk := await file.read(1024 * 1024):
                size += len(chunk)
                if size > settings.max_upload_bytes:
                    raise HTTPException(
                        status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                        detail=f"File exceeds {settings.max_upload_bytes} bytes",
                    )
                tmp.write(chunk)
        if size == 0:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail="Empty file"
            )

        report = engine.scan_file(tmp_path, file_name=file.filename or "upload.apk")
        _persist(db, report)
        if report.verdict is not Verdict.CLEAN:
            _quarantine(tmp_path, report.sha256)
        return report
    finally:
        if tmp_path is not None and tmp_path.exists():
            tmp_path.unlink()


def _upload_dir() -> Path:
    path = settings.data_dir / "uploads"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _quarantine(tmp_path: Path, sha256: str) -> None:
    quarantine = settings.data_dir / "quarantine"
    quarantine.mkdir(parents=True, exist_ok=True)
    target = quarantine / f"{sha256}.bin"
    if not target.exists():
        shutil.copy2(tmp_path, target)


def _persist(db: Session, report: ScanReport) -> None:
    sample = db.get(Sample, report.sha256)
    if sample is None:
        sample = Sample(
            sha256=report.sha256,
            file_name=report.file_name,
            file_size=report.file_size,
            verdict=report.verdict.value,
            score=report.score,
            threat_name=report.threat_name,
            report_json=report.model_dump_json(),
            engine_version=report.engine_version,
        )
        db.add(sample)
    else:
        sample.verdict = report.verdict.value
        sample.score = report.score
        sample.threat_name = report.threat_name
        sample.report_json = report.model_dump_json()
        sample.engine_version = report.engine_version
        sample.scan_count += 1
    db.commit()
