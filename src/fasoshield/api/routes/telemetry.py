"""Anonymised agent telemetry: feeds the national threat statistics."""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from ...db.models import TelemetryEvent
from ..deps import AuthDep, get_db
from ..schemas import TelemetryAck, TelemetryIn

router = APIRouter(tags=["telemetry"])


@router.post("/v1/telemetry", response_model=TelemetryAck, dependencies=[AuthDep])
def submit_telemetry(event: TelemetryIn, db: Session = Depends(get_db)) -> TelemetryAck:
    db.add(
        TelemetryEvent(
            agent_id=event.agent_id,
            event_type=event.event_type,
            sha256=event.sha256.lower() if event.sha256 else None,
            package_name=event.package_name,
            verdict=event.verdict.value if event.verdict else None,
            threat_name=event.threat_name,
            region=event.region,
        )
    )
    db.commit()
    return TelemetryAck(accepted=True, received_at=datetime.now(timezone.utc))
