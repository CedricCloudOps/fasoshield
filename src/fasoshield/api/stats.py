"""SOC console aggregations.

Two complementary views feed the analyst dashboard:

- the *corpus* — every file the platform has scanned (Sample table);
- the *field* — anonymised detections reported by mobile agents
  (TelemetryEvent table), which paints the national threat picture.

All queries are plain SQLAlchemy Core selects so they run identically on the
SQLite dev database and a PostgreSQL production instance.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..db.models import Sample, TelemetryEvent
from ..engine.hashdb import HashDB

DETECTION_VERDICTS = ("SUSPICIOUS", "MALICIOUS")


def signature_stats(hashdb: HashDB) -> dict:
    stats = hashdb.stats()
    return {
        "version": stats["version"],
        "blocklist": stats["blocklist"],
        "official_apps": stats["official_apps"],
    }


def corpus_stats(db: Session) -> dict:
    verdict_rows = db.execute(
        select(Sample.verdict, func.count()).group_by(Sample.verdict)
    ).all()
    verdicts = {verdict: count for verdict, count in verdict_rows}
    samples = sum(verdicts.values())
    detections = sum(verdicts.get(v, 0) for v in DETECTION_VERDICTS)
    return {
        "samples": samples,
        "detections": detections,
        "verdicts": [
            {"verdict": verdict, "count": count}
            for verdict, count in sorted(verdicts.items())
        ],
    }


def field_stats(db: Session, days: int = 14) -> dict:
    detection = TelemetryEvent.event_type == "detection"

    events = db.scalar(select(func.count()).select_from(TelemetryEvent)) or 0
    agents = db.scalar(select(func.count(func.distinct(TelemetryEvent.agent_id)))) or 0
    detections = db.scalar(
        select(func.count()).select_from(TelemetryEvent).where(detection)
    ) or 0

    by_region = [
        {"label": region or "inconnue", "count": count}
        for region, count in db.execute(
            select(TelemetryEvent.region, func.count())
            .where(detection)
            .group_by(TelemetryEvent.region)
            .order_by(func.count().desc())
        ).all()
    ]
    top_threats = [
        {"label": threat, "count": count}
        for threat, count in db.execute(
            select(TelemetryEvent.threat_name, func.count())
            .where(detection, TelemetryEvent.threat_name.is_not(None))
            .group_by(TelemetryEvent.threat_name)
            .order_by(func.count().desc())
            .limit(10)
        ).all()
    ]

    # Daily detection counts over the trailing window, zero-filled so the
    # timeline has one point per day even when nothing was reported.
    since = datetime.now(timezone.utc) - timedelta(days=days - 1)
    day = func.date(TelemetryEvent.created_at)
    counted = dict(
        db.execute(
            select(day, func.count())
            .where(detection, TelemetryEvent.created_at >= since)
            .group_by(day)
        ).all()
    )
    timeline = []
    for offset in range(days):
        d = (since + timedelta(days=offset)).date().isoformat()
        timeline.append({"date": d, "count": int(counted.get(d, 0))})

    return {
        "events": events,
        "agents": agents,
        "detections": detections,
        "by_region": by_region,
        "top_threats": top_threats,
        "timeline": timeline,
    }


def recent_detections(db: Session, limit: int = 12) -> list[dict]:
    rows = db.execute(
        select(TelemetryEvent)
        .where(TelemetryEvent.event_type == "detection")
        .order_by(TelemetryEvent.created_at.desc())
        .limit(limit)
    ).scalars()
    return [
        {
            "created_at": ev.created_at,
            "verdict": ev.verdict,
            "threat_name": ev.threat_name,
            "package_name": ev.package_name,
            "region": ev.region,
        }
        for ev in rows
    ]


def overview(db: Session, hashdb: HashDB) -> dict:
    return {
        "generated_at": datetime.now(timezone.utc),
        "signatures": signature_stats(hashdb),
        "corpus": corpus_stats(db),
        "field": field_stats(db),
        "recent_detections": recent_detections(db),
    }
