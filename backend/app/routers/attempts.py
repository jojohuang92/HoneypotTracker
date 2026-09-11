import csv
import io
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, Query, HTTPException, Request
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session as DBSession, Query as SAQuery
from sqlalchemy import func, desc

from app.database import get_db
from app.models import Attempt
from app.rate_limit import limiter
from app.schemas import AttemptOut, PaginatedAttempts

router = APIRouter()


@router.get("/filter-options")
@limiter.limit("60/minute")
def filter_options(request: Request, db: DBSession = Depends(get_db)):
    """Return distinct values for country, event_id, and intent filters."""
    countries = (
        db.query(Attempt.country_code, Attempt.country_name)
        .filter(Attempt.country_code.isnot(None), Attempt.country_code != "")
        .distinct()
        .order_by(Attempt.country_name)
        .all()
    )
    events = (
        db.query(Attempt.event_id)
        .filter(Attempt.event_id.isnot(None))
        .distinct()
        .order_by(Attempt.event_id)
        .all()
    )
    intents = (
        db.query(Attempt.intent)
        .filter(Attempt.intent.isnot(None), Attempt.intent != "")
        .distinct()
        .order_by(Attempt.intent)
        .all()
    )
    protocols = (
        db.query(Attempt.protocol)
        .filter(Attempt.protocol.isnot(None), Attempt.protocol != "")
        .distinct()
        .order_by(Attempt.protocol)
        .all()
    )
    return {
        "countries": [{"code": c, "name": n} for c, n in countries],
        "events": [r[0] for r in events],
        "intents": [r[0] for r in intents],
        "protocols": [r[0] for r in protocols],
    }


def _filtered(
    db: DBSession,
    days: float,
    sensor: str | None,
    country: list[str] | None,
    intent: list[str] | None,
    event_id: list[str] | None,
    protocol: list[str] | None,
    port: list[int] | None,
    ip: str | None,
) -> SAQuery:
    """The attempts matching a filter set; shared by the list and the export
    so a CSV always contains exactly what the table showed."""
    query = db.query(Attempt)
    if days > 0:
        query = query.filter(
            Attempt.timestamp >= datetime.utcnow() - timedelta(days=days)
        )
    if sensor:
        query = query.filter(Attempt.sensor_id == sensor)
    if country:
        query = query.filter(Attempt.country_code.in_(country))
    if intent:
        query = query.filter(Attempt.intent.in_(intent))
    if event_id:
        query = query.filter(Attempt.event_id.in_(event_id))
    if protocol:
        query = query.filter(Attempt.protocol.in_([p.lower() for p in protocol]))
    if port:
        query = query.filter(Attempt.dst_port.in_(port))
    if ip:
        query = query.filter(Attempt.src_ip == ip)
    return query


@router.get("", response_model=PaginatedAttempts)
@limiter.limit("60/minute")
def list_attempts(
    request: Request,
    page: int = Query(1, ge=1),
    limit: int = Query(50, ge=1, le=200),
    country: list[str] | None = Query(None),
    intent: list[str] | None = Query(None),
    event_id: list[str] | None = Query(None),
    protocol: list[str] | None = Query(None, description="ssh / telnet"),
    port: list[int] | None = Query(None, description="Targeted port"),
    ip: str | None = None,
    days: float = Query(0, ge=0, le=365),
    sensor: str | None = Query(None, description="Restrict to a single sensor id"),
    db: DBSession = Depends(get_db),
):
    query = _filtered(db, days, sensor, country, intent, event_id, protocol, port, ip)

    total = query.count()
    pages = max(1, (total + limit - 1) // limit)
    items = (
        query.order_by(desc(Attempt.timestamp))
        .offset((page - 1) * limit)
        .limit(limit)
        .all()
    )

    return PaginatedAttempts(items=items, total=total, page=page, pages=pages)


EXPORT_COLUMNS = [
    "timestamp", "sensor_id", "session_id", "event_id", "src_ip", "src_port",
    "dst_port", "protocol", "country_code", "country_name", "city",
    "username", "password", "command", "success", "intent", "mitre_id",
]
EXPORT_MAX_ROWS = 50_000
EXPORT_CHUNK = 1_000


def _csv_cell(value):
    if value is None:
        return ""
    if isinstance(value, datetime):
        return value.strftime("%Y-%m-%dT%H:%M:%SZ")
    if isinstance(value, bool):
        return "true" if value else "false"
    text = str(value)
    # A cell starting with a formula trigger is executed by spreadsheet apps.
    # Attackers type these characters, so neutralise them for the analyst.
    if text[:1] in ("=", "+", "-", "@") or text[:1] in ("\t", "\r"):
        text = "'" + text
    return text


@router.get("/export.csv")
@limiter.limit("10/minute")
def export_attempts_csv(
    request: Request,
    country: list[str] | None = Query(None),
    intent: list[str] | None = Query(None),
    event_id: list[str] | None = Query(None),
    protocol: list[str] | None = Query(None),
    port: list[int] | None = Query(None),
    ip: str | None = None,
    days: float = Query(0, ge=0, le=365),
    sensor: str | None = Query(None),
    db: DBSession = Depends(get_db),
):
    """The filtered attempts as CSV, newest first, capped at EXPORT_MAX_ROWS.

    Takes the same filters as the list endpoint so the download matches the
    view. Streams in chunks: a wide window on a busy sensor is tens of
    thousands of rows, and building that in memory would stall the worker.
    """
    query = (
        _filtered(db, days, sensor, country, intent, event_id, protocol, port, ip)
        .order_by(desc(Attempt.timestamp), desc(Attempt.id))
    )

    def rows():
        buf = io.StringIO()
        writer = csv.writer(buf, lineterminator="\n")
        writer.writerow(EXPORT_COLUMNS)
        yield buf.getvalue()
        sent = 0
        offset = 0
        while sent < EXPORT_MAX_ROWS:
            chunk = query.offset(offset).limit(min(EXPORT_CHUNK, EXPORT_MAX_ROWS - sent)).all()
            if not chunk:
                break
            buf.seek(0)
            buf.truncate()
            for a in chunk:
                writer.writerow([_csv_cell(getattr(a, col)) for col in EXPORT_COLUMNS])
            yield buf.getvalue()
            sent += len(chunk)
            offset += len(chunk)
            if len(chunk) < EXPORT_CHUNK:
                break

    stamp = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    return StreamingResponse(
        rows(),
        media_type="text/csv; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="attempts-{stamp}.csv"',
            "Cache-Control": "no-store",
        },
    )


@router.get("/recent", response_model=list[AttemptOut])
@limiter.limit("60/minute")
def recent_attempts(
    request: Request,
    limit: int = Query(50, ge=1, le=200),
    db: DBSession = Depends(get_db),
):
    return (
        db.query(Attempt)
        .order_by(desc(Attempt.timestamp))
        .limit(limit)
        .all()
    )


@router.get("/{attempt_id}", response_model=AttemptOut)
@limiter.limit("60/minute")
def get_attempt(request: Request, attempt_id: int, db: DBSession = Depends(get_db)):
    attempt = db.query(Attempt).filter(Attempt.id == attempt_id).first()
    if not attempt:
        raise HTTPException(status_code=404, detail="Attempt not found")
    return attempt
