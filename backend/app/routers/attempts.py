from fastapi import APIRouter, Depends, Query, HTTPException, Request
from sqlalchemy.orm import Session as DBSession
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
    return {
        "countries": [{"code": c, "name": n} for c, n in countries],
        "events": [r[0] for r in events],
        "intents": [r[0] for r in intents],
    }


@router.get("", response_model=PaginatedAttempts)
@limiter.limit("60/minute")
def list_attempts(
    request: Request,
    page: int = Query(1, ge=1),
    limit: int = Query(50, ge=1, le=200),
    country: list[str] | None = Query(None),
    intent: list[str] | None = Query(None),
    event_id: list[str] | None = Query(None),
    ip: str | None = None,
    db: DBSession = Depends(get_db),
):
    query = db.query(Attempt)

    if country:
        query = query.filter(Attempt.country_code.in_(country))
    if intent:
        query = query.filter(Attempt.intent.in_(intent))
    if event_id:
        query = query.filter(Attempt.event_id.in_(event_id))
    if ip:
        query = query.filter(Attempt.src_ip == ip)

    total = query.count()
    pages = max(1, (total + limit - 1) // limit)
    items = (
        query.order_by(desc(Attempt.timestamp))
        .offset((page - 1) * limit)
        .limit(limit)
        .all()
    )

    return PaginatedAttempts(items=items, total=total, page=page, pages=pages)


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
