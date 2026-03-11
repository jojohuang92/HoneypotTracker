from fastapi import APIRouter, Depends, Query, HTTPException
from sqlalchemy.orm import Session as DBSession
from sqlalchemy import func, desc

from app.database import get_db
from app.models import Attempt
from app.schemas import AttemptOut, PaginatedAttempts

router = APIRouter()


@router.get("", response_model=PaginatedAttempts)
def list_attempts(
    page: int = Query(1, ge=1),
    limit: int = Query(50, ge=1, le=200),
    country: str | None = None,
    intent: str | None = None,
    ip: str | None = None,
    db: DBSession = Depends(get_db),
):
    query = db.query(Attempt)

    if country:
        query = query.filter(Attempt.country_code == country)
    if intent:
        query = query.filter(Attempt.intent == intent)
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
def recent_attempts(
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
def get_attempt(attempt_id: int, db: DBSession = Depends(get_db)):
    attempt = db.query(Attempt).filter(Attempt.id == attempt_id).first()
    if not attempt:
        raise HTTPException(status_code=404, detail="Attempt not found")
    return attempt
