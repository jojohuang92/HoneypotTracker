"""Full-text search across commands, usernames, passwords, IPs, and filenames."""

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy.orm import Session as DBSession
from sqlalchemy import func, desc, or_

from app.database import get_db
from app.models import Attempt
from app.rate_limit import limiter
from app.schemas import SearchResult, AttemptOut

router = APIRouter()


@router.get("", response_model=SearchResult)
@limiter.limit("30/minute")
def search(
    request: Request,
    q: str = Query(..., min_length=1, max_length=200),
    limit: int = Query(50, ge=1, le=200),
    db: DBSession = Depends(get_db),
):
    """Search across commands, usernames, passwords, IPs, and session IDs."""
    pattern = f"%{q}%"

    query = (
        db.query(Attempt)
        .filter(
            or_(
                Attempt.src_ip.ilike(pattern),
                Attempt.command.ilike(pattern),
                Attempt.username.ilike(pattern),
                Attempt.password.ilike(pattern),
                Attempt.session_id.ilike(pattern),
                Attempt.country_name.ilike(pattern),
                Attempt.city.ilike(pattern),
                Attempt.as_org.ilike(pattern),
            )
        )
    )

    total = query.count()
    items = (
        query.order_by(desc(Attempt.timestamp))
        .limit(limit)
        .all()
    )

    return SearchResult(items=items, total=total, query=q)
