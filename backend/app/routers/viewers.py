from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session as DBSession
from sqlalchemy import func, distinct

from app.database import get_db
from app.models import PageView

router = APIRouter()


def _get_visitor_ip(request: Request) -> str:
    """Extract visitor IP from trusted nginx headers, with validation."""
    import ipaddress as _ipa

    candidate = (
        request.headers.get("X-Real-IP")
        or request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
        or (request.client.host if request.client else "unknown")
    )
    # Validate it looks like a real IP address
    try:
        _ipa.ip_address(candidate)
    except ValueError:
        candidate = request.client.host if request.client else "unknown"
    return candidate


@router.post("/view")
def record_view(request: Request, db: DBSession = Depends(get_db)):
    """Record a page visit."""
    db.add(PageView(
        visitor_ip=_get_visitor_ip(request),
        user_agent=request.headers.get("User-Agent", ""),
    ))
    db.commit()
    return {"ok": True}


@router.get("/viewers")
def get_viewers(db: DBSession = Depends(get_db)):
    """Return total and unique visitor counts."""
    total = db.query(func.count(PageView.id)).scalar() or 0
    unique = db.query(func.count(distinct(PageView.visitor_ip))).scalar() or 0
    today = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
    today_total = (
        db.query(func.count(PageView.id))
        .filter(PageView.visited_at >= today)
        .scalar() or 0
    )
    last_24h = datetime.utcnow() - timedelta(hours=24)
    active = (
        db.query(func.count(distinct(PageView.visitor_ip)))
        .filter(PageView.visited_at >= last_24h)
        .scalar() or 0
    )
    return {
        "total_views": total,
        "unique_visitors": unique,
        "views_today": today_total,
        "unique_last_24h": active,
    }
