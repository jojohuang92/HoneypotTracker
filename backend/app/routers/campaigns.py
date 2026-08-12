"""Campaign correlation endpoint."""

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy.orm import Session as DBSession

from app.database import get_db
from app.rate_limit import limiter
from app.schemas import Campaign
from app.services.campaigns import find_campaigns

router = APIRouter()


@router.get("", response_model=list[Campaign])
@limiter.limit("20/minute")
def list_campaigns(
    request: Request,
    days: int = Query(7, ge=1, le=90),
    sensor: str | None = Query(None, description="Restrict to one sensor"),
    limit: int = Query(50, ge=1, le=200),
    db: DBSession = Depends(get_db),
):
    """Groups of IPs running the same operation, widest first.

    Correlation is windowed because it scans raw events; the default of 7 days
    keeps it responsive on modest hardware.
    """
    return find_campaigns(db, days=days, sensor_id=sensor, limit=limit)
