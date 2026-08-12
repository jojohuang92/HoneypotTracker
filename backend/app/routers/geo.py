from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy.orm import Session as DBSession
from sqlalchemy import func, desc

from app.database import get_db
from app.models import Attempt
from app.rate_limit import limiter
from app.schemas import GeoPin

router = APIRouter()


@router.get("/pins", response_model=list[GeoPin])
@limiter.limit("30/minute")
def get_pins(
    request: Request,
    limit: int = Query(500, ge=1, le=2000),
    sensor: str | None = Query(None, description="Restrict to a single sensor id"),
    db: DBSession = Depends(get_db),
):
    """Get map pins clustered by source IP (one pin per unique IP)."""
    # Subquery to get latest attempt per IP. Rows ingested before the
    # geoip fix stored unknown locations as 0.0/0.0 — exclude those too.
    sub_q = db.query(
        Attempt.src_ip,
        func.count(Attempt.id).label("count"),
        func.max(Attempt.timestamp).label("latest_timestamp"),
    ).filter(
        Attempt.latitude.isnot(None),
        ~((Attempt.latitude == 0) & (Attempt.longitude == 0)),
    )
    if sensor:
        sub_q = sub_q.filter(Attempt.sensor_id == sensor)
    sub = sub_q.group_by(Attempt.src_ip).subquery()

    rows = (
        db.query(
            Attempt.latitude,
            Attempt.longitude,
            Attempt.country_code,
            Attempt.country_name,
            Attempt.city,
            Attempt.event_id,
            Attempt.src_ip,
            sub.c.count,
            sub.c.latest_timestamp,
        )
        .join(sub, (Attempt.src_ip == sub.c.src_ip) & (Attempt.timestamp == sub.c.latest_timestamp))
        .order_by(desc(sub.c.count))
        .limit(limit)
        .all()
    )

    return [
        GeoPin(
            latitude=r.latitude,
            longitude=r.longitude,
            count=r.count,
            country_code=r.country_code,
            country_name=r.country_name,
            city=r.city,
            latest_timestamp=r.latest_timestamp,
            latest_event_id=r.event_id,
            latest_src_ip=r.src_ip,
        )
        for r in rows
    ]
