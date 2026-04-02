from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy.orm import Session as DBSession
from sqlalchemy import func, desc

from app.database import get_db
from app.models import Attempt, IPScore
from app.rate_limit import limiter
from app.schemas import UniqueIP
from app.services.abuseipdb import get_cached_score, fetch_and_cache_score

router = APIRouter()


@router.get("", response_model=list[UniqueIP])
@limiter.limit("60/minute")
def list_unique_ips(
    request: Request,
    limit: int = Query(50, ge=1, le=200),
    db: DBSession = Depends(get_db),
):
    """Return unique IPs ranked by attack count, with cached AbuseIPDB scores."""
    rows = (
        db.query(
            Attempt.src_ip,
            func.count(Attempt.id).label("count"),
            func.max(Attempt.country_code).label("country_code"),
            func.max(Attempt.country_name).label("country_name"),
            func.max(Attempt.city).label("city"),
            func.max(Attempt.timestamp).label("latest_timestamp"),
        )
        .group_by(Attempt.src_ip)
        .order_by(desc("count"))
        .limit(limit)
        .all()
    )

    # Batch-load cached scores
    ips = [r.src_ip for r in rows]
    cached = {
        s.ip: s
        for s in db.query(IPScore).filter(IPScore.ip.in_(ips)).all()
    }

    result = []
    for r in rows:
        score_row = cached.get(r.src_ip)
        result.append(UniqueIP(
            src_ip=r.src_ip,
            count=r.count,
            country_code=r.country_code,
            country_name=r.country_name,
            city=r.city,
            latest_timestamp=r.latest_timestamp,
            abuse_score=score_row.abuse_score if score_row else None,
            isp=score_row.isp if score_row else None,
            usage_type=score_row.usage_type if score_row else None,
            total_reports=score_row.total_reports if score_row else None,
        ))

    return result


@router.post("/{ip}/score", response_model=UniqueIP | dict)
@limiter.limit("10/minute")
def lookup_ip_score(request: Request, ip: str, db: DBSession = Depends(get_db)):
    """Fetch (or refresh) the AbuseIPDB score for a single IP."""
    score_row = fetch_and_cache_score(db, ip)

    # Get attack stats for this IP
    stats = (
        db.query(
            func.count(Attempt.id).label("count"),
            func.max(Attempt.country_code).label("country_code"),
            func.max(Attempt.country_name).label("country_name"),
            func.max(Attempt.city).label("city"),
            func.max(Attempt.timestamp).label("latest_timestamp"),
        )
        .filter(Attempt.src_ip == ip)
        .first()
    )

    return UniqueIP(
        src_ip=ip,
        count=stats.count if stats else 0,
        country_code=stats.country_code if stats else None,
        country_name=stats.country_name if stats else None,
        city=stats.city if stats else None,
        latest_timestamp=stats.latest_timestamp if stats else None,
        abuse_score=score_row.abuse_score if score_row else None,
        isp=score_row.isp if score_row else None,
        usage_type=score_row.usage_type if score_row else None,
        total_reports=score_row.total_reports if score_row else None,
    )
