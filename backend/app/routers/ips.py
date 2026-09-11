import ipaddress

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.orm import Session as DBSession
from sqlalchemy import func, desc

from app.database import get_db
from app.models import Attempt, IPIntel, IPScore
from app.rate_limit import limiter
from app.schemas import IPIntelOut, ThreatScore, UniqueIP
from app.services.abuseipdb import RateLimitedError, fetch_and_cache_score
from app.services.ip_intel import intel_for_ips, summarize
from app.services.threat_score import score_ip, score_ips

router = APIRouter()


@router.get("", response_model=list[UniqueIP])
@limiter.limit("60/minute")
def list_unique_ips(
    request: Request,
    limit: int | None = Query(None, ge=1),
    sensor: str | None = Query(None, description="Restrict to a single sensor id"),
    scored: bool = Query(False, description="Include composite threat scores"),
    db: DBSession = Depends(get_db),
):
    """Return unique IPs ranked by attack count, with cached AbuseIPDB scores.

    When ``limit`` is omitted, returns every distinct source IP. Threat scoring
    is opt-in because it costs several extra aggregate queries.
    """
    query = db.query(
        Attempt.src_ip,
        func.count(Attempt.id).label("count"),
        func.max(Attempt.country_code).label("country_code"),
        func.max(Attempt.country_name).label("country_name"),
        func.max(Attempt.city).label("city"),
        func.max(Attempt.timestamp).label("latest_timestamp"),
        func.count(func.distinct(Attempt.sensor_id)).label("sensor_count"),
    )
    if sensor:
        query = query.filter(Attempt.sensor_id == sensor)
    query = query.group_by(Attempt.src_ip).order_by(desc("count"))
    if limit is not None:
        query = query.limit(limit)
    rows = query.all()

    # Batch-load cached scores
    ips = [r.src_ip for r in rows]
    cached = {
        s.ip: s
        for s in db.query(IPScore).filter(IPScore.ip.in_(ips)).all()
    }
    threat = score_ips(db, ips) if scored else {}
    intel = intel_for_ips(db, ips)

    result = []
    for r in rows:
        score_row = cached.get(r.src_ip)
        ts = threat.get(r.src_ip)
        ii = intel.get(r.src_ip)
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
            sensor_count=r.sensor_count or 0,
            threat_score=ts.total if ts else None,
            threat_level=ts.level if ts else None,
            tags=ii.tags if ii else [],
            open_ports=ii.open_ports if ii else [],
        ))

    return result


@router.get("/{ip}/intel", response_model=IPIntelOut)
@limiter.limit("60/minute")
def ip_intel(request: Request, ip: str, db: DBSession = Depends(get_db)):
    """Infrastructure context for one IP: tags, exposed ports, CVEs, Tor.

    Never triggers a lookup — the background worker owns the upstream rate
    budget. An IP the worker has not reached yet answers with empty fields.
    """
    row = db.query(IPIntel).filter(IPIntel.ip == ip).first()
    summary = summarize(row, ip)
    return IPIntelOut(
        ip=ip,
        found=bool(row.found) if row else False,
        tags=summary.tags,
        open_ports=summary.open_ports,
        hostnames=summary.hostnames,
        cpes=summary.cpes,
        vulns=summary.vulns,
        is_tor=summary.is_tor,
        fetched_at=summary.fetched_at,
    )


@router.get("/{ip}/threat", response_model=ThreatScore)
@limiter.limit("60/minute")
def ip_threat_score(request: Request, ip: str, db: DBSession = Depends(get_db)):
    """The composite threat score for one IP, with its component breakdown."""
    return score_ip(db, ip)


@router.post("/{ip}/score", response_model=UniqueIP | dict)
@limiter.limit("10/minute")
def lookup_ip_score(request: Request, ip: str, db: DBSession = Depends(get_db)):
    """Fetch (or refresh) the AbuseIPDB score for a single IP."""
    # Validate before spending AbuseIPDB quota or caching junk identifiers
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid IP address")
    if not addr.is_global:
        raise HTTPException(status_code=400, detail="IP address is not publicly routable")

    try:
        score_row = fetch_and_cache_score(db, ip)
    except RateLimitedError:
        raise HTTPException(
            status_code=429, detail="AbuseIPDB quota exhausted — try again later"
        )

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
