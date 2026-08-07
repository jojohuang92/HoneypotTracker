from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy.orm import Session as DBSession
from sqlalchemy import func, desc, distinct
from datetime import datetime, timedelta

from app.database import get_db
from app.mitre import TACTIC_NAME_BY_ID, TACTICS, tactic_for, technique_name_for
from app.models import Attempt
from app.rate_limit import limiter
from app.schemas import (
    OverviewStats, CountryRank, IntentBreakdown,
    CommandRank, CredentialPair, TimelineBucket,
    MitreMatrix, MitreTactic, MitreTechnique,
)
from app.time_utils import local_midnight_utc_naive

router = APIRouter()

# Shared "days" query param: 0 = all time, otherwise a trailing window.
DaysQuery = Query(0, ge=0, le=365, description="Restrict to the last N days (0 = all time)")


def _since(days: float) -> datetime | None:
    return datetime.utcnow() - timedelta(days=days) if days > 0 else None

INTENT_DESCRIPTIONS = {
    "brute_force": "Repeated login attempts to guess credentials",
    "reconnaissance": "System enumeration and information gathering",
    "malware_deployment": "Downloading and executing malicious payloads",
    "persistence": "Establishing persistent backdoor access",
    "cryptomining": "Deploying cryptocurrency mining software",
    "credential_theft": "Stealing passwords and authentication tokens",
    "sabotage": "Destructive actions against the system",
    "lateral_movement": "Attempting to pivot to other systems",
    "scanning": "Port scanning and network reconnaissance",
    "data_exfiltration": "Extracting sensitive data from the system",
}

INTENT_MITRE = {
    "brute_force": "T1110",
    "reconnaissance": "T1592",
    "malware_deployment": "T1059",
    "persistence": "T1053",
    "cryptomining": "T1496",
    "credential_theft": "T1003",
    "sabotage": "T1485",
    "lateral_movement": "T1021",
    "scanning": "T1046",
    "data_exfiltration": "T1041",
}


@router.get("/overview", response_model=OverviewStats)
@limiter.limit("60/minute")
def overview(request: Request, days: float = DaysQuery, db: DBSession = Depends(get_db)):
    today = local_midnight_utc_naive()
    since = _since(days)

    total_q = db.query(func.count(Attempt.id))
    ips_q = db.query(func.count(distinct(Attempt.src_ip)))
    countries_q = (
        db.query(func.count(distinct(Attempt.country_code)))
        .filter(Attempt.country_code.isnot(None))
    )
    if since:
        total_q = total_q.filter(Attempt.timestamp >= since)
        ips_q = ips_q.filter(Attempt.timestamp >= since)
        countries_q = countries_q.filter(Attempt.timestamp >= since)

    attacks_today = (
        db.query(func.count(Attempt.id))
        .filter(Attempt.timestamp >= today)
        .scalar() or 0
    )

    prev_attempts = None
    if since:
        prev_since = since - timedelta(days=days)
        prev_attempts = (
            db.query(func.count(Attempt.id))
            .filter(Attempt.timestamp >= prev_since, Attempt.timestamp < since)
            .scalar() or 0
        )

    return OverviewStats(
        total_attempts=total_q.scalar() or 0,
        unique_ips=ips_q.scalar() or 0,
        unique_countries=countries_q.scalar() or 0,
        attacks_today=attacks_today,
        active_sessions=0,
        prev_attempts=prev_attempts,
    )


@router.get("/countries", response_model=list[CountryRank])
@limiter.limit("60/minute")
def country_rankings(
    request: Request,
    limit: int = Query(20, ge=1, le=100),
    days: float = DaysQuery,
    db: DBSession = Depends(get_db),
):
    since = _since(days)
    total_q = db.query(func.count(Attempt.id))
    rows_q = (
        db.query(
            Attempt.country_code,
            Attempt.country_name,
            func.count(Attempt.id).label("count"),
        )
        .filter(Attempt.country_code.isnot(None))
    )
    if since:
        total_q = total_q.filter(Attempt.timestamp >= since)
        rows_q = rows_q.filter(Attempt.timestamp >= since)

    total = total_q.scalar() or 1
    rows = (
        rows_q
        .group_by(Attempt.country_code, Attempt.country_name)
        .order_by(desc("count"))
        .limit(limit)
        .all()
    )

    return [
        CountryRank(
            country_code=r.country_code,
            country_name=r.country_name or r.country_code,
            count=r.count,
            percentage=round(r.count / total * 100, 1),
        )
        for r in rows
    ]


@router.get("/intents", response_model=list[IntentBreakdown])
@limiter.limit("60/minute")
def intent_breakdown(request: Request, days: float = DaysQuery, db: DBSession = Depends(get_db)):
    since = _since(days)
    total_q = db.query(func.count(Attempt.id))
    rows_q = db.query(Attempt.intent, func.count(Attempt.id).label("count")).filter(
        Attempt.intent.isnot(None)
    )
    if since:
        total_q = total_q.filter(Attempt.timestamp >= since)
        rows_q = rows_q.filter(Attempt.timestamp >= since)

    total = total_q.scalar() or 1
    rows = rows_q.group_by(Attempt.intent).order_by(desc("count")).all()

    return [
        IntentBreakdown(
            intent=r.intent,
            count=r.count,
            percentage=round(r.count / total * 100, 1),
            mitre_id=INTENT_MITRE.get(r.intent),
            description=INTENT_DESCRIPTIONS.get(r.intent),
        )
        for r in rows
    ]


@router.get("/commands", response_model=list[CommandRank])
@limiter.limit("60/minute")
def top_commands(
    request: Request,
    limit: int = Query(20, ge=1, le=100),
    days: float = DaysQuery,
    db: DBSession = Depends(get_db),
):
    since = _since(days)
    rows_q = db.query(
        Attempt.command,
        func.count(Attempt.id).label("count"),
        Attempt.intent,
    ).filter(Attempt.command.isnot(None), Attempt.command != "")
    if since:
        rows_q = rows_q.filter(Attempt.timestamp >= since)

    rows = (
        rows_q
        .group_by(Attempt.command)
        .order_by(desc("count"))
        .limit(limit)
        .all()
    )

    return [
        CommandRank(command=r.command, count=r.count, intent=r.intent)
        for r in rows
    ]


@router.get("/credentials", response_model=list[CredentialPair])
@limiter.limit("60/minute")
def top_credentials(
    request: Request,
    limit: int = Query(20, ge=1, le=100),
    days: float = DaysQuery,
    db: DBSession = Depends(get_db),
):
    since = _since(days)
    rows_q = db.query(
        Attempt.username,
        Attempt.password,
        func.count(Attempt.id).label("count"),
    ).filter(Attempt.username.isnot(None))
    if since:
        rows_q = rows_q.filter(Attempt.timestamp >= since)

    rows = (
        rows_q
        .group_by(Attempt.username, Attempt.password)
        .order_by(desc("count"))
        .limit(limit)
        .all()
    )

    return [
        CredentialPair(
            username=r.username or "",
            password=r.password or "",
            count=r.count,
        )
        for r in rows
    ]


@router.get("/ports", response_model=list[dict])
@limiter.limit("60/minute")
def top_ports(
    request: Request,
    limit: int = Query(10, ge=1, le=50),
    days: float = DaysQuery,
    db: DBSession = Depends(get_db),
):
    since = _since(days)
    rows_q = db.query(
        Attempt.dst_port,
        func.count(Attempt.id).label("count"),
    ).filter(Attempt.dst_port.isnot(None))
    if since:
        rows_q = rows_q.filter(Attempt.timestamp >= since)

    rows = (
        rows_q
        .group_by(Attempt.dst_port)
        .order_by(desc("count"))
        .limit(limit)
        .all()
    )
    total = sum(r.count for r in rows) or 1
    return [
        {"port": r.dst_port, "count": r.count, "percentage": round(r.count / total * 100, 1)}
        for r in rows
    ]


@router.get("/mitre", response_model=MitreMatrix)
@limiter.limit("60/minute")
def mitre_matrix(request: Request, days: float = DaysQuery, db: DBSession = Depends(get_db)):
    """Return observed MITRE ATT&CK techniques grouped by tactic, with counts."""
    since = _since(days)
    rows_q = db.query(Attempt.mitre_id, func.count(Attempt.id).label("count")).filter(
        Attempt.mitre_id.isnot(None)
    )
    if since:
        rows_q = rows_q.filter(Attempt.timestamp >= since)

    rows = rows_q.group_by(Attempt.mitre_id).order_by(desc("count")).all()

    by_tactic: dict[str, list[MitreTechnique]] = {}
    totals: dict[str, int] = {}
    grand_total = 0

    for r in rows:
        tactic_id = tactic_for(r.mitre_id)
        if not tactic_id:
            continue  # drop unknown technique IDs rather than inventing a tactic
        technique = MitreTechnique(
            mitre_id=r.mitre_id,
            technique_name=technique_name_for(r.mitre_id),
            tactic_id=tactic_id,
            tactic_name=TACTIC_NAME_BY_ID[tactic_id],
            count=r.count,
        )
        by_tactic.setdefault(tactic_id, []).append(technique)
        totals[tactic_id] = totals.get(tactic_id, 0) + r.count
        grand_total += r.count

    tactics = []
    # Preserve MITRE Navigator column order
    for tactic_id, tactic_name in TACTICS:
        if tactic_id not in by_tactic:
            continue
        techniques = sorted(by_tactic[tactic_id], key=lambda t: -t.count)
        tactics.append(MitreTactic(
            tactic_id=tactic_id,
            tactic_name=tactic_name,
            total=totals[tactic_id],
            techniques=techniques,
        ))

    return MitreMatrix(tactics=tactics, grand_total=grand_total)


@router.get("/timeline", response_model=list[TimelineBucket])
@limiter.limit("30/minute")
def timeline(
    request: Request,
    granularity: str = Query("hour", pattern="^(hour|day)$"),
    days: float = Query(7, ge=0.1, le=90),
    tz_offset: int = Query(0, ge=-720, le=840, description="Local UTC offset in minutes"),
    db: DBSession = Depends(get_db),
):
    since = datetime.utcnow() - timedelta(days=days)

    if granularity == "hour":
        fmt = "%Y-%m-%d %H:00"
        step = timedelta(hours=1)
    else:
        fmt = "%Y-%m-%d"
        step = timedelta(days=1)

    # Shift stored UTC timestamps into the caller's local timezone before bucketing
    local_ts = func.datetime(Attempt.timestamp, f"{tz_offset:+d} minutes")

    rows = (
        db.query(
            func.strftime(fmt, local_ts).label("bucket"),
            func.count(Attempt.id).label("count"),
        )
        .filter(Attempt.timestamp >= since)
        .group_by("bucket")
        .order_by("bucket")
        .all()
    )

    counts = {r.bucket: r.count for r in rows}

    # Build the full range of buckets so gaps show as zero
    offset_delta = timedelta(minutes=tz_offset)
    local_now = datetime.utcnow() + offset_delta
    local_since = since + offset_delta
    # Truncate to the start of the current bucket
    if granularity == "hour":
        cursor = local_since.replace(minute=0, second=0, microsecond=0)
    else:
        cursor = local_since.replace(hour=0, minute=0, second=0, microsecond=0)

    result = []
    while cursor <= local_now:
        key = cursor.strftime(fmt)
        result.append(TimelineBucket(bucket=key, count=counts.get(key, 0)))
        cursor += step

    return result
