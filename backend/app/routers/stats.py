from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session as DBSession
from sqlalchemy import func, desc, distinct, case
from datetime import datetime, timedelta, timezone

from app.database import get_db
from app.models import Attempt
from app.schemas import (
    OverviewStats, CountryRank, IntentBreakdown,
    CommandRank, CredentialPair, TimelineBucket,
)

router = APIRouter()

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
def overview(db: DBSession = Depends(get_db)):
    # "Today" resets at midnight PST (UTC-8)
    pst = timezone(timedelta(hours=-8))
    today_pst = datetime.now(pst).replace(hour=0, minute=0, second=0, microsecond=0)
    today = today_pst.astimezone(timezone.utc).replace(tzinfo=None)

    total = db.query(func.count(Attempt.id)).scalar() or 0
    unique_ips = db.query(func.count(distinct(Attempt.src_ip))).scalar() or 0
    unique_countries = (
        db.query(func.count(distinct(Attempt.country_code)))
        .filter(Attempt.country_code.isnot(None))
        .scalar() or 0
    )
    attacks_today = (
        db.query(func.count(Attempt.id))
        .filter(Attempt.timestamp >= today)
        .scalar() or 0
    )

    return OverviewStats(
        total_attempts=total,
        unique_ips=unique_ips,
        unique_countries=unique_countries,
        attacks_today=attacks_today,
        active_sessions=0,
    )


@router.get("/countries", response_model=list[CountryRank])
def country_rankings(
    limit: int = Query(20, ge=1, le=100),
    db: DBSession = Depends(get_db),
):
    total = db.query(func.count(Attempt.id)).scalar() or 1

    rows = (
        db.query(
            Attempt.country_code,
            Attempt.country_name,
            func.count(Attempt.id).label("count"),
        )
        .filter(Attempt.country_code.isnot(None))
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
def intent_breakdown(db: DBSession = Depends(get_db)):
    total = db.query(func.count(Attempt.id)).scalar() or 1

    rows = (
        db.query(Attempt.intent, func.count(Attempt.id).label("count"))
        .filter(Attempt.intent.isnot(None))
        .group_by(Attempt.intent)
        .order_by(desc("count"))
        .all()
    )

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
def top_commands(
    limit: int = Query(20, ge=1, le=100),
    db: DBSession = Depends(get_db),
):
    rows = (
        db.query(
            Attempt.command,
            func.count(Attempt.id).label("count"),
            Attempt.intent,
        )
        .filter(Attempt.command.isnot(None), Attempt.command != "")
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
def top_credentials(
    limit: int = Query(20, ge=1, le=100),
    db: DBSession = Depends(get_db),
):
    rows = (
        db.query(
            Attempt.username,
            Attempt.password,
            func.count(Attempt.id).label("count"),
        )
        .filter(Attempt.username.isnot(None))
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
def top_ports(
    limit: int = Query(10, ge=1, le=50),
    db: DBSession = Depends(get_db),
):
    rows = (
        db.query(
            Attempt.dst_port,
            func.count(Attempt.id).label("count"),
        )
        .filter(Attempt.dst_port.isnot(None))
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


@router.get("/timeline", response_model=list[TimelineBucket])
def timeline(
    granularity: str = Query("hour", regex="^(hour|day)$"),
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
