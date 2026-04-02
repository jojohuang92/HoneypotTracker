"""Attacker profiling endpoint — groups all activity by source IP."""

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session as DBSession
from sqlalchemy import func, desc

from app.database import get_db
from app.models import Attempt, Session, CapturedFile, IPScore
from app.rate_limit import limiter
from app.schemas import (
    AttackerProfile, IntentBreakdown, CommandRank,
    CredentialPair, SessionSummary, TimelineBucket,
)

router = APIRouter()


@router.get("/{ip}", response_model=AttackerProfile)
@limiter.limit("30/minute")
def get_attacker_profile(request: Request, ip: str, db: DBSession = Depends(get_db)):
    """Build a full attacker profile for a given source IP."""
    # Check if IP exists
    total = db.query(func.count(Attempt.id)).filter(Attempt.src_ip == ip).scalar() or 0
    if total == 0:
        raise HTTPException(status_code=404, detail="IP not found")

    # Basic info from latest attempt
    latest = (
        db.query(Attempt)
        .filter(Attempt.src_ip == ip)
        .order_by(desc(Attempt.timestamp))
        .first()
    )

    first_seen = (
        db.query(func.min(Attempt.timestamp))
        .filter(Attempt.src_ip == ip)
        .scalar()
    )
    last_seen = (
        db.query(func.max(Attempt.timestamp))
        .filter(Attempt.src_ip == ip)
        .scalar()
    )

    # Counts
    total_commands = (
        db.query(func.count(Attempt.id))
        .filter(Attempt.src_ip == ip, Attempt.event_id == "cowrie.command.input")
        .scalar() or 0
    )
    total_files = (
        db.query(func.count(CapturedFile.id))
        .join(Attempt, CapturedFile.attempt_id == Attempt.id)
        .filter(Attempt.src_ip == ip)
        .scalar() or 0
    )
    total_sessions = (
        db.query(func.count(Session.id))
        .filter(Session.src_ip == ip)
        .scalar() or 0
    )

    # Intent breakdown for this IP
    intent_rows = (
        db.query(Attempt.intent, func.count(Attempt.id).label("count"))
        .filter(Attempt.src_ip == ip, Attempt.intent.isnot(None))
        .group_by(Attempt.intent)
        .order_by(desc("count"))
        .all()
    )
    intents = [
        IntentBreakdown(
            intent=r.intent,
            count=r.count,
            percentage=round(r.count / total * 100, 1) if total else 0,
        )
        for r in intent_rows
    ]

    # Top commands
    cmd_rows = (
        db.query(Attempt.command, func.count(Attempt.id).label("count"), Attempt.intent)
        .filter(Attempt.src_ip == ip, Attempt.command.isnot(None), Attempt.command != "")
        .group_by(Attempt.command)
        .order_by(desc("count"))
        .limit(15)
        .all()
    )
    top_commands = [
        CommandRank(command=r.command, count=r.count, intent=r.intent)
        for r in cmd_rows
    ]

    # Top credentials
    cred_rows = (
        db.query(Attempt.username, Attempt.password, func.count(Attempt.id).label("count"))
        .filter(Attempt.src_ip == ip, Attempt.username.isnot(None))
        .group_by(Attempt.username, Attempt.password)
        .order_by(desc("count"))
        .limit(10)
        .all()
    )
    top_credentials = [
        CredentialPair(username=r.username or "", password=r.password or "", count=r.count)
        for r in cred_rows
    ]

    # Sessions
    sess_rows = (
        db.query(Session)
        .filter(Session.src_ip == ip)
        .order_by(desc(Session.start_time))
        .limit(20)
        .all()
    )
    sessions = [SessionSummary.model_validate(s) for s in sess_rows]

    # Activity timeline (daily buckets)
    timeline_rows = (
        db.query(
            func.strftime("%Y-%m-%d", Attempt.timestamp).label("bucket"),
            func.count(Attempt.id).label("count"),
        )
        .filter(Attempt.src_ip == ip)
        .group_by("bucket")
        .order_by("bucket")
        .all()
    )
    timeline = [TimelineBucket(bucket=r.bucket, count=r.count) for r in timeline_rows]

    # Abuse score
    score_row = db.query(IPScore).filter(IPScore.ip == ip).first()

    return AttackerProfile(
        src_ip=ip,
        country_code=latest.country_code if latest else None,
        country_name=latest.country_name if latest else None,
        city=latest.city if latest else None,
        asn=latest.asn if latest else None,
        as_org=latest.as_org if latest else None,
        abuse_score=score_row.abuse_score if score_row else None,
        isp=score_row.isp if score_row else None,
        first_seen=first_seen,
        last_seen=last_seen,
        total_attempts=total,
        total_sessions=total_sessions,
        total_commands=total_commands,
        total_files=total_files,
        intents=intents,
        top_commands=top_commands,
        top_credentials=top_credentials,
        sessions=sessions,
        timeline=timeline,
    )
