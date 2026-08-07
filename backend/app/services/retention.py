"""Data retention: aggregate completed days into DailyStat, prune raw rows.

On a small host (Raspberry Pi SD card) the SQLite database grows without
bound. This worker writes one DailyStat row per completed UTC day — always,
so long-term trends survive pruning — and, when ``retention_days`` > 0,
deletes attempts, sessions, and page views older than the window.

Captured-file metadata, report logs, IP scores, and daily aggregates are
never pruned: they are small and they are the honeypot's long-term record.
"""

import asyncio
import logging
from datetime import date, datetime, timedelta

from sqlalchemy import distinct, func
from sqlalchemy.orm import Session as DBSession

from app.config import settings
from app.database import SessionLocal
from app.models import Attempt, DailyStat, PageView, Session

logger = logging.getLogger(__name__)

# Seconds between retention passes
RUN_INTERVAL = 6 * 3600


def _day_bounds(day: date) -> tuple[datetime, datetime]:
    start = datetime.combine(day, datetime.min.time())
    return start, start + timedelta(days=1)


def _top_value(db: DBSession, column, start: datetime, end: datetime) -> str | None:
    row = (
        db.query(column)
        .filter(
            Attempt.timestamp >= start,
            Attempt.timestamp < end,
            column.isnot(None),
            column != "",
        )
        .group_by(column)
        .order_by(func.count(Attempt.id).desc())
        .first()
    )
    return row[0] if row else None


def aggregate_day(db: DBSession, day: date) -> DailyStat | None:
    """Upsert the DailyStat row for one UTC day. Returns None for empty days."""
    start, end = _day_bounds(day)
    in_day = [Attempt.timestamp >= start, Attempt.timestamp < end]

    total = db.query(func.count(Attempt.id)).filter(*in_day).scalar() or 0
    if total == 0:
        return None

    stat = DailyStat(
        date=day.isoformat(),
        total_attempts=total,
        unique_ips=db.query(func.count(distinct(Attempt.src_ip))).filter(*in_day).scalar() or 0,
        unique_countries=(
            db.query(func.count(distinct(Attempt.country_code)))
            .filter(*in_day, Attempt.country_code.isnot(None))
            .scalar() or 0
        ),
        top_country=_top_value(db, Attempt.country_name, start, end),
        top_username=_top_value(db, Attempt.username, start, end),
        top_password=_top_value(db, Attempt.password, start, end),
        top_command=_top_value(db, Attempt.command, start, end),
    )
    merged = db.merge(stat)
    db.commit()
    return merged


def aggregate_missing_days(db: DBSession, now: datetime | None = None) -> int:
    """Aggregate every completed UTC day that has attempts.

    Days already in DailyStat are skipped, except yesterday, which is always
    re-aggregated in case events arrived after the previous pass.
    """
    now = now or datetime.utcnow()
    today = now.date()
    yesterday = (today - timedelta(days=1)).isoformat()

    days_with_data = {
        row[0]
        for row in db.query(func.strftime("%Y-%m-%d", Attempt.timestamp))
        .filter(Attempt.timestamp < datetime.combine(today, datetime.min.time()))
        .distinct()
        .all()
    }
    already_done = {row[0] for row in db.query(DailyStat.date).all()}

    to_do = (days_with_data - already_done) | ({yesterday} & days_with_data)
    written = 0
    for day_str in sorted(to_do):
        if aggregate_day(db, date.fromisoformat(day_str)) is not None:
            written += 1
    return written


def prune(db: DBSession, now: datetime | None = None) -> dict[str, int]:
    """Delete raw rows older than the retention window. No-op when disabled."""
    if settings.retention_days <= 0:
        return {"attempts": 0, "sessions": 0, "page_views": 0}

    now = now or datetime.utcnow()
    cutoff = now - timedelta(days=settings.retention_days)

    attempts = (
        db.query(Attempt).filter(Attempt.timestamp < cutoff)
        .delete(synchronize_session=False)
    )
    sessions = (
        db.query(Session).filter(Session.start_time < cutoff)
        .delete(synchronize_session=False)
    )
    page_views = (
        db.query(PageView).filter(PageView.visited_at < cutoff)
        .delete(synchronize_session=False)
    )
    db.commit()
    return {"attempts": attempts, "sessions": sessions, "page_views": page_views}


def run_retention_pass(now: datetime | None = None) -> None:
    """One full pass: aggregate first (so pruned days survive as stats)."""
    db = SessionLocal()
    try:
        written = aggregate_missing_days(db, now)
        if written:
            logger.info(f"Retention: aggregated {written} day(s) into daily_stats")

        deleted = prune(db, now)
        if any(deleted.values()):
            logger.info(
                "Retention: pruned %s attempts, %s sessions, %s page views "
                "older than %s days",
                deleted["attempts"], deleted["sessions"], deleted["page_views"],
                settings.retention_days,
            )
    finally:
        db.close()


async def retention_worker():
    """Background loop: aggregate + prune every RUN_INTERVAL seconds."""
    logger.info(
        "Starting retention worker (retention_days=%s)",
        settings.retention_days or "disabled",
    )
    while True:
        try:
            await asyncio.to_thread(run_retention_pass)
        except Exception as e:
            logger.error(f"Retention pass failed: {e}", exc_info=True)
        await asyncio.sleep(RUN_INTERVAL)
