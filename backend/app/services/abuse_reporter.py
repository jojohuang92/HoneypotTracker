"""Background service to auto-report attacking IPs to AbuseIPDB."""

import asyncio
import logging
from datetime import datetime, timedelta

import httpx
from sqlalchemy import func

from app.config import settings
from app.database import SessionLocal
from app.models import Attempt, Session, ReportLog

logger = logging.getLogger(__name__)

ABUSEIPDB_REPORT_URL = "https://api.abuseipdb.com/api/v2/report"

# Minimum time between reports for the same IP
DEDUP_WINDOW = timedelta(minutes=15)

# Delay between API calls (seconds)
API_DELAY = 2

# How often to scan for reportable sessions (seconds)
SCAN_INTERVAL = 120

# Map classifier intents to AbuseIPDB category IDs
# https://www.abuseipdb.com/categories
INTENT_CATEGORIES: dict[str, list[int]] = {
    "brute_force":       [18, 22],  # Brute-Force, SSH
    "malware_deployment": [22, 23], # SSH, Exploited Host
    "cryptomining":      [22, 23],
    "credential_theft":  [18, 22],
    "reconnaissance":    [22],
    "persistence":       [22, 23],
    "sabotage":          [22, 23],
    "unknown":           [22],
}


def _was_recently_reported(db, ip: str) -> bool:
    """Check if this IP was reported within the dedup window."""
    cutoff = datetime.utcnow() - DEDUP_WINDOW
    return (
        db.query(ReportLog)
        .filter(
            ReportLog.report_type == "abuseipdb",
            ReportLog.identifier == ip,
            ReportLog.reported_at > cutoff,
            ReportLog.success == True,
        )
        .first()
        is not None
    )


def _build_report_comment(db, ip: str, session_id: str) -> tuple[str, set[int]]:
    """Build a human-readable comment and collect categories from attack activity."""
    attempts = (
        db.query(Attempt)
        .filter(Attempt.src_ip == ip, Attempt.session_id == session_id)
        .all()
    )

    categories: set[int] = set()
    login_count = 0
    commands: list[str] = []
    files: list[str] = []
    intents: set[str] = set()

    for a in attempts:
        intent = a.intent or "unknown"
        intents.add(intent)
        for cat in INTENT_CATEGORIES.get(intent, [22]):
            categories.add(cat)

        if a.username is not None:
            login_count += 1
        if a.command:
            if a.command.startswith("download:") or a.command.startswith("upload:"):
                files.append(a.command)
            else:
                commands.append(a.command)

    if not categories:
        categories.add(22)  # SSH as fallback

    parts = [f"Cowrie SSH honeypot: session {session_id}"]
    if login_count:
        parts.append(f"{login_count} login attempt(s)")
    if commands:
        shown = commands[:5]
        parts.append(f"{len(commands)} command(s): {'; '.join(shown)}")
    if files:
        parts.append(f"{len(files)} file transfer(s)")
    if intents - {"unknown"}:
        parts.append(f"classified as: {', '.join(sorted(intents - {'unknown'}))}")

    comment = " | ".join(parts)
    # AbuseIPDB comment limit is 1024 chars
    if len(comment) > 1024:
        comment = comment[:1021] + "..."

    return comment, categories


def _report_ip(ip: str, categories: set[int], comment: str) -> bool:
    """Send a report to AbuseIPDB. Returns True on success."""
    try:
        resp = httpx.post(
            ABUSEIPDB_REPORT_URL,
            headers={
                "Key": settings.abuseipdb_api_key,
                "Accept": "application/json",
            },
            data={
                "ip": ip,
                "categories": ",".join(str(c) for c in sorted(categories)),
                "comment": comment,
            },
            timeout=15,
        )
        if resp.status_code == 200:
            return True
        elif resp.status_code == 429:
            logger.warning("AbuseIPDB rate limit hit — backing off")
            return False
        else:
            logger.warning(f"AbuseIPDB report for {ip} returned {resp.status_code}: {resp.text[:200]}")
            return False
    except Exception as e:
        logger.warning(f"AbuseIPDB report failed for {ip}: {e}")
        return False


async def auto_report_ips():
    """Background loop: find closed sessions with unreported IPs, report to AbuseIPDB."""
    if not settings.abuseipdb_api_key:
        logger.info("No AbuseIPDB API key — auto IP reporting disabled")
        return

    logger.info("Starting automatic AbuseIPDB reporter")

    while True:
        try:
            db = SessionLocal()
            try:
                # Find closed sessions whose IPs haven't been reported recently
                closed_sessions = (
                    db.query(Session)
                    .filter(Session.end_time.isnot(None))
                    .order_by(Session.end_time.desc())
                    .limit(50)
                    .all()
                )

                to_report: list[tuple[str, str]] = []  # (ip, session_id)
                seen_ips: set[str] = set()

                for sess in closed_sessions:
                    ip = sess.src_ip
                    if ip in seen_ips:
                        continue
                    seen_ips.add(ip)
                    if not _was_recently_reported(db, ip):
                        to_report.append((ip, sess.session_id))
            finally:
                db.close()

            for ip, session_id in to_report:
                db = SessionLocal()
                try:
                    # Re-check dedup inside the loop (another iteration may have reported it)
                    if _was_recently_reported(db, ip):
                        continue

                    comment, categories = _build_report_comment(db, ip, session_id)
                    success = _report_ip(ip, categories, comment)

                    log_entry = ReportLog(
                        report_type="abuseipdb",
                        identifier=ip,
                        success=success,
                        detail=comment[:500],
                    )
                    db.add(log_entry)
                    db.commit()

                    if success:
                        logger.info(f"Reported {ip} to AbuseIPDB (categories: {sorted(categories)})")
                    else:
                        # Back off on failure
                        await asyncio.sleep(30)
                finally:
                    db.close()

                await asyncio.sleep(API_DELAY)

        except Exception as e:
            logger.error(f"AbuseIPDB reporter error: {e}", exc_info=True)

        await asyncio.sleep(SCAN_INTERVAL)
