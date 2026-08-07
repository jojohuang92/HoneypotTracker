"""Background service to automatically look up unique IPs via AbuseIPDB."""

import asyncio
import logging
import time
from datetime import datetime

from sqlalchemy import select

from app.config import settings
from app.database import SessionLocal
from app.models import Attempt, IPScore
from app.services.abuseipdb import fetch_and_cache_score, CACHE_TTL, RateLimitedError

logger = logging.getLogger(__name__)

# How often to scan for new IPs (seconds)
SCAN_INTERVAL = 60
# Delay between API calls to respect rate limits
API_DELAY = 2
# Don't retry an IP whose lookup errored until this many seconds pass
FAILURE_BACKOFF = 3600
# Pause all lookups this long after a 429 (the quota is account-wide)
QUOTA_COOLOFF = 15 * 60

# ip → time.monotonic() of the last failed lookup
_failed_ips: dict[str, float] = {}


def _recently_failed(ip: str) -> bool:
    failed_at = _failed_ips.get(ip)
    return failed_at is not None and (time.monotonic() - failed_at) < FAILURE_BACKOFF


def _mark_failed(ip: str) -> None:
    _failed_ips[ip] = time.monotonic()
    if len(_failed_ips) > 10_000:
        now = time.monotonic()
        for stale in [k for k, v in _failed_ips.items() if (now - v) >= FAILURE_BACKOFF]:
            del _failed_ips[stale]


def _lookup_ip(ip: str) -> dict | None:
    """Run the blocking AbuseIPDB lookup in a worker thread."""
    db = SessionLocal()
    try:
        result = fetch_and_cache_score(db, ip)
        if not result:
            return None
        return {
            "abuse_score": result.abuse_score,
            "isp": result.isp,
        }
    finally:
        db.close()


async def auto_lookup_ips():
    """Continuously scan for unique IPs missing AbuseIPDB scores and look them up."""
    if not settings.abuseipdb_api_key:
        logger.info("No AbuseIPDB API key configured — auto IP lookup disabled")
        return

    logger.info("Starting automatic IP lookup service")

    while True:
        try:
            db = SessionLocal()
            try:
                # Find unique IPs with no fresh cached score.
                fresh_cutoff = datetime.utcnow() - CACHE_TTL
                fresh_scores = select(IPScore.ip).where(IPScore.fetched_at >= fresh_cutoff)
                missing_or_stale = (
                    db.query(Attempt.src_ip)
                    .filter(~Attempt.src_ip.in_(fresh_scores))
                    .distinct()
                    .all()
                )
                new_ips = [row[0] for row in missing_or_stale]
            finally:
                db.close()

            if new_ips:
                logger.info(f"Found {len(new_ips)} IPs without AbuseIPDB scores")

            for ip in new_ips:
                if _recently_failed(ip):
                    continue
                try:
                    result = await asyncio.to_thread(_lookup_ip, ip)
                except RateLimitedError:
                    logger.warning(
                        "AbuseIPDB quota exhausted — pausing lookups for "
                        f"{QUOTA_COOLOFF // 60} minutes"
                    )
                    await asyncio.sleep(QUOTA_COOLOFF)
                    break
                if result:
                    logger.info(
                        f"Looked up {ip}: abuse_score={result['abuse_score']}, "
                        f"isp={result['isp']}"
                    )
                else:
                    _mark_failed(ip)
                await asyncio.sleep(API_DELAY)

        except Exception as e:
            logger.error(f"Auto IP lookup error: {e}", exc_info=True)

        await asyncio.sleep(SCAN_INTERVAL)
