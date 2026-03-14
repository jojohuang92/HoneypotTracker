"""Background service to automatically look up unique IPs via AbuseIPDB."""

import asyncio
import logging

from sqlalchemy import func

from app.config import settings
from app.database import SessionLocal
from app.models import Attempt, IPScore
from app.services.abuseipdb import fetch_and_cache_score, CACHE_TTL

logger = logging.getLogger(__name__)

# How often to scan for new IPs (seconds)
SCAN_INTERVAL = 60
# Delay between API calls to respect rate limits
API_DELAY = 2


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
                # Find unique IPs that have no cached score at all
                scored_ips = db.query(IPScore.ip).subquery()
                unscored = (
                    db.query(Attempt.src_ip)
                    .filter(~Attempt.src_ip.in_(db.query(scored_ips)))
                    .distinct()
                    .all()
                )
                new_ips = [row[0] for row in unscored]
            finally:
                db.close()

            if new_ips:
                logger.info(f"Found {len(new_ips)} IPs without AbuseIPDB scores")

            for ip in new_ips:
                db = SessionLocal()
                try:
                    result = fetch_and_cache_score(db, ip)
                    if result:
                        logger.info(
                            f"Looked up {ip}: abuse_score={result.abuse_score}, "
                            f"isp={result.isp}"
                        )
                finally:
                    db.close()
                await asyncio.sleep(API_DELAY)

        except Exception as e:
            logger.error(f"Auto IP lookup error: {e}", exc_info=True)

        await asyncio.sleep(SCAN_INTERVAL)
