import logging
from datetime import datetime, timedelta

import httpx
from sqlalchemy.orm import Session as DBSession

from app.config import settings
from app.models import IPScore

logger = logging.getLogger(__name__)

ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
CACHE_TTL = timedelta(days=7)


def get_cached_score(db: DBSession, ip: str) -> IPScore | None:
    """Return cached score if it exists and isn't stale."""
    row = db.query(IPScore).filter(IPScore.ip == ip).first()
    if row and row.fetched_at and (datetime.utcnow() - row.fetched_at) < CACHE_TTL:
        return row
    return None


def fetch_and_cache_score(db: DBSession, ip: str) -> IPScore | None:
    """Fetch score from AbuseIPDB API and cache it."""
    if not settings.abuseipdb_api_key:
        return None

    try:
        resp = httpx.get(
            ABUSEIPDB_URL,
            params={"ipAddress": ip, "maxAgeInDays": 90},
            headers={
                "Key": settings.abuseipdb_api_key,
                "Accept": "application/json",
            },
            timeout=10,
        )
        resp.raise_for_status()
        data = resp.json().get("data", {})

        score = IPScore(
            ip=ip,
            abuse_score=data.get("abuseConfidenceScore", 0),
            isp=data.get("isp", ""),
            usage_type=data.get("usageType", ""),
            total_reports=data.get("totalReports", 0),
            fetched_at=datetime.utcnow(),
        )
        db.merge(score)
        db.commit()
        return score
    except Exception as e:
        logger.warning(f"AbuseIPDB lookup failed for {ip}: {e}")
        return None
