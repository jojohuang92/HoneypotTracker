"""VirusTotal file report lookup."""

import logging

import httpx

from app.config import settings
from app.database import SessionLocal
from app.models import CapturedFile

logger = logging.getLogger(__name__)

VT_BASE = "https://www.virustotal.com/api/v3"


async def enrich_captured_file(file_id: int) -> None:
    """Query VirusTotal for a captured file and persist the results."""
    if not settings.virustotal_api_key:
        return

    db = SessionLocal()
    try:
        captured = db.query(CapturedFile).filter_by(id=file_id).first()
        if not captured or not captured.sha256:
            return

        headers = {"x-apikey": settings.virustotal_api_key}
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(
                f"{VT_BASE}/files/{captured.sha256}", headers=headers
            )

        if resp.status_code == 404:
            logger.info(f"VT: {captured.sha256[:16]}... not in database yet")
            return
        if resp.status_code != 200:
            logger.warning(f"VT API returned {resp.status_code} for {captured.sha256[:16]}...")
            return

        attrs = resp.json().get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        total = sum(stats.values())

        captured.vt_positives = stats.get("malicious", 0)
        captured.vt_total = total
        captured.vt_link = f"https://www.virustotal.com/gui/file/{captured.sha256}"

        if not captured.file_size:
            captured.file_size = attrs.get("size")
        if not captured.file_type:
            captured.file_type = attrs.get("type_description") or attrs.get("magic") or ""

        db.commit()
        logger.info(
            f"VT: {captured.sha256[:16]}... → {captured.vt_positives}/{total} detections"
        )
    except Exception as e:
        logger.error(f"VT enrichment failed for file {file_id}: {e}")
    finally:
        db.close()
