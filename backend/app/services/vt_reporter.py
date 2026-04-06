"""Background service to auto-submit captured malware files to VirusTotal."""

import asyncio
import logging
from pathlib import Path

import httpx

from app.config import settings
from app.database import SessionLocal
from app.models import CapturedFile, ReportLog

logger = logging.getLogger(__name__)

VT_UPLOAD_URL = "https://www.virustotal.com/api/v3/files"

# Delay between uploads (VT free tier: 4 req/min, be conservative)
API_DELAY = 20

# How often to scan for unsubmitted files (seconds)
SCAN_INTERVAL = 120

# Max file size to upload (32 MB — VT limit for standard endpoint)
MAX_FILE_SIZE = 32 * 1024 * 1024


def _was_already_submitted(db, sha256: str) -> bool:
    """Check if this hash was already submitted to VT."""
    return (
        db.query(ReportLog)
        .filter(
            ReportLog.report_type == "virustotal",
            ReportLog.identifier == sha256,
            ReportLog.success == True,
        )
        .first()
        is not None
    )


def _upload_file(file_path: str, filename: str) -> tuple[bool, str]:
    """Upload a file to VirusTotal. Returns (success, detail)."""
    try:
        path = Path(file_path)
        if not path.exists():
            return False, f"File not found: {file_path}"

        if path.stat().st_size > MAX_FILE_SIZE:
            return False, f"File too large ({path.stat().st_size} bytes)"

        with open(path, "rb") as f:
            resp = httpx.post(
                VT_UPLOAD_URL,
                headers={"x-apikey": settings.virustotal_api_key},
                files={"file": (filename or path.name, f)},
                timeout=60,
            )

        if resp.status_code == 200:
            analysis_id = resp.json().get("data", {}).get("id", "")
            return True, f"Submitted, analysis_id={analysis_id}"
        elif resp.status_code == 429:
            return False, "Rate limit hit"
        else:
            return False, f"HTTP {resp.status_code}: {resp.text[:200]}"
    except Exception as e:
        return False, str(e)


async def auto_report_files():
    """Background loop: find captured files not yet submitted to VT, upload them."""
    if not settings.virustotal_api_key:
        logger.info("No VirusTotal API key — auto file reporting disabled")
        return

    logger.info("Starting automatic VirusTotal file reporter")

    while True:
        try:
            db = SessionLocal()
            try:
                # Find captured files with a local path that haven't been submitted
                candidates = (
                    db.query(CapturedFile)
                    .filter(
                        CapturedFile.sha256.isnot(None),
                        CapturedFile.local_path.isnot(None),
                        CapturedFile.local_path != "",
                    )
                    .order_by(CapturedFile.created_at.desc())
                    .limit(20)
                    .all()
                )

                to_submit: list[tuple[int, str, str, str]] = []  # (id, sha256, path, filename)
                seen_hashes: set[str] = set()

                for cf in candidates:
                    if cf.sha256 in seen_hashes:
                        continue
                    seen_hashes.add(cf.sha256)
                    if not _was_already_submitted(db, cf.sha256):
                        to_submit.append((cf.id, cf.sha256, cf.local_path, cf.filename or ""))
            finally:
                db.close()

            for file_id, sha256, local_path, filename in to_submit:
                db = SessionLocal()
                try:
                    # Re-check dedup
                    if _was_already_submitted(db, sha256):
                        continue

                    success, detail = _upload_file(local_path, filename)

                    log_entry = ReportLog(
                        report_type="virustotal",
                        identifier=sha256,
                        success=success,
                        detail=detail[:500],
                    )
                    db.add(log_entry)
                    db.commit()

                    if success:
                        logger.info(f"Submitted {sha256[:16]}... to VirusTotal")
                    else:
                        logger.warning(f"VT upload failed for {sha256[:16]}...: {detail}")
                        if "Rate limit" in detail:
                            await asyncio.sleep(60)
                finally:
                    db.close()

                await asyncio.sleep(API_DELAY)

        except Exception as e:
            logger.error(f"VT reporter error: {e}", exc_info=True)

        await asyncio.sleep(SCAN_INTERVAL)
