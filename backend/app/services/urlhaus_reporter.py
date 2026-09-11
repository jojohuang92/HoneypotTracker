"""Submit captured payload URLs to URLhaus (abuse.ch).

Cowrie records the URL every attacker ``wget``/``curl`` fetched and the bytes
it served. That pair is exactly what URLhaus collects — live malware
distribution sites — and its submission policy is strict about *live*: only
URLs currently serving a payload may be sent. A capture with a hash proves
the URL served one at capture time, so a URL is submitted only while its
newest capture is younger than ``settings.urlhaus_max_age_hours``; the
backlog of stale URLs is never dumped.

Follows the other reporters: report-once per URL through ``ReportLog``
(``report_type`` "urlhaus"), a bounded retry budget for failures, and the
HTTP call in a worker thread so ingestion never waits on abuse.ch.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import re
from datetime import datetime, timedelta
from urllib.parse import urlsplit

import httpx
from sqlalchemy import func

from app.config import settings
from app.database import SessionLocal
from app.models import CapturedFile, ReportLog

logger = logging.getLogger(__name__)

URLHAUS_SUBMIT_URL = "https://urlhaus.abuse.ch/api/"
REPORT_TYPE = "urlhaus"

SCAN_INTERVAL = 300      # seconds between passes
API_DELAY = 5            # seconds between submissions
BATCH_LIMIT = 25         # URLs per pass
MAX_ATTEMPTS = 3         # failed submissions per URL before giving up ...
RETRY_WINDOW = timedelta(days=7)  # ... within this window
AUTH_FAILURE_PAUSE = 6 * 3600     # a bad key will not fix itself in a minute

# URLhaus tag alphabet. Anything else is dropped rather than mangled.
_TAG_RE = re.compile(r"[^A-Za-z0-9.\- ]")
_MAX_URL_LEN = 2048


class AuthRejected(Exception):
    """URLhaus refused the Auth-Key; retrying only makes noise."""


def eligible_url(url: str | None) -> bool:
    """Only public http(s) URLs may be submitted.

    A honeypot sees attackers fetch from private ranges (their own LAN, a
    misconfigured dropper) and from the honeypot itself; none of those belong
    in a public feed, and URLhaus would reject them anyway.
    """
    if not url or len(url) > _MAX_URL_LEN:
        return False
    try:
        parts = urlsplit(url)
    except ValueError:
        return False
    if parts.scheme not in ("http", "https") or not parts.hostname:
        return False
    host = parts.hostname
    if host in ("localhost",) or host.endswith(".local") or host.endswith(".internal"):
        return False
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return "." in host  # a bare label is not a public hostname
    return addr.is_global


def build_tags(arch: str | None, malware_family: str | None) -> list[str]:
    """Tags for the entry: provenance always, plus what analysis found."""
    tags = ["honeypot", "cowrie"]
    if arch:
        tags.append("elf")
        tags.append(arch)
    if malware_family:
        tags.append(malware_family)
    cleaned: list[str] = []
    for tag in tags:
        tag = _TAG_RE.sub("", tag).strip()
        if tag and tag.lower() not in {c.lower() for c in cleaned}:
            cleaned.append(tag[:50])
    return cleaned


def build_submission(url: str, tags: list[str]) -> dict:
    return {
        "anonymous": "1" if settings.urlhaus_anonymous else "0",
        "submission": [{"url": url, "threat": "malware_download", "tags": tags}],
    }


def _already_submitted(db, url: str) -> bool:
    return (
        db.query(ReportLog)
        .filter(
            ReportLog.report_type == REPORT_TYPE,
            ReportLog.identifier == url,
            ReportLog.success.is_(True),
        )
        .first()
        is not None
    )


def _spent_attempts(db, url: str) -> bool:
    failures = (
        db.query(func.count(ReportLog.id))
        .filter(
            ReportLog.report_type == REPORT_TYPE,
            ReportLog.identifier == url,
            ReportLog.success.is_(False),
            ReportLog.reported_at >= datetime.utcnow() - RETRY_WINDOW,
        )
        .scalar()
    ) or 0
    return failures >= MAX_ATTEMPTS


def find_candidates(db, now: datetime | None = None,
                    limit: int = BATCH_LIMIT) -> list[tuple[str, list[str]]]:
    """Distinct URLs captured recently enough to still count as live."""
    now = now or datetime.utcnow()
    cutoff = now - timedelta(hours=settings.urlhaus_max_age_hours)
    rows = (
        db.query(
            CapturedFile.url,
            func.max(CapturedFile.arch),
            func.max(CapturedFile.malware_family),
        )
        .filter(
            CapturedFile.timestamp >= cutoff,
            CapturedFile.url.isnot(None),
            CapturedFile.url != "",
            CapturedFile.sha256.isnot(None),
            CapturedFile.sha256 != "",
        )
        .group_by(CapturedFile.url)
        .order_by(func.max(CapturedFile.timestamp).desc())
        .all()
    )
    out: list[tuple[str, list[str]]] = []
    for url, arch, family in rows:
        if not eligible_url(url):
            continue
        if _already_submitted(db, url) or _spent_attempts(db, url):
            continue
        out.append((url, build_tags(arch, family)))
        if len(out) >= limit:
            break
    return out


def submit_url(url: str, tags: list[str]) -> tuple[bool, str]:
    """POST one URL. Returns (success, detail) for the audit log."""
    try:
        resp = httpx.post(
            URLHAUS_SUBMIT_URL,
            json=build_submission(url, tags),
            headers={
                "Auth-Key": settings.urlhaus_auth_key,
                "Content-Type": "application/json",
            },
            timeout=20,
        )
    except httpx.HTTPError as exc:
        return False, f"request failed: {exc}"

    if resp.status_code in (401, 403):
        raise AuthRejected(f"HTTP {resp.status_code}: {resp.text[:200]}")
    if resp.status_code == 429:
        return False, "Rate limit hit"
    if resp.status_code != 200:
        return False, f"HTTP {resp.status_code}: {resp.text[:200]}"

    body = resp.text.strip()
    try:
        data = json.loads(body)
    except ValueError:
        data = None
    if isinstance(data, dict):
        status = str(data.get("query_status", "ok")).lower()
        if status in ("ok", "success"):
            return True, body[:500]
        if "auth" in status or "key" in status:
            raise AuthRejected(body[:200])
        return False, body[:500]
    # Not JSON: treat an explicit error phrase as failure, else accepted.
    lowered = body.lower()
    if "error" in lowered or "invalid" in lowered or "denied" in lowered:
        if "auth" in lowered or "key" in lowered:
            raise AuthRejected(body[:200])
        return False, body[:500]
    return True, body[:500]


async def auto_report_urls():
    """Background loop: submit fresh captured payload URLs to URLhaus."""
    if not settings.urlhaus_auth_key:
        logger.info("No URLhaus Auth-Key — URL submission disabled")
        return

    logger.info("Starting automatic URLhaus URL reporter")

    while True:
        try:
            db = SessionLocal()
            try:
                candidates = await asyncio.to_thread(find_candidates, db)
            finally:
                db.close()

            for url, tags in candidates:
                db = SessionLocal()
                try:
                    if _already_submitted(db, url) or _spent_attempts(db, url):
                        continue
                    try:
                        success, detail = await asyncio.to_thread(submit_url, url, tags)
                    except AuthRejected as exc:
                        logger.error("URLhaus rejected the Auth-Key (%s) — pausing %dh",
                                     exc, AUTH_FAILURE_PAUSE // 3600)
                        db.add(ReportLog(report_type=REPORT_TYPE, identifier=url,
                                         success=False, detail=f"auth rejected: {exc}"[:500]))
                        db.commit()
                        await asyncio.sleep(AUTH_FAILURE_PAUSE)
                        break

                    db.add(ReportLog(report_type=REPORT_TYPE, identifier=url,
                                     success=success, detail=detail[:500]))
                    db.commit()
                    if success:
                        logger.info("Submitted %s to URLhaus (tags=%s)", url, tags)
                    else:
                        logger.warning("URLhaus submission failed for %s: %s", url, detail)
                        if "Rate limit" in detail:
                            await asyncio.sleep(60)
                finally:
                    db.close()
                await asyncio.sleep(API_DELAY)

        except Exception as exc:
            logger.error("URLhaus reporter error: %s", exc, exc_info=True)

        await asyncio.sleep(SCAN_INTERVAL)
