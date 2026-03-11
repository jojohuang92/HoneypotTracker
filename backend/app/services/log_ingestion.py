"""Cowrie JSON log ingestion service.

Tails the Cowrie log file, parses each JSON line by event type,
enriches with GeoIP data, classifies intent, persists to the DB,
and publishes SSE events for real-time dashboard updates.
"""

import asyncio
import ipaddress
import json
import logging
import os
from datetime import datetime
from pathlib import Path

from sqlalchemy.orm import Session as DBSession

from app.config import settings
from app.database import SessionLocal
from app.models import Attempt, CapturedFile, Session
from app.routers.stream import publish_event
from app.services.classifier import classify_command, classify_login
from app.services.geoip import GeoIPLookup
from app.services.virustotal import enrich_captured_file

logger = logging.getLogger(__name__)

# Singleton GeoIP instance
_geoip: GeoIPLookup | None = None


def get_geoip() -> GeoIPLookup:
    global _geoip
    if _geoip is None:
        _geoip = GeoIPLookup(settings.geoip_db_path)
    return _geoip


def _is_private_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def _parse_timestamp(ts_str: str) -> datetime:
    """Parse Cowrie's ISO-ish timestamp format. Returns naive UTC datetime."""
    # Cowrie uses: 2024-01-15T08:23:45.123456Z or 2024-01-15T08:23:45.123456+0000
    ts_str = ts_str.replace("Z", "+00:00").replace("+0000", "+00:00")
    try:
        dt = datetime.fromisoformat(ts_str)
        # Strip timezone info — SQLite stores naive datetimes, mixing causes errors
        return dt.replace(tzinfo=None)
    except ValueError:
        return datetime.utcnow()


def _build_attempt(
    event: dict,
    event_id: str,
    session_id: str,
    src_ip: str,
    timestamp: datetime,
    geo,
    **kwargs,
) -> Attempt:
    """Construct an Attempt with all common fields pre-populated."""
    return Attempt(
        session_id=session_id,
        event_id=event_id,
        timestamp=timestamp,
        src_ip=src_ip,
        src_port=event.get("src_port"),
        dst_port=event.get("dst_port", 22),
        protocol=event.get("protocol", "ssh"),
        country_code=geo.country_code,
        country_name=geo.country_name,
        city=geo.city,
        latitude=geo.latitude,
        longitude=geo.longitude,
        asn=geo.asn,
        as_org=geo.as_org,
        **kwargs,
    )


def _increment_session_field(db: DBSession, session_id: str, field: str) -> None:
    """Atomically increment a counter field on the Session row."""
    sess = db.query(Session).filter_by(session_id=session_id).first()
    if sess:
        setattr(sess, field, (getattr(sess, field) or 0) + 1)


def _process_event(event: dict, db: DBSession) -> tuple[dict | None, int | None]:
    """Process a single Cowrie JSON event.

    Returns (sse_payload, captured_file_id). Either value may be None.
    """
    event_id = event.get("eventid", "")
    session_id = event.get("session", "")
    src_ip = event.get("src_ip", "")
    timestamp = _parse_timestamp(event.get("timestamp", ""))

    if _is_private_ip(src_ip):
        logger.debug(f"Skipping private IP: {src_ip}")
        return None, None

    geoip = get_geoip()
    geo = geoip.lookup(src_ip)

    # --- Session connect ---
    if event_id == "cowrie.session.connect":
        protocol = event.get("protocol", "ssh")
        session_obj = Session(
            session_id=session_id,
            src_ip=src_ip,
            start_time=timestamp,
            protocol=protocol,
            country_code=geo.country_code,
            country_name=geo.country_name,
            latitude=geo.latitude,
            longitude=geo.longitude,
        )
        db.merge(session_obj)
        db.commit()
        return {
            "type": "session_start",
            "session_id": session_id,
            "src_ip": src_ip,
            "country": geo.country_name,
            "protocol": protocol,
        }, None

    # --- Login attempt ---
    elif event_id in ("cowrie.login.failed", "cowrie.login.success"):
        success = event_id == "cowrie.login.success"
        intent, mitre_id = classify_login(success)

        db.add(_build_attempt(
            event, event_id, session_id, src_ip, timestamp, geo,
            username=event.get("username", ""),
            password=event.get("password", ""),
            success=success,
            intent=intent,
            mitre_id=mitre_id,
        ))
        _increment_session_field(db, session_id, "login_attempts")
        db.commit()
        return {
            "type": "login_attempt",
            "session_id": session_id,
            "src_ip": src_ip,
            "username": event.get("username", ""),
            "password": event.get("password", ""),
            "success": success,
            "country": geo.country_name,
            "latitude": geo.latitude,
            "longitude": geo.longitude,
        }, None

    # --- Command input ---
    elif event_id == "cowrie.command.input":
        command = event.get("input", "")
        intent, mitre_id = classify_command(command)

        db.add(_build_attempt(
            event, event_id, session_id, src_ip, timestamp, geo,
            command=command,
            intent=intent,
            mitre_id=mitre_id,
        ))
        _increment_session_field(db, session_id, "commands_run")
        db.commit()
        return {
            "type": "command",
            "session_id": session_id,
            "src_ip": src_ip,
            "command": command,
            "intent": intent,
            "mitre_id": mitre_id,
            "country": geo.country_name,
            "latitude": geo.latitude,
            "longitude": geo.longitude,
        }, None

    # --- File download/upload ---
    elif event_id in ("cowrie.session.file_download", "cowrie.session.file_upload"):
        url = event.get("url", event.get("destfile", ""))
        sha256 = event.get("shasum", "")
        filename = event.get("outfile", event.get("filename", ""))

        attempt = _build_attempt(
            event, event_id, session_id, src_ip, timestamp, geo,
            command=f"download: {url}" if url else f"upload: {filename}",
            intent="malware_deployment",
            mitre_id="T1105",
        )
        db.add(attempt)
        db.flush()

        captured_id = None
        if sha256:
            captured = CapturedFile(
                attempt_id=attempt.id,
                session_id=session_id,
                timestamp=timestamp,
                filename=os.path.basename(filename) if filename else "",
                url=url,
                sha256=sha256,
                local_path=event.get("outfile", ""),
            )
            db.add(captured)
            db.flush()
            captured_id = captured.id

        _increment_session_field(db, session_id, "files_downloaded")
        db.commit()
        return {
            "type": "file_download",
            "session_id": session_id,
            "src_ip": src_ip,
            "url": url,
            "sha256": sha256,
            "country": geo.country_name,
        }, captured_id

    # --- Session closed ---
    elif event_id == "cowrie.session.closed":
        sess = db.query(Session).filter_by(session_id=session_id).first()
        if sess:
            sess.end_time = timestamp
            if sess.start_time:
                delta = timestamp - sess.start_time
                sess.duration_secs = delta.total_seconds()
            db.commit()
        return None, None

    return None, None


async def tail_cowrie_log(log_path: str):
    """Continuously tail the Cowrie JSON log file and process new lines.

    Uses a simple seek-based approach: reads to EOF, then polls for new data.
    This is more reliable than inotify across different OS/filesystem combos.
    """
    path = Path(log_path)
    logger.info(f"Starting Cowrie log ingestion from: {path}")

    # Wait for log file to appear
    while not path.exists():
        logger.info(f"Waiting for Cowrie log file: {path}")
        await asyncio.sleep(5)

    # Start at end of file (only process new events)
    file_size = path.stat().st_size
    position = file_size
    logger.info(f"Cowrie log found ({file_size} bytes). Tailing from end...")

    while True:
        try:
            current_size = path.stat().st_size

            # File was truncated/rotated — reset to beginning
            if current_size < position:
                logger.info("Log file rotated — resetting to beginning")
                position = 0

            if current_size > position:
                with open(path, "r") as f:
                    f.seek(position)
                    lines = f.readlines()
                    position = f.tell()

                db = SessionLocal()
                try:
                    for line in lines:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            event = json.loads(line)
                        except json.JSONDecodeError:
                            logger.debug(f"Skipping malformed JSON line")
                            continue

                        sse_payload, captured_id = _process_event(event, db)
                        if sse_payload:
                            publish_event("new_attack", sse_payload)
                        if captured_id:
                            asyncio.create_task(enrich_captured_file(captured_id))
                finally:
                    db.close()

        except FileNotFoundError:
            logger.warning("Log file disappeared — waiting for it to reappear")
            await asyncio.sleep(5)
            continue
        except Exception as e:
            logger.error(f"Ingestion error: {e}", exc_info=True)

        await asyncio.sleep(1)  # Poll interval
