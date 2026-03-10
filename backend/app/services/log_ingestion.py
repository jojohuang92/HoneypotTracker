"""Cowrie JSON log ingestion service.

Tails the Cowrie log file, parses each JSON line by event type,
enriches with GeoIP data, classifies intent, persists to the DB,
and publishes SSE events for real-time dashboard updates.
"""

import asyncio
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

logger = logging.getLogger(__name__)

# Singleton GeoIP instance
_geoip: GeoIPLookup | None = None


def get_geoip() -> GeoIPLookup:
    global _geoip
    if _geoip is None:
        _geoip = GeoIPLookup(settings.geoip_db_path)
    return _geoip


def _parse_timestamp(ts_str: str) -> datetime:
    """Parse Cowrie's ISO-ish timestamp format."""
    # Cowrie uses: 2024-01-15T08:23:45.123456Z or 2024-01-15T08:23:45.123456+0000
    ts_str = ts_str.replace("Z", "+00:00").replace("+0000", "+00:00")
    try:
        return datetime.fromisoformat(ts_str)
    except ValueError:
        return datetime.utcnow()


def _process_event(event: dict, db: DBSession) -> dict | None:
    """Process a single Cowrie JSON event. Returns SSE payload or None."""
    event_id = event.get("eventid", "")
    session_id = event.get("session", "")
    src_ip = event.get("src_ip", "")
    timestamp = _parse_timestamp(event.get("timestamp", ""))

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
        }

    # --- Login attempt ---
    elif event_id in ("cowrie.login.failed", "cowrie.login.success"):
        success = event_id == "cowrie.login.success"
        intent, mitre_id = classify_login(success)

        attempt = Attempt(
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
            username=event.get("username", ""),
            password=event.get("password", ""),
            success=success,
            intent=intent,
            mitre_id=mitre_id,
        )
        db.add(attempt)

        # Update session login count
        sess = db.query(Session).filter_by(session_id=session_id).first()
        if sess:
            sess.login_attempts = (sess.login_attempts or 0) + 1

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
        }

    # --- Command input ---
    elif event_id == "cowrie.command.input":
        command = event.get("input", "")
        intent, mitre_id = classify_command(command)

        attempt = Attempt(
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
            command=command,
            intent=intent,
            mitre_id=mitre_id,
        )
        db.add(attempt)

        # Update session command count
        sess = db.query(Session).filter_by(session_id=session_id).first()
        if sess:
            sess.commands_run = (sess.commands_run or 0) + 1

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
        }

    # --- File download/upload ---
    elif event_id in ("cowrie.session.file_download", "cowrie.session.file_upload"):
        url = event.get("url", event.get("destfile", ""))
        sha256 = event.get("shasum", "")
        filename = event.get("outfile", event.get("filename", ""))

        # Create an attempt record for the download event
        attempt = Attempt(
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
            command=f"download: {url}" if url else f"upload: {filename}",
            intent="malware_deployment",
            mitre_id="T1105",
        )
        db.add(attempt)
        db.flush()

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

        # Update session file count
        sess = db.query(Session).filter_by(session_id=session_id).first()
        if sess:
            sess.files_downloaded = (sess.files_downloaded or 0) + 1

        db.commit()
        return {
            "type": "file_download",
            "session_id": session_id,
            "src_ip": src_ip,
            "url": url,
            "sha256": sha256,
            "country": geo.country_name,
        }

    # --- Session closed ---
    elif event_id == "cowrie.session.closed":
        sess = db.query(Session).filter_by(session_id=session_id).first()
        if sess:
            sess.end_time = timestamp
            if sess.start_time:
                delta = timestamp - sess.start_time
                sess.duration_secs = delta.total_seconds()
            db.commit()
        return None

    return None


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

                        sse_payload = _process_event(event, db)
                        if sse_payload:
                            publish_event("new_attack", sse_payload)
                finally:
                    db.close()

        except FileNotFoundError:
            logger.warning("Log file disappeared — waiting for it to reappear")
            await asyncio.sleep(5)
            continue
        except Exception as e:
            logger.error(f"Ingestion error: {e}", exc_info=True)

        await asyncio.sleep(1)  # Poll interval
