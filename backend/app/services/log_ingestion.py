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
import re
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import or_
from sqlalchemy.orm import Session as DBSession

from app.config import settings
from app.database import SessionLocal
from app.models import Attempt, CapturedFile, Sensor, Session
from app.routers.stream import publish_event
from app.services import alerts, splunk_forwarder
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


_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")


def _normalized_sha256(value) -> str:
    """Return a lowercase hex sha256, or "" if the value isn't one.

    Validated at the ingestion boundary rather than at each use: the hash
    reaches a VirusTotal URL path and a filesystem lookup downstream, and for
    events arriving over /api/ingest it is whatever the sensor sent.
    """
    if not isinstance(value, str) or not _SHA256_RE.match(value):
        return ""
    return value.lower()


def _parse_timestamp(ts_str: str) -> datetime:
    """Parse Cowrie's ISO-ish timestamp format. Returns naive UTC datetime."""
    # Cowrie uses: 2024-01-15T08:23:45.123456Z or 2024-01-15T08:23:45.123456+0000
    ts_str = ts_str.replace("Z", "+00:00").replace("+0000", "+00:00")
    try:
        dt = datetime.fromisoformat(ts_str)
        # Store UTC as naive datetimes because the existing SQLite schema is naive.
        if dt.tzinfo is not None:
            return dt.astimezone(timezone.utc).replace(tzinfo=None)
        return dt
    except ValueError:
        return datetime.utcnow()


def _build_attempt(
    event: dict,
    event_id: str,
    session_id: str,
    src_ip: str,
    timestamp: datetime,
    geo,
    sensor_id: str,
    **kwargs,
) -> Attempt:
    """Construct an Attempt with all common fields pre-populated."""
    return Attempt(
        sensor_id=sensor_id,
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


def _sensor_match(column, sensor_id: str):
    """Match a sensor, counting unattributed rows as this hub's own.

    Rows written before multi-sensor support have no sensor id. The migration
    backfills them, but tolerating NULL here keeps ingestion correct against a
    database that has not been migrated yet.
    """
    return or_(column == sensor_id, column.is_(None))


def _increment_session_field(
    db: DBSession, session_id: str, field: str, sensor_id: str
) -> None:
    """Increment a counter field on the Session row (ingestion is the only writer).

    Scoped by sensor so a Cowrie session-id collision between two sensors
    cannot bump the wrong session's counters.
    """
    sess = (
        db.query(Session)
        .filter(
            Session.session_id == session_id,
            _sensor_match(Session.sensor_id, sensor_id),
        )
        .first()
    )
    if sess:
        setattr(sess, field, (getattr(sess, field) or 0) + 1)


def _attempt_base_query(
    db: DBSession,
    event_id: str,
    session_id: str,
    src_ip: str,
    timestamp: datetime,
    sensor_id: str,
):
    """Build the common duplicate-detection query for a Cowrie event.

    Scoped by sensor so two sensors observing identical events at the same
    instant are never mistaken for duplicates of each other.
    """
    return db.query(Attempt).filter(
        Attempt.event_id == event_id,
        Attempt.session_id == session_id,
        Attempt.src_ip == src_ip,
        Attempt.timestamp == timestamp,
        _sensor_match(Attempt.sensor_id, sensor_id),
    )


def _attempt_exists(
    db: DBSession,
    event_id: str,
    session_id: str,
    src_ip: str,
    timestamp: datetime,
    sensor_id: str,
    **fields,
) -> bool:
    query = _attempt_base_query(db, event_id, session_id, src_ip, timestamp, sensor_id)
    for name, value in fields.items():
        column = getattr(Attempt, name)
        query = query.filter(column.is_(None) if value is None else column == value)
    return query.first() is not None


def _process_event(
    event: dict,
    db: DBSession,
    sensor_id: str | None = None,
    *,
    trusted_paths: bool = False,
) -> tuple[dict | None, int | None]:
    """Process a single Cowrie JSON event.

    ``sensor_id`` attributes the event to a sensor; it defaults to this hub's
    own. Geolocation and intent are always derived here, never taken from the
    payload, so a compromised remote sensor cannot forge either.

    ``trusted_paths`` says whether ``outfile`` names a file on *this* host. It
    holds only for the Cowrie log this hub tails itself, where Cowrie writes
    the path. Events arriving over /api/ingest describe files on the sensor's
    disk, so their paths are dropped rather than stored — otherwise a sensor
    could name any local file and have the VT reporter upload it.

    Returns (sse_payload, captured_file_id). Either value may be None.
    """
    sensor_id = sensor_id or settings.sensor_id
    event_id = event.get("eventid", "")
    session_id = event.get("session", "")
    src_ip = event.get("src_ip", "")
    timestamp = _parse_timestamp(event.get("timestamp", ""))

    if _is_private_ip(src_ip):
        logger.debug(f"Skipping private IP: {src_ip}")
        return None, None

    # --- Session connect ---
    if event_id == "cowrie.session.connect":
        existing = db.query(Session).filter_by(session_id=session_id).first()
        if existing:
            return None, None

        geoip = get_geoip()
        geo = geoip.lookup(src_ip)
        protocol = event.get("protocol", "ssh")
        session_obj = Session(
            sensor_id=sensor_id,
            session_id=session_id,
            src_ip=src_ip,
            start_time=timestamp,
            protocol=protocol,
            country_code=geo.country_code,
            country_name=geo.country_name,
            latitude=geo.latitude,
            longitude=geo.longitude,
        )
        db.add(session_obj)
        db.commit()
        return {
            "type": "session_start",
            "event_id": event_id,
            "session_id": session_id,
            "src_ip": src_ip,
            "country": geo.country_name,
            "protocol": protocol,
            "sensor_id": sensor_id,
        }, None

    # --- Login attempt ---
    elif event_id in ("cowrie.login.failed", "cowrie.login.success"):
        success = event_id == "cowrie.login.success"
        username = event.get("username", "")
        password = event.get("password", "")
        if _attempt_exists(
            db,
            event_id,
            session_id,
            src_ip,
            timestamp,
            sensor_id,
            username=username,
            password=password,
        ):
            return None, None

        geoip = get_geoip()
        geo = geoip.lookup(src_ip)
        intent, mitre_id = classify_login(success)

        db.add(_build_attempt(
            event, event_id, session_id, src_ip, timestamp, geo, sensor_id,
            username=username,
            password=password,
            success=success,
            intent=intent,
            mitre_id=mitre_id,
        ))
        _increment_session_field(db, session_id, "login_attempts", sensor_id)
        db.commit()
        return {
            "type": "login_attempt",
            "event_id": event_id,
            "session_id": session_id,
            "src_ip": src_ip,
            "username": username,
            "password": password,
            "success": success,
            "country": geo.country_name,
            "latitude": geo.latitude,
            "longitude": geo.longitude,
            "sensor_id": sensor_id,
        }, None

    # --- Command input ---
    elif event_id == "cowrie.command.input":
        command = event.get("input", "")
        if _attempt_exists(
            db,
            event_id,
            session_id,
            src_ip,
            timestamp,
            sensor_id,
            command=command,
        ):
            return None, None

        geoip = get_geoip()
        geo = geoip.lookup(src_ip)
        intent, mitre_id = classify_command(command)

        db.add(_build_attempt(
            event, event_id, session_id, src_ip, timestamp, geo, sensor_id,
            command=command,
            intent=intent,
            mitre_id=mitre_id,
        ))
        _increment_session_field(db, session_id, "commands_run", sensor_id)
        db.commit()
        return {
            "type": "command",
            "event_id": event_id,
            "session_id": session_id,
            "src_ip": src_ip,
            "command": command,
            "intent": intent,
            "mitre_id": mitre_id,
            "country": geo.country_name,
            "latitude": geo.latitude,
            "longitude": geo.longitude,
            "sensor_id": sensor_id,
        }, None

    # --- File download/upload ---
    elif event_id in ("cowrie.session.file_download", "cowrie.session.file_upload"):
        url = event.get("url", event.get("destfile", ""))
        sha256 = _normalized_sha256(event.get("shasum", ""))
        filename = event.get("outfile", event.get("filename", ""))
        command = f"download: {url}" if url else f"upload: {filename}"

        if _attempt_exists(
            db,
            event_id,
            session_id,
            src_ip,
            timestamp,
            sensor_id,
            command=command,
        ):
            return None, None

        geoip = get_geoip()
        geo = geoip.lookup(src_ip)

        attempt = _build_attempt(
            event, event_id, session_id, src_ip, timestamp, geo, sensor_id,
            command=command,
            intent="malware_deployment",
            mitre_id="T1105",
        )
        db.add(attempt)
        db.flush()

        captured_id = None
        if sha256:
            captured = CapturedFile(
                attempt_id=attempt.id,
                sensor_id=sensor_id,
                session_id=session_id,
                timestamp=timestamp,
                filename=os.path.basename(filename) if filename else "",
                url=url,
                sha256=sha256,
                local_path=event.get("outfile", "") if trusted_paths else "",
            )
            db.add(captured)
            db.flush()
            captured_id = captured.id

        _increment_session_field(db, session_id, "files_downloaded", sensor_id)
        db.commit()
        return {
            "type": "file_download",
            "event_id": event_id,
            "session_id": session_id,
            "src_ip": src_ip,
            "url": url,
            "sha256": sha256,
            "country": geo.country_name,
            "sensor_id": sensor_id,
        }, captured_id

    # --- Session closed ---
    elif event_id == "cowrie.session.closed":
        sess = (
            db.query(Session)
            .filter(
                Session.session_id == session_id,
                _sensor_match(Session.sensor_id, sensor_id),
            )
            .first()
        )
        if sess:
            sess.end_time = timestamp
            if sess.start_time:
                delta = timestamp - sess.start_time
                sess.duration_secs = delta.total_seconds()
            db.commit()
        return None, None

    return None, None


def process_batch(
    events: list[dict],
    db: DBSession,
    sensor_id: str | None = None,
    *,
    trusted_paths: bool = False,
) -> list[tuple[dict | None, int | None]]:
    """Process a batch of Cowrie events and mark the sensor as having reported.

    Shared by local log tailing and remote sensor ingestion so both paths
    normalize, enrich, and classify identically. Only the local tailer passes
    ``trusted_paths`` — see :func:`_process_event`.
    """
    sensor_id = sensor_id or settings.sensor_id
    results = [
        _process_event(event, db, sensor_id, trusted_paths=trusted_paths)
        for event in events
    ]

    # One liveness write per batch rather than per event.
    if any(payload for payload, _ in results):
        sensor = db.query(Sensor).filter_by(sensor_id=sensor_id).first()
        if sensor:
            sensor.last_event_at = datetime.utcnow()
            db.commit()
    return results


# Strong references to in-flight fire-and-forget tasks. The event loop only
# keeps weak references, so without this a pending Splunk send or VT
# enrichment can be garbage-collected before it runs.
_pending_tasks: set[asyncio.Task] = set()


def _dispatch(sse_payload: dict | None, captured_id: int | None) -> list[asyncio.Task]:
    """Fan out a processed event: SSE publish + Splunk forward + VT enrichment.

    Splunk send and VT enrichment are fire-and-forget tasks so a slow or
    offline downstream never stalls ingestion.
    """
    tasks: list[asyncio.Task] = []
    if sse_payload:
        publish_event("new_attack", sse_payload)
        tasks.append(asyncio.create_task(splunk_forwarder.send(sse_payload)))
        tasks.append(asyncio.create_task(alerts.alert_for_event(sse_payload)))
    if captured_id:
        tasks.append(asyncio.create_task(enrich_captured_file(captured_id)))
    for task in tasks:
        _pending_tasks.add(task)
        task.add_done_callback(_pending_tasks.discard)
    return tasks


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

                batch: list[dict] = []
                for line in lines:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        batch.append(json.loads(line))
                    except json.JSONDecodeError:
                        logger.debug("Skipping malformed JSON line")
                        continue

                db = SessionLocal()
                try:
                    # Cowrie wrote these paths on this host, so they may be read.
                    for sse_payload, captured_id in process_batch(
                        batch, db, trusted_paths=True
                    ):
                        _dispatch(sse_payload, captured_id)
                finally:
                    db.close()

        except FileNotFoundError:
            logger.warning("Log file disappeared — waiting for it to reappear")
            await asyncio.sleep(5)
            continue
        except Exception as e:
            logger.error(f"Ingestion error: {e}", exc_info=True)

        await asyncio.sleep(1)  # Poll interval
