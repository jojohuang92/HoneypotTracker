"""Sensor registry: identity, ingest-token verification, and health.

Security posture for remote sensors:
- Tokens are stored only as SHA-256 hashes and compared in constant time.
- The token identifies the sensor, so a leaked token cannot be used to submit
  events attributed to a *different* sensor.
- Published coordinates are rounded to the sensor's declared precision, so a
  residential sensor never discloses a street-level position through the API.
"""

import hashlib
import logging
import secrets
from datetime import datetime, timedelta

from sqlalchemy.orm import Session as DBSession

from app.config import settings
from app.models import Sensor

logger = logging.getLogger(__name__)

PRECISIONS = ("exact", "city", "country")

# Decimal places kept per precision level. One decimal is ~11 km; zero is
# ~111 km, enough to place a marker in the right country and nowhere finer.
_ROUNDING = {"exact": None, "city": 1, "country": 0}


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def generate_token() -> str:
    return secrets.token_urlsafe(32)


def publish_coords(sensor: Sensor) -> tuple[float | None, float | None]:
    """Coordinates as they may be shown publicly, coarsened by precision."""
    if sensor.latitude is None or sensor.longitude is None:
        return None, None
    digits = _ROUNDING.get(sensor.location_precision or "country", 0)
    if digits is None:
        return sensor.latitude, sensor.longitude
    return round(sensor.latitude, digits), round(sensor.longitude, digits)


def authenticate(db: DBSession, token: str) -> Sensor | None:
    """Resolve an ingest token to its enabled sensor, or None."""
    if not token:
        return None
    digest = hash_token(token)
    # Compare every candidate so timing does not reveal which sensor matched.
    match: Sensor | None = None
    for sensor in db.query(Sensor).filter(Sensor.token_hash.isnot(None)).all():
        if secrets.compare_digest(sensor.token_hash, digest):
            match = sensor
    if match is None or not match.enabled:
        return None
    return match


def ensure_local_sensor(db: DBSession) -> Sensor:
    """Create or refresh the row describing this hub's own sensor."""
    sensor = db.query(Sensor).filter_by(sensor_id=settings.sensor_id).first()
    precision = settings.sensor_location_precision
    if precision not in PRECISIONS:
        precision = "exact"

    if sensor is None:
        sensor = Sensor(sensor_id=settings.sensor_id, is_local=True)
        db.add(sensor)

    sensor.label = settings.sensor_label or settings.honeypot_label
    sensor.is_local = True
    sensor.enabled = True
    sensor.country_code = settings.sensor_country_code or sensor.country_code
    sensor.city = settings.sensor_city or sensor.city
    if settings.sensor_latitude is not None:
        sensor.latitude = settings.sensor_latitude
    if settings.sensor_longitude is not None:
        sensor.longitude = settings.sensor_longitude
    sensor.location_precision = precision
    sensor.timezone = sensor.timezone or settings.local_timezone
    sensor.protocols = settings.sensor_protocols
    db.commit()
    return sensor


def is_offline(sensor: Sensor, now: datetime | None = None) -> bool:
    """True when a sensor has stopped reporting.

    Remote sensors are judged by agent heartbeat, which arrives on a timer and
    so is independent of attack volume. The local sensor has no agent, so its
    ingestion is judged by event flow instead.
    """
    now = now or datetime.utcnow()
    cutoff = now - timedelta(minutes=settings.sensor_offline_after_minutes)
    marker = sensor.last_event_at if sensor.is_local else sensor.last_heartbeat_at
    if marker is None:
        # Never reported: only "offline" once it has had time to check in.
        return sensor.created_at is not None and sensor.created_at < cutoff
    return marker < cutoff


def low_disk(sensor: Sensor) -> bool:
    if sensor.disk_free_bytes is None:
        return False
    return sensor.disk_free_bytes < settings.sensor_min_disk_free_mb * 1024 * 1024
