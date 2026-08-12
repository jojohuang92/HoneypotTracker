"""Watches sensor liveness and disk, alerting through the existing channels.

A silent sensor looks identical to a quiet internet until you check: this
worker is what turns "no data" into "the Taipei box stopped reporting". Uses
the same cooldown-guarded alert path as attack alerts, so an offline sensor
notifies once rather than every cycle.
"""

import asyncio
import logging

from app.config import settings
from app.database import SessionLocal
from app.models import Sensor
from app.services import alerts, sensor_registry

logger = logging.getLogger(__name__)

CHECK_INTERVAL_SECS = 300

# Sensors currently considered down, so recovery can be announced once.
_down: set[str] = set()


def _snapshot() -> list[dict]:
    """Read sensor health in one short-lived session."""
    db = SessionLocal()
    try:
        rows = []
        for sensor in db.query(Sensor).filter(Sensor.enabled.is_(True)).all():
            rows.append(
                {
                    "sensor_id": sensor.sensor_id,
                    "label": sensor.label,
                    "offline": sensor_registry.is_offline(sensor),
                    "low_disk": sensor_registry.low_disk(sensor),
                    "disk_free_bytes": sensor.disk_free_bytes,
                    "is_local": bool(sensor.is_local),
                }
            )
        return rows
    finally:
        db.close()


async def check_once() -> None:
    for row in await asyncio.to_thread(_snapshot):
        sensor_id = row["sensor_id"]
        label = row["label"] or sensor_id

        if row["offline"]:
            if sensor_id not in _down:
                _down.add(sensor_id)
                signal = "events" if row["is_local"] else "heartbeats"
                await alerts.send_alert(
                    "Honeypot: sensor offline",
                    f"{label} has sent no {signal} for over "
                    f"{settings.sensor_offline_after_minutes} minutes",
                    priority="high",
                )
        elif sensor_id in _down:
            _down.discard(sensor_id)
            await alerts.send_alert("Honeypot: sensor back online", f"{label} is reporting again")

        if row["low_disk"]:
            free_mb = (row["disk_free_bytes"] or 0) // (1024 * 1024)
            # Cooldown-guarded, so this repeats at most once per cooldown window.
            if alerts._should_send(f"low-disk:{sensor_id}"):
                await alerts.send_alert(
                    "Honeypot: sensor low on disk",
                    f"{label} has {free_mb} MB free "
                    f"(threshold {settings.sensor_min_disk_free_mb} MB)",
                    priority="high",
                )


async def sensor_health_worker() -> None:
    logger.info("Sensor health worker started")
    while True:
        try:
            await check_once()
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("Sensor health check failed")
        await asyncio.sleep(CHECK_INTERVAL_SECS)
