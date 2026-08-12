"""Event ingestion from remote sensors.

Remote sensors cannot be reached inbound (they sit behind NAT), so they push
batches here. The endpoint is deliberately narrow:

- the bearer token identifies the sensor, so a leaked token cannot submit
  events attributed to another sensor;
- batches carry (epoch, seq) and are replayed at most once, so a retry after a
  lost response cannot double-count attacks;
- payloads are size-capped, and every event is re-normalized, re-geolocated,
  and re-classified by the hub — nothing the sensor claims about geography or
  intent is trusted.
"""

import logging
from datetime import datetime

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from sqlalchemy.orm import Session as DBSession

from app.config import settings
from app.database import get_db
from app.models import Sensor
from app.rate_limit import limiter
from app.schemas import HeartbeatIn, IngestBatch, IngestResult
from app.services import sensor_registry
from app.services.log_ingestion import _dispatch, process_batch

logger = logging.getLogger(__name__)
router = APIRouter()


def _require_sensor(
    db: DBSession = Depends(get_db),
    x_sensor_key: str = Header(...),
) -> Sensor:
    """Resolve the sensor from its ingest token, or fail uniformly."""
    sensor = sensor_registry.authenticate(db, x_sensor_key)
    if sensor is None:
        # Same response whether the token is unknown, malformed, or disabled.
        raise HTTPException(status_code=403, detail="Invalid sensor key")
    return sensor


def _guard_body_size(request: Request) -> None:
    length = request.headers.get("content-length")
    if length and length.isdigit() and int(length) > settings.ingest_max_bytes:
        raise HTTPException(status_code=413, detail="Batch too large")


@router.post("", response_model=IngestResult)
@limiter.limit("120/minute")
async def ingest(
    request: Request,
    batch: IngestBatch,
    sensor: Sensor = Depends(_require_sensor),
    db: DBSession = Depends(get_db),
):
    """Accept a batch of raw Cowrie events from a remote sensor."""
    _guard_body_size(request)

    if len(batch.events) > settings.ingest_max_events:
        raise HTTPException(
            status_code=413,
            detail=f"Batch exceeds {settings.ingest_max_events} events",
        )

    # A new agent epoch means its cursor was reset (fresh install, lost state),
    # so sequence numbers start over and must not be judged against the old high
    # water mark.
    new_epoch = batch.epoch != (sensor.last_epoch or "")
    high_water = 0 if new_epoch else (sensor.last_seq or 0)

    fresh = [e for e in batch.events if e.seq > high_water]
    skipped = len(batch.events) - len(fresh)

    accepted = 0
    if fresh:
        results = process_batch([e.event for e in fresh], db, sensor.sensor_id)
        for sse_payload, captured_id in results:
            _dispatch(sse_payload, captured_id)
        accepted = sum(1 for payload, _ in results if payload)

    sensor.last_epoch = batch.epoch
    sensor.last_seq = max([high_water] + [e.seq for e in fresh])
    sensor.last_heartbeat_at = datetime.utcnow()
    db.commit()

    if skipped:
        logger.info(
            "Ingest from %s: %d accepted, %d replayed events skipped",
            sensor.sensor_id, accepted, skipped,
        )

    return IngestResult(accepted=accepted, skipped=skipped, last_seq=sensor.last_seq)


@router.post("/heartbeat")
@limiter.limit("60/minute")
def heartbeat(
    request: Request,
    payload: HeartbeatIn,
    sensor: Sensor = Depends(_require_sensor),
    db: DBSession = Depends(get_db),
):
    """Liveness ping plus agent telemetry.

    Heartbeats are independent of attack volume, so a quiet-but-healthy sensor
    is never mistaken for a dead one.
    """
    sensor.last_heartbeat_at = datetime.utcnow()
    if payload.agent_version:
        sensor.agent_version = payload.agent_version
    if payload.disk_free_bytes is not None:
        sensor.disk_free_bytes = payload.disk_free_bytes
    if payload.disk_total_bytes is not None:
        sensor.disk_total_bytes = payload.disk_total_bytes
    db.commit()
    return {"status": "ok", "sensor_id": sensor.sensor_id}
