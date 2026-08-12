"""Fleet view: sensor inventory, health, and cross-sensor overlap."""

from datetime import datetime, timedelta
from itertools import combinations

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy import func
from sqlalchemy.orm import Session as DBSession

from app.database import get_db
from app.models import Attempt, Sensor
from app.rate_limit import limiter
from app.schemas import SensorOut, SensorOverlap, SensorOverlapPair
from app.services import sensor_registry

router = APIRouter()


def _to_out(sensor: Sensor, stats: dict, protocols: dict) -> SensorOut:
    lat, lon = sensor_registry.publish_coords(sensor)
    if not sensor.enabled:
        status = "disabled"
    else:
        status = "offline" if sensor_registry.is_offline(sensor) else "online"

    return SensorOut(
        sensor_id=sensor.sensor_id,
        label=sensor.label,
        is_local=bool(sensor.is_local),
        enabled=bool(sensor.enabled),
        country_code=sensor.country_code,
        country_name=sensor.country_name,
        city=sensor.city if sensor.location_precision != "country" else None,
        latitude=lat,
        longitude=lon,
        location_precision=sensor.location_precision or "country",
        timezone=sensor.timezone,
        protocols=[p for p in (sensor.protocols or "").split(",") if p],
        status=status,
        last_event_at=sensor.last_event_at,
        last_heartbeat_at=sensor.last_heartbeat_at,
        agent_version=sensor.agent_version,
        disk_free_bytes=sensor.disk_free_bytes,
        disk_total_bytes=sensor.disk_total_bytes,
        low_disk=sensor_registry.low_disk(sensor),
        total_attempts=stats.get("total", 0),
        attempts_24h=stats.get("day", 0),
        unique_ips_24h=stats.get("ips_24h", 0),
        protocol_breakdown=protocols,
    )


@router.get("", response_model=list[SensorOut])
@limiter.limit("60/minute")
def list_sensors(request: Request, db: DBSession = Depends(get_db)):
    """Every registered sensor with health and recent activity.

    Coordinates come back already coarsened to each sensor's precision.
    """
    since = datetime.utcnow() - timedelta(days=1)

    totals = dict(
        db.query(Attempt.sensor_id, func.count(Attempt.id)).group_by(Attempt.sensor_id).all()
    )
    day_rows = (
        db.query(
            Attempt.sensor_id,
            func.count(Attempt.id),
            func.count(func.distinct(Attempt.src_ip)),
        )
        .filter(Attempt.timestamp >= since)
        .group_by(Attempt.sensor_id)
        .all()
    )
    day = {r[0]: {"day": r[1], "ips_24h": r[2]} for r in day_rows}

    proto_rows = (
        db.query(Attempt.sensor_id, Attempt.protocol, func.count(Attempt.id))
        .filter(Attempt.timestamp >= since)
        .group_by(Attempt.sensor_id, Attempt.protocol)
        .all()
    )
    protocols: dict[str, dict[str, int]] = {}
    for sensor_id, protocol, count in proto_rows:
        protocols.setdefault(sensor_id, {})[protocol or "unknown"] = count

    out = []
    for sensor in db.query(Sensor).order_by(Sensor.is_local.desc(), Sensor.sensor_id).all():
        stats = {"total": totals.get(sensor.sensor_id, 0), **day.get(sensor.sensor_id, {})}
        out.append(_to_out(sensor, stats, protocols.get(sensor.sensor_id, {})))
    return out


@router.get("/overlap", response_model=SensorOverlap)
@limiter.limit("30/minute")
def sensor_overlap(
    request: Request,
    days: int = Query(7, ge=1, le=90),
    limit: int = Query(20, ge=1, le=100),
    db: DBSession = Depends(get_db),
):
    """Which attackers hit several sensors versus just one.

    Overlap is the signal that separates indiscriminate internet-wide scanning
    from traffic aimed at one host. With a single reporting sensor it is
    definitionally zero, and ``sensors_reporting`` says so.
    """
    since = datetime.utcnow() - timedelta(days=days)

    rows = (
        db.query(Attempt.src_ip, Attempt.sensor_id, func.count(Attempt.id))
        .filter(Attempt.timestamp >= since)
        .group_by(Attempt.src_ip, Attempt.sensor_id)
        .all()
    )

    by_ip: dict[str, dict[str, int]] = {}
    for ip, sensor_id, count in rows:
        by_ip.setdefault(ip, {})[sensor_id or "unknown"] = count

    sensors_reporting = len({s for seen in by_ip.values() for s in seen})
    shared = {ip: seen for ip, seen in by_ip.items() if len(seen) > 1}

    exclusive: dict[str, int] = {}
    for seen in by_ip.values():
        if len(seen) == 1:
            only = next(iter(seen))
            exclusive[only] = exclusive.get(only, 0) + 1

    pair_counts: dict[tuple[str, str], int] = {}
    for seen in shared.values():
        for a, b in combinations(sorted(seen), 2):
            pair_counts[(a, b)] = pair_counts.get((a, b), 0) + 1

    top_shared = sorted(
        (
            {
                "src_ip": ip,
                "sensors": sorted(seen),
                "total": sum(seen.values()),
                "per_sensor": seen,
            }
            for ip, seen in shared.items()
        ),
        key=lambda r: -r["total"],
    )[:limit]

    total_ips = len(by_ip)
    return SensorOverlap(
        days=days,
        sensors_reporting=sensors_reporting,
        total_ips=total_ips,
        shared_ips=len(shared),
        overlap_rate=round(len(shared) / total_ips * 100, 2) if total_ips else 0.0,
        exclusive_by_sensor=exclusive,
        pairs=[
            SensorOverlapPair(sensor_a=a, sensor_b=b, shared_ips=n)
            for (a, b), n in sorted(pair_counts.items(), key=lambda kv: -kv[1])
        ],
        top_shared=top_shared,
    )
