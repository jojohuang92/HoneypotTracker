import hashlib
import ipaddress
import logging
import secrets

from fastapi import APIRouter, Depends, Header, HTTPException
from sqlalchemy.orm import Session as DBSession

from app.config import settings
from app.database import get_db
from app.models import Attempt, CapturedFile, Sensor, Session
from app.schemas import SensorCreate, SensorCreated
from app.services import sensor_registry

router = APIRouter()
audit_logger = logging.getLogger("audit")


def _audit_log(action: str, key: str, details: dict | None = None):
    """Log admin action with a truncated key hash for traceability."""
    key_prefix = hashlib.sha256(key.encode()).hexdigest()[:8]
    audit_logger.info(
        "ADMIN_ACTION action=%s key_prefix=%s details=%s",
        action, key_prefix, details,
    )


def _require_admin_key(x_admin_key: str = Header(...)) -> str:
    """Validate the admin API key. Returns a uniform 403 whether the key is
    unconfigured or wrong, so attackers cannot distinguish the two cases."""
    if not settings.admin_api_key or not secrets.compare_digest(
        x_admin_key, settings.admin_api_key
    ):
        raise HTTPException(status_code=403, detail="Invalid admin API key")
    return x_admin_key


def _private_ips_in_db(db: DBSession) -> set[str]:
    attempt_ips = {r[0] for r in db.query(Attempt.src_ip).distinct()}
    session_ips = {r[0] for r in db.query(Session.src_ip).distinct()}
    result = set()
    for ip in attempt_ips | session_ips:
        try:
            if ipaddress.ip_address(ip).is_private:
                result.add(ip)
        except ValueError:
            pass
    return result


@router.get("/private-ips")
def list_private_ips(
    _key: str = Depends(_require_admin_key),
    db: DBSession = Depends(get_db),
):
    """List all private IPs currently in the database."""
    private_ips = _private_ips_in_db(db)
    counts = {}
    for ip in private_ips:
        counts[ip] = db.query(Attempt).filter(Attempt.src_ip == ip).count()

    _audit_log("list_private_ips", _key, {"total_ips": len(private_ips)})
    return {"private_ips": counts, "total_ips": len(private_ips)}


@router.delete("/private-ips")
def delete_private_ips(
    _key: str = Depends(_require_admin_key),
    db: DBSession = Depends(get_db),
):
    """Delete all attempts, sessions, and captured files from private IPs."""
    private_ips = _private_ips_in_db(db)
    if not private_ips:
        _audit_log("delete_private_ips", _key, {"deleted": 0})
        return {"deleted": 0, "message": "No private IPs found"}

    private_attempt_ids = [
        r[0] for r in db.query(Attempt.id).filter(Attempt.src_ip.in_(private_ips))
    ]

    files_deleted = db.query(CapturedFile).filter(
        CapturedFile.attempt_id.in_(private_attempt_ids)
    ).delete(synchronize_session=False)

    attempts_deleted = db.query(Attempt).filter(
        Attempt.src_ip.in_(private_ips)
    ).delete(synchronize_session=False)

    sessions_deleted = db.query(Session).filter(
        Session.src_ip.in_(private_ips)
    ).delete(synchronize_session=False)

    db.commit()

    result = {
        "deleted_ips": sorted(private_ips),
        "attempts_deleted": attempts_deleted,
        "sessions_deleted": sessions_deleted,
        "files_deleted": files_deleted,
    }
    _audit_log("delete_private_ips", _key, result)
    return result


@router.post("/sensors", response_model=SensorCreated, status_code=201)
def create_sensor(
    payload: SensorCreate,
    _key: str = Depends(_require_admin_key),
    db: DBSession = Depends(get_db),
):
    """Register a remote sensor and mint its ingest token.

    The token is returned once and stored only as a SHA-256 hash — there is no
    way to recover it later, only to re-issue.
    """
    if db.query(Sensor).filter_by(sensor_id=payload.sensor_id).first():
        raise HTTPException(status_code=409, detail="Sensor already exists")
    if payload.location_precision not in sensor_registry.PRECISIONS:
        raise HTTPException(
            status_code=400,
            detail=f"location_precision must be one of {sensor_registry.PRECISIONS}",
        )

    token = sensor_registry.generate_token()
    sensor = Sensor(
        sensor_id=payload.sensor_id,
        label=payload.label,
        is_local=False,
        enabled=True,
        token_hash=sensor_registry.hash_token(token),
        country_code=payload.country_code,
        country_name=payload.country_name,
        city=payload.city,
        latitude=payload.latitude,
        longitude=payload.longitude,
        location_precision=payload.location_precision,
        timezone=payload.timezone,
        protocols=payload.protocols,
    )
    db.add(sensor)
    db.commit()

    _audit_log("create_sensor", _key, {"sensor_id": payload.sensor_id})
    return SensorCreated(sensor_id=sensor.sensor_id, label=sensor.label, token=token)


@router.post("/sensors/{sensor_id}/rotate", response_model=SensorCreated)
def rotate_sensor_token(
    sensor_id: str,
    _key: str = Depends(_require_admin_key),
    db: DBSession = Depends(get_db),
):
    """Issue a new ingest token, immediately invalidating the previous one."""
    sensor = db.query(Sensor).filter_by(sensor_id=sensor_id).first()
    if not sensor or sensor.is_local:
        raise HTTPException(status_code=404, detail="Remote sensor not found")

    token = sensor_registry.generate_token()
    sensor.token_hash = sensor_registry.hash_token(token)
    db.commit()

    _audit_log("rotate_sensor_token", _key, {"sensor_id": sensor_id})
    return SensorCreated(sensor_id=sensor.sensor_id, label=sensor.label, token=token)


@router.delete("/sensors/{sensor_id}")
def disable_sensor(
    sensor_id: str,
    _key: str = Depends(_require_admin_key),
    db: DBSession = Depends(get_db),
):
    """Revoke a sensor's access, keeping the events it already reported."""
    sensor = db.query(Sensor).filter_by(sensor_id=sensor_id).first()
    if not sensor or sensor.is_local:
        raise HTTPException(status_code=404, detail="Remote sensor not found")

    sensor.enabled = False
    sensor.token_hash = None
    db.commit()

    _audit_log("disable_sensor", _key, {"sensor_id": sensor_id})
    return {"sensor_id": sensor_id, "enabled": False}
