import hashlib
import ipaddress
import logging
import secrets

from fastapi import APIRouter, Depends, Header, HTTPException
from sqlalchemy.orm import Session as DBSession

from app.config import settings
from app.database import get_db
from app.models import Attempt, CapturedFile, Session

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
