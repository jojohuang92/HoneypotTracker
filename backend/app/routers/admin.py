import ipaddress

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session as DBSession

from app.database import get_db
from app.models import Attempt, CapturedFile, Session

router = APIRouter()


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
def list_private_ips(db: DBSession = Depends(get_db)):
    """List all private IPs currently in the database."""
    private_ips = _private_ips_in_db(db)
    counts = {}
    for ip in private_ips:
        counts[ip] = db.query(Attempt).filter(Attempt.src_ip == ip).count()
    return {"private_ips": counts, "total_ips": len(private_ips)}


@router.delete("/private-ips")
def delete_private_ips(db: DBSession = Depends(get_db)):
    """Delete all attempts, sessions, and captured files from private IPs."""
    private_ips = _private_ips_in_db(db)
    if not private_ips:
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

    return {
        "deleted_ips": sorted(private_ips),
        "attempts_deleted": attempts_deleted,
        "sessions_deleted": sessions_deleted,
        "files_deleted": files_deleted,
    }
