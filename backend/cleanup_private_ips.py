"""Delete all attempts, sessions, and captured files sourced from private/reserved IPs.

Usage (from backend/ with venv active):
    python cleanup_private_ips.py [--dry-run]
"""

import ipaddress
import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from app.database import engine, Base, SessionLocal
from app.models import Attempt, CapturedFile, Session

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

DRY_RUN = "--dry-run" in sys.argv


def is_private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def run():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        # Collect all unique IPs across attempts and sessions
        attempt_ips = {r[0] for r in db.query(Attempt.src_ip).distinct()}
        session_ips = {r[0] for r in db.query(Session.src_ip).distinct()}
        private_ips = {ip for ip in (attempt_ips | session_ips) if is_private(ip)}

        if not private_ips:
            logger.info("No private IPs found — nothing to do.")
            return

        logger.info(f"Private IPs to purge: {sorted(private_ips)}")

        # Count before deletion
        attempt_count = db.query(Attempt).filter(Attempt.src_ip.in_(private_ips)).count()
        session_count = db.query(Session).filter(Session.src_ip.in_(private_ips)).count()

        # CapturedFile has no src_ip — delete via attempt_id
        private_attempt_ids = [
            r[0] for r in db.query(Attempt.id).filter(Attempt.src_ip.in_(private_ips))
        ]
        file_count = db.query(CapturedFile).filter(
            CapturedFile.attempt_id.in_(private_attempt_ids)
        ).count()

        logger.info(
            f"Will delete: {attempt_count} attempts, {session_count} sessions, "
            f"{file_count} captured files"
        )

        if DRY_RUN:
            logger.info("Dry run — no changes made.")
            return

        if file_count:
            db.query(CapturedFile).filter(
                CapturedFile.attempt_id.in_(private_attempt_ids)
            ).delete(synchronize_session=False)

        db.query(Attempt).filter(Attempt.src_ip.in_(private_ips)).delete(
            synchronize_session=False
        )
        db.query(Session).filter(Session.src_ip.in_(private_ips)).delete(
            synchronize_session=False
        )

        db.commit()
        logger.info("Done.")
    finally:
        db.close()


if __name__ == "__main__":
    run()
