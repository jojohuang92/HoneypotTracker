"""One-shot backfill: reads entire cowrie.json from the beginning and ingests into DB.

Usage (from backend/ directory with venv active):
    python backfill_logs.py [/path/to/cowrie.json]

If no path is given, uses COWRIE_LOG_PATH from .env (or the default in config.py).
"""

import json
import logging
import sys
from pathlib import Path

# Ensure app package is importable
sys.path.insert(0, str(Path(__file__).parent))

from app.config import settings
from app.database import engine, Base, SessionLocal
from app.services.log_ingestion import _process_event

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)


def backfill(log_path: str):
    path = Path(log_path)
    if not path.exists():
        logger.error(f"Log file not found: {path}")
        sys.exit(1)

    # Ensure tables exist
    Base.metadata.create_all(bind=engine)

    total = 0
    ingested = 0
    errors = 0

    db = SessionLocal()
    try:
        with open(path, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                total += 1
                try:
                    event = json.loads(line)
                    _process_event(event, db)  # VT enrichment skipped during backfill
                    ingested += 1
                except json.JSONDecodeError:
                    errors += 1
                except Exception as e:
                    logger.warning(f"Failed to process event: {e}")
                    errors += 1
    finally:
        db.close()

    logger.info(f"Done. {ingested}/{total} events ingested, {errors} errors.")


if __name__ == "__main__":
    log_path = sys.argv[1] if len(sys.argv) > 1 else settings.cowrie_log_path
    logger.info(f"Backfilling from: {log_path}")
    backfill(log_path)
