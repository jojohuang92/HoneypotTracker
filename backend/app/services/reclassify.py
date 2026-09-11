"""Re-run the intent rules over commands that previously matched none.

A rule improvement only helps events that arrive after it ships. The stored
corpus keeps whatever verdict the rules gave at ingestion time, so without a
pass like this one, fixing a regex leaves hundreds of thousands of rows still
carrying the old answer — and the dashboard keeps showing it.

Only ``unknown`` rows are revisited. A row the rules already classified is left
strictly alone: this is a way to fill in abstentions, never a re-label of the
whole corpus on every restart.
"""

import asyncio
import logging

from sqlalchemy.orm import Session as DBSession

from app.database import SessionLocal
from app.models import Attempt
from app.services.classifier import classify_command

logger = logging.getLogger(__name__)

BATCH = 500

# Ingestion writes a synthetic "download: <url>" / "upload: <name>" row for
# file-transfer events and sets their intent directly, never through the rules.
# Those strings are not shell commands: handing one to the classifier reads the
# URL as if it were a command and produces a confident wrong answer. They
# should never be unknown in the first place, so this is a guard rather than a
# filter — but it is a cheap one, and the failure it prevents is silent.
SYNTHETIC_PREFIXES = ("download: ", "upload: ")


def reclassify_unknown(db: DBSession, limit: int = BATCH) -> int:
    """Re-classify up to ``limit`` unknown commands. Returns how many changed."""
    candidates = (
        db.query(Attempt)
        .filter(
            Attempt.intent == "unknown",
            Attempt.command.isnot(None),
            Attempt.command != "",
        )
        .limit(limit)
        .all()
    )

    updated = 0
    for attempt in candidates:
        command = attempt.command or ""
        if command.startswith(SYNTHETIC_PREFIXES):
            continue

        intent, mitre_id = classify_command(command)
        if intent == "unknown":
            continue

        attempt.intent = intent
        attempt.mitre_id = mitre_id
        updated += 1

    if updated:
        db.commit()
    return updated


def run_reclassify_pass() -> int:
    """One full pass over the backlog. Returns the total number changed.

    Terminates when a batch changes nothing. Rows the rules still abstain on
    stay ``unknown`` and are simply offered again on the next startup, which is
    what makes a later rule improvement reach them without any extra machinery.
    """
    total = 0
    while True:
        db = SessionLocal()
        try:
            changed = reclassify_unknown(db)
        finally:
            db.close()
        if not changed:
            return total
        total += changed


async def reclassify_worker() -> None:
    """Startup task: apply current rules to the stored backlog, then stop.

    Deliberately not a loop. New events are classified at ingestion, so there is
    nothing to poll for — the backlog is a one-time debt each time the rules
    change.
    """
    try:
        total = await asyncio.to_thread(run_reclassify_pass)
        if total:
            logger.info("Reclassified %s previously-unknown commands", total)
    except Exception:
        logger.exception("Reclassification pass failed")
