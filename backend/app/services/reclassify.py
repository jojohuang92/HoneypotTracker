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


def reclassify_unknown(
    db: DBSession, limit: int = BATCH, after_id: int = 0
) -> tuple[int, int | None]:
    """Re-classify one batch of unknown commands.

    Returns ``(changed, cursor)``, where ``cursor`` is the highest row id
    examined — pass it back as ``after_id`` to continue — or ``None`` once the
    scan has run off the end of the table.

    The cursor is what makes the scan finish. Rows the rules still abstain on
    keep ``intent = 'unknown'``, so they stay in the candidate set no matter
    how many times they are examined; paging by id steps over them, while
    re-querying from the start would keep handing back the same ones.
    """
    candidates = (
        db.query(Attempt)
        .filter(
            Attempt.intent == "unknown",
            Attempt.command.isnot(None),
            Attempt.command != "",
            Attempt.id > after_id,
        )
        .order_by(Attempt.id)
        .limit(limit)
        .all()
    )
    if not candidates:
        return 0, None

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
    return updated, candidates[-1].id


def run_reclassify_pass() -> int:
    """One full pass over the backlog. Returns the total number changed.

    Ends by reaching the end of the table, never by a batch changing nothing:
    a batch made up entirely of commands the rules abstain on is normal, and
    treating it as the end strands every classifiable row behind it.
    """
    total = 0
    cursor = 0
    while True:
        db = SessionLocal()
        try:
            changed, cursor = reclassify_unknown(db, limit=BATCH, after_id=cursor)
        finally:
            db.close()
        if cursor is None:
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
