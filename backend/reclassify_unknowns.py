"""Re-run the rule classifier on rows currently labeled 'unknown'.

Only updates rows where the new classifier produces a non-unknown label,
so this is safe to re-run and won't regress previously classified rows.
"""

from __future__ import annotations

from app.database import SessionLocal
from app.models import Attempt
from app.services.classifier import classify_command


BATCH = 1000


def main() -> None:
    db = SessionLocal()
    try:
        total = (
            db.query(Attempt)
            .filter(Attempt.intent == "unknown", Attempt.command.isnot(None))
            .count()
        )
        print(f"candidates: {total}")

        updated = 0
        offset = 0
        while True:
            rows = (
                db.query(Attempt)
                .filter(Attempt.intent == "unknown", Attempt.command.isnot(None))
                .order_by(Attempt.id)
                .offset(offset)
                .limit(BATCH)
                .all()
            )
            if not rows:
                break
            changed_in_batch = 0
            for row in rows:
                intent, mitre_id = classify_command(row.command or "")
                if intent != "unknown":
                    row.intent = intent
                    row.mitre_id = mitre_id
                    changed_in_batch += 1
            db.commit()
            updated += changed_in_batch
            # Rows we didn't change still count against offset (they stay 'unknown')
            offset += len(rows) - changed_in_batch
            print(f"scanned={offset + updated} reclassified={updated}")

        print(f"done: reclassified {updated}/{total}")
    finally:
        db.close()


if __name__ == "__main__":
    main()
