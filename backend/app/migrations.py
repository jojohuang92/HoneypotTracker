"""Lightweight, idempotent SQLite schema migrations.

``Base.metadata.create_all`` creates new tables but never alters existing ones,
so columns added to already-deployed tables need explicit DDL. Every statement
here is guarded by an existence check and safe to run on every startup.

Adding a column with a constant DEFAULT is O(1) in SQLite — the default is
recorded in the schema and returned for pre-existing rows — so backfilling
sensor_id on a large attempts table costs nothing. Creating the accompanying
index does scan the table once, which is a one-time cost at first startup.
"""

import logging

from sqlalchemy import text
from sqlalchemy.engine import Engine

logger = logging.getLogger(__name__)


def _columns(conn, table: str) -> set[str]:
    rows = conn.execute(text(f"PRAGMA table_info({table})")).fetchall()
    return {r[1] for r in rows}


def _tables(conn) -> set[str]:
    rows = conn.execute(
        text("SELECT name FROM sqlite_master WHERE type='table'")
    ).fetchall()
    return {r[0] for r in rows}


def run_migrations(engine: Engine, local_sensor_id: str) -> list[str]:
    """Apply pending migrations. Returns the list of statements applied."""
    if not engine.url.get_backend_name().startswith("sqlite"):
        # Other backends are not deployed; skip rather than emit wrong DDL.
        return []

    applied: list[str] = []
    # Existing rows predate multi-sensor support, so they belong to this hub's
    # own sensor. Quote defensively: sensor ids are operator-supplied.
    default = local_sensor_id.replace("'", "''")

    with engine.begin() as conn:
        present = _tables(conn)
        for table in ("attempts", "sessions", "captured_files"):
            if table not in present:
                continue  # create_all will make it with the column already
            if "sensor_id" in _columns(conn, table):
                continue
            conn.execute(
                text(
                    f"ALTER TABLE {table} ADD COLUMN sensor_id VARCHAR "
                    f"DEFAULT '{default}'"
                )
            )
            applied.append(f"{table}.sensor_id")

        for table in ("attempts", "sessions", "captured_files"):
            if table not in present:
                continue
            conn.execute(
                text(
                    f"CREATE INDEX IF NOT EXISTS ix_{table}_sensor_id "
                    f"ON {table} (sensor_id)"
                )
            )

        # captured_files.attempt_id is a foreign key that predates any index.
        # Threat scoring joins on it, and without this SQLite scans the whole
        # captured_files table once per matching attempt.
        if "captured_files" in present:
            conn.execute(
                text(
                    "CREATE INDEX IF NOT EXISTS ix_captured_files_attempt_id "
                    "ON captured_files (attempt_id)"
                )
            )

    if applied:
        logger.info("Applied migrations: %s", ", ".join(applied))
    return applied
