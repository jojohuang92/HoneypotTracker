"""Backup and restore of the honeypot database.

These tests drive the real `scripts/backup.sh` and `scripts/restore.sh` against
temporary directories — not a reimplementation of them — because the thing that
has to work is the shell that runs unattended at 03:00, not a Python model of
it.

The database is the one irreplaceable asset in the project: months of attacker
sessions that cannot be re-collected on request. Every branch that could lose
data, or quietly produce a backup that does not restore, is pinned here.
"""

import hashlib
import io
import json
import os
import shutil
import sqlite3
import subprocess
import tarfile
import time
from pathlib import Path

import pytest
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker

from app.database import Base
from tests.conftest import make_attempt, make_captured_file, make_session

REPO_ROOT = Path(__file__).resolve().parents[2]
BACKUP_SH = REPO_ROOT / "scripts" / "backup.sh"
RESTORE_SH = REPO_ROOT / "scripts" / "restore.sh"

SEEDED_ATTEMPTS = 5


# ---------------------------------------------------------------------------
# Layout fixture: a throwaway copy of the production file layout
# ---------------------------------------------------------------------------

class Layout:
    def __init__(self, root: Path):
        self.root = root
        self.db = root / "data" / "honeypot.db"
        self.env_file = root / "release" / "backend" / ".env"
        self.samples = root / "downloads"
        self.backups = root / "data" / "backups"

    @property
    def env(self) -> dict:
        """Environment driving the scripts at test paths, with no systemd."""
        return {
            **os.environ,
            "HP_DB": str(self.db),
            "HP_ENV_FILE": str(self.env_file),
            "HP_SAMPLES_DIR": str(self.samples),
            "HP_BACKUP_DIR": str(self.backups),
            "HP_SERVICE": "",
            "HP_HEALTH_URL": "",
        }

    def archives(self) -> list[Path]:
        return sorted(self.backups.glob("honeypot-*.tar.zst"))

    def latest(self) -> Path:
        return self.archives()[-1]


def _seed(db_path: Path) -> None:
    """Build a real database from the application's own models."""
    db_path.parent.mkdir(parents=True, exist_ok=True)
    engine = create_engine(f"sqlite:///{db_path}")

    @event.listens_for(engine, "connect")
    def _pragmas(dbapi_conn, _rec):
        cur = dbapi_conn.cursor()
        cur.execute("PRAGMA journal_mode=WAL")
        cur.close()

    Base.metadata.create_all(bind=engine)
    session = sessionmaker(bind=engine)()
    for i in range(SEEDED_ATTEMPTS):
        make_attempt(session, session_id=f"sess-{i:03d}", src_ip=f"10.0.0.{i}")
    make_session(session)
    make_captured_file(session)
    session.close()
    engine.dispose()


@pytest.fixture()
def layout(tmp_path) -> Layout:
    lay = Layout(tmp_path)
    _seed(lay.db)

    lay.env_file.parent.mkdir(parents=True, exist_ok=True)
    lay.env_file.write_text("ADMIN_API_KEY=super-secret\nNTFY_URL=\n")
    lay.env_file.chmod(0o600)

    lay.samples.mkdir(parents=True, exist_ok=True)
    for body in (b"#!/bin/sh\necho pwned\n", b"\x7fELF fake binary"):
        sha = hashlib.sha256(body).hexdigest()
        (lay.samples / sha).write_bytes(body)

    return lay


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def run_backup(layout: Layout, **overrides) -> subprocess.CompletedProcess:
    return subprocess.run(
        [str(BACKUP_SH)],
        env={**layout.env, **{k: str(v) for k, v in overrides.items()}},
        capture_output=True,
        text=True,
    )


def run_restore(layout: Layout, *args, **overrides) -> subprocess.CompletedProcess:
    return subprocess.run(
        [str(RESTORE_SH), *args],
        env={**layout.env, **{k: str(v) for k, v in overrides.items()}},
        capture_output=True,
        text=True,
    )


def count_attempts(db_path: Path) -> int:
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    try:
        return conn.execute("SELECT COUNT(*) FROM attempts").fetchone()[0]
    finally:
        conn.close()


def open_archive(archive: Path) -> tarfile.TarFile:
    """Python's tarfile has no zstd support, so decompress through the tool."""
    decompressed = subprocess.run(
        ["zstd", "-dc", str(archive)], capture_output=True, check=True
    ).stdout
    return tarfile.open(fileobj=io.BytesIO(decompressed))


def read_manifest(archive: Path) -> dict:
    with open_archive(archive) as tar:
        return json.load(tar.extractfile("MANIFEST.json"))


def member_names(archive: Path) -> list[str]:
    with open_archive(archive) as tar:
        return tar.getnames()


# ---------------------------------------------------------------------------
# Producing a snapshot
# ---------------------------------------------------------------------------

class TestBackup:
    def test_produces_one_archive_with_a_checksum_sidecar(self, layout):
        result = run_backup(layout)

        assert result.returncode == 0, result.stderr
        assert len(layout.archives()) == 1
        sidecar = Path(str(layout.latest()) + ".sha256")
        assert sidecar.exists()

        digest = hashlib.sha256(layout.latest().read_bytes()).hexdigest()
        assert sidecar.read_text().split()[0] == digest

    def test_archive_carries_database_env_and_samples(self, layout):
        run_backup(layout)
        names = member_names(layout.latest())

        assert "MANIFEST.json" in names
        assert "honeypot.db" in names
        assert "env/backend.env" in names
        assert sum(n.startswith("samples/") and not n == "samples" for n in names) == 2

    def test_manifest_records_row_counts_and_database_digest(self, layout):
        run_backup(layout)
        manifest = read_manifest(layout.latest())

        assert manifest["row_counts"]["attempts"] == SEEDED_ATTEMPTS
        assert manifest["row_counts"]["captured_files"] == 1
        assert manifest["sample_count"] == 2

        with open_archive(layout.latest()) as tar:
            body = tar.extractfile("honeypot.db").read()
        assert manifest["db_sha256"] == hashlib.sha256(body).hexdigest()

    def test_snapshot_captures_writes_still_in_the_wal(self, layout):
        """A plain file copy would miss these rows; VACUUM INTO must not."""
        conn = sqlite3.connect(layout.db)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute(
            "INSERT INTO attempts (sensor_id, session_id, event_id, timestamp,"
            " src_ip, protocol) VALUES ('local', 'wal-1', 'cowrie.login.failed',"
            " '2025-06-15T12:00:00', '9.9.9.9', 'ssh')"
        )
        conn.commit()
        conn.close()

        run_backup(layout)

        assert read_manifest(layout.latest())["row_counts"]["attempts"] == SEEDED_ATTEMPTS + 1

    def test_archive_is_not_world_readable(self, layout):
        """It holds both the admin key and live attacker malware."""
        run_backup(layout)
        assert layout.latest().stat().st_mode & 0o077 == 0

    def test_rotation_keeps_the_newest_and_prunes_sidecars(self, layout):
        for _ in range(3):
            assert run_backup(layout, HP_KEEP=2).returncode == 0
            time.sleep(1.1)  # filenames are second-granular

        archives = layout.archives()
        assert len(archives) == 2
        assert len(list(layout.backups.glob("*.sha256"))) == 2

    def test_a_failed_run_keeps_existing_snapshots_and_leaves_no_partials(self, layout):
        assert run_backup(layout).returncode == 0
        survivor = layout.latest()

        layout.db.write_bytes(b"this is not a database")
        result = run_backup(layout, HP_KEEP=1)

        assert result.returncode != 0
        assert survivor.exists()
        assert list(layout.backups.glob("*.part")) == []

    def test_preflight_aborts_when_free_space_is_short(self, layout):
        result = run_backup(layout, HP_MIN_FREE_FACTOR=10_000_000)

        assert result.returncode != 0
        assert layout.archives() == []


# ---------------------------------------------------------------------------
# Restoring one
# ---------------------------------------------------------------------------

class TestRestore:
    def test_reproduces_the_snapshot_row_for_row(self, layout):
        run_backup(layout)
        layout.db.unlink()

        result = run_restore(layout, "latest")

        assert result.returncode == 0, result.stderr
        assert count_attempts(layout.db) == SEEDED_ATTEMPTS

    def test_restored_database_passes_integrity_check(self, layout):
        run_backup(layout)
        layout.db.unlink()
        run_restore(layout, "latest")

        conn = sqlite3.connect(layout.db)
        try:
            assert conn.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        finally:
            conn.close()

    def test_displaced_database_is_kept_not_deleted(self, layout):
        run_backup(layout)
        before = layout.db.read_bytes()

        run_restore(layout, "--force", "latest")

        kept = list(layout.db.parent.glob("honeypot.db.pre-restore-*"))
        assert len(kept) == 1
        assert kept[0].read_bytes() == before

    def test_refuses_to_overwrite_a_newer_database(self, layout):
        run_backup(layout)
        time.sleep(1.1)
        conn = sqlite3.connect(layout.db)
        conn.execute(
            "INSERT INTO attempts (sensor_id, session_id, event_id, timestamp,"
            " src_ip, protocol) VALUES ('local', 'newer', 'cowrie.login.failed',"
            " '2025-06-16T12:00:00', '8.8.8.8', 'ssh')"
        )
        conn.commit()
        conn.close()

        result = run_restore(layout, "latest")

        assert result.returncode != 0
        assert count_attempts(layout.db) == SEEDED_ATTEMPTS + 1

    def test_force_overwrites_a_newer_database(self, layout):
        run_backup(layout)
        time.sleep(1.1)
        layout.db.touch()

        assert run_restore(layout, "--force", "latest").returncode == 0
        assert count_attempts(layout.db) == SEEDED_ATTEMPTS

    def test_rejects_a_truncated_archive(self, layout):
        run_backup(layout)
        archive = layout.latest()
        archive.write_bytes(archive.read_bytes()[: -64])
        before = layout.db.read_bytes()

        result = run_restore(layout, "--force", str(archive))

        assert result.returncode != 0
        assert layout.db.read_bytes() == before

    def test_rejects_an_archive_whose_sidecar_disagrees(self, layout):
        run_backup(layout)
        sidecar = Path(str(layout.latest()) + ".sha256")
        sidecar.write_text(f"{'0' * 64}  {layout.latest().name}\n")

        result = run_restore(layout, "--force", "latest")

        assert result.returncode != 0

    def test_leaves_env_and_samples_alone_by_default(self, layout):
        run_backup(layout)
        layout.env_file.write_text("ADMIN_API_KEY=rotated-since-backup\n")
        shutil.rmtree(layout.samples)

        assert run_restore(layout, "--force", "latest").returncode == 0
        assert "rotated-since-backup" in layout.env_file.read_text()
        assert not layout.samples.exists()

    def test_restores_env_and_samples_when_asked(self, layout):
        run_backup(layout)
        layout.env_file.write_text("ADMIN_API_KEY=rotated-since-backup\n")
        shutil.rmtree(layout.samples)

        result = run_restore(layout, "--force", "--with-env", "--with-samples", "latest")

        assert result.returncode == 0, result.stderr
        assert "super-secret" in layout.env_file.read_text()
        assert len(list(layout.samples.iterdir())) == 2

    def test_restored_env_is_not_world_readable(self, layout):
        run_backup(layout)
        run_restore(layout, "--force", "--with-env", "latest")

        assert layout.env_file.stat().st_mode & 0o077 == 0
