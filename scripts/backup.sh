#!/usr/bin/env bash
# Daily snapshot of the honeypot database, captured .env, and Cowrie samples.
#
# Invoked by honeypot-backup.timer. Safe to run by hand at any time — the API
# keeps serving and writing throughout, because the database copy goes through
# SQLite's VACUUM INTO rather than a file copy. The database runs in WAL mode
# (app/database.py), so recently committed rows live in honeypot.db-wal, and a
# plain `cp honeypot.db` would silently produce a backup missing them.
#
# Every path is overridable via HP_* so the test suite can drive this exact
# script against temporary directories.
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)

HP_DB=${HP_DB:-/home/jopi/honeypot-data/honeypot.db}
HP_ENV_FILE=${HP_ENV_FILE:-/home/jopi/HoneypotTracker-release/backend/.env}
HP_SAMPLES_DIR=${HP_SAMPLES_DIR:-/home/jopi/docker/cowrie/var/lib/cowrie/downloads}
HP_BACKUP_DIR=${HP_BACKUP_DIR:-/home/jopi/honeypot-data/backups}
HP_RELEASE_DIR=${HP_RELEASE_DIR:-$(dirname "$SCRIPT_DIR")}
HP_KEEP=${HP_KEEP:-7}
HP_MIN_FREE_FACTOR=${HP_MIN_FREE_FACTOR:-1.3}
HP_PYTHON=${HP_PYTHON:-python3}

log() { printf '%s backup: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"; }
die() { printf '%s backup: ERROR %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >&2; exit 1; }

command -v zstd >/dev/null 2>&1 || die "zstd is not installed"
command -v "$HP_PYTHON" >/dev/null 2>&1 || die "python interpreter not found: $HP_PYTHON"
[[ -f $HP_DB ]] || die "database not found: $HP_DB"

mkdir -p "$HP_BACKUP_DIR"
chmod 700 "$HP_BACKUP_DIR"

# --- preflight: refuse to start a run that could fill the card ----------------
db_bytes=$(stat -c %s "$HP_DB")
free_bytes=$(df -PB1 "$HP_BACKUP_DIR" | awk 'NR==2 {print $4}')
need_bytes=$("$HP_PYTHON" -c 'import sys; print(int(float(sys.argv[1]) * int(sys.argv[2])))' \
    "$HP_MIN_FREE_FACTOR" "$db_bytes")
if (( free_bytes < need_bytes )); then
    die "insufficient free space: need ${need_bytes}B, have ${free_bytes}B"
fi

stamp=$(date -u +%Y%m%dT%H%M%SZ)
name="honeypot-${stamp}.tar.zst"
archive="$HP_BACKUP_DIR/$name"
partial="$archive.part"

stage=$(mktemp -d "$HP_BACKUP_DIR/stage-XXXXXX")
cleanup() { rm -rf "$stage" "$partial"; }
trap cleanup EXIT

# --- stage the things that are not the database -------------------------------
members=(MANIFEST.json honeypot.db)

mkdir -p "$stage/samples"
sample_note="none"
if [[ -d $HP_SAMPLES_DIR ]]; then
    # -a preserves the 0640 the sample-perms timer applies; samples are live
    # malware and stay exactly as captured.
    find "$HP_SAMPLES_DIR" -maxdepth 1 -type f -exec cp -a {} "$stage/samples/" \;
    sample_note="$HP_SAMPLES_DIR"
fi
members+=(samples)

env_included=0
if [[ -f $HP_ENV_FILE ]]; then
    mkdir -p "$stage/env"
    install -m 0600 "$HP_ENV_FILE" "$stage/env/backend.env"
    env_included=1
    members+=(env)
else
    log "no .env at $HP_ENV_FILE — snapshot will not contain one"
fi

git_sha=$(git -C "$HP_RELEASE_DIR" rev-parse HEAD 2>/dev/null || echo unknown)

# --- snapshot the database, verify it, and describe the result ----------------
# A snapshot that fails integrity_check is not a backup; the script dies here
# and the existing rotation is left untouched.
"$HP_PYTHON" - "$HP_DB" "$stage" "$git_sha" "$env_included" "$HP_KEEP" "$sample_note" <<'PY'
import hashlib
import json
import os
import sqlite3
import socket
import sys
from datetime import datetime, timezone
from pathlib import Path

src, stage, git_sha, env_included, keep, sample_note = sys.argv[1:7]
stage = Path(stage)
copy = stage / "honeypot.db"

source = sqlite3.connect(src)
try:
    source.execute("VACUUM INTO ?", (str(copy),))
finally:
    source.close()

snap = sqlite3.connect(f"file:{copy}?mode=ro", uri=True)
try:
    status = snap.execute("PRAGMA integrity_check").fetchone()[0]
    if status != "ok":
        sys.exit(f"snapshot failed integrity_check: {status}")
    tables = [
        row[0]
        for row in snap.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
            " AND name NOT LIKE 'sqlite_%' ORDER BY name"
        )
    ]
    row_counts = {
        table: snap.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[0]
        for table in tables
    }
finally:
    snap.close()

digest = hashlib.sha256()
with copy.open("rb") as handle:
    for chunk in iter(lambda: handle.read(1 << 20), b""):
        digest.update(chunk)

samples = sorted(p for p in (stage / "samples").iterdir() if p.is_file())

manifest = {
    "created_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "created_epoch": int(datetime.now(timezone.utc).timestamp()),
    "host": socket.gethostname(),
    "git_sha": git_sha,
    "source_db": src,
    "db_bytes": copy.stat().st_size,
    "db_sha256": digest.hexdigest(),
    "row_counts": row_counts,
    "sample_source": sample_note,
    "sample_count": len(samples),
    "sample_bytes": sum(p.stat().st_size for p in samples),
    "env_included": env_included == "1",
    "keep": int(keep),
}
(stage / "MANIFEST.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
print(f"{manifest['db_bytes']} {sum(manifest['row_counts'].values())} {manifest['sample_count']}")
PY

# --- pack atomically ----------------------------------------------------------
# Write to .part and rename only once zstd has exited cleanly, so a power cut
# can never leave behind a truncated file that looks like a valid snapshot.
(
    umask 077
    tar -C "$stage" -cf - "${members[@]}" | zstd -q -3 -o "$partial"
)
chmod 600 "$partial"
mv "$partial" "$archive"
( cd "$HP_BACKUP_DIR" && sha256sum "$name" > "$name.sha256" )
chmod 600 "$archive.sha256"

archive_bytes=$(stat -c %s "$archive")
log "wrote $name (${archive_bytes}B from ${db_bytes}B database)"

# --- rotate, only after the new snapshot is safely in place -------------------
mapfile -t existing < <(find "$HP_BACKUP_DIR" -maxdepth 1 -name 'honeypot-*.tar.zst' | sort)
surplus=$(( ${#existing[@]} - HP_KEEP ))
if (( surplus > 0 )); then
    for stale in "${existing[@]:0:$surplus}"; do
        rm -f "$stale" "$stale.sha256"
        log "pruned $(basename "$stale")"
    done
fi

log "done — $(( ${#existing[@]} > HP_KEEP ? HP_KEEP : ${#existing[@]} )) snapshot(s) retained"
