#!/usr/bin/env bash
# Restore a snapshot produced by scripts/backup.sh.
#
#   restore.sh [--force] [--with-env] [--with-samples] <snapshot|latest>
#
# The database is restored by default and nothing else: in a real recovery the
# thing that is gone is the data, while .env and the sample directory are
# usually current and must not be rolled back underneath a running system.
#
# The database being replaced is never deleted — it is moved aside as
# honeypot.db.pre-restore-<timestamp>, so a restore from the wrong snapshot is
# itself recoverable.
set -euo pipefail

HP_DB=${HP_DB:-/home/jopi/honeypot-data/honeypot.db}
HP_ENV_FILE=${HP_ENV_FILE:-/home/jopi/HoneypotTracker-release/backend/.env}
HP_SAMPLES_DIR=${HP_SAMPLES_DIR:-/home/jopi/docker/cowrie/var/lib/cowrie/downloads}
HP_BACKUP_DIR=${HP_BACKUP_DIR:-/home/jopi/honeypot-data/backups}
HP_SERVICE=${HP_SERVICE-honeypot-api}
HP_HEALTH_URL=${HP_HEALTH_URL-http://127.0.0.1:8000/api/health}
HP_PYTHON=${HP_PYTHON:-python3}

log() { printf '%s restore: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"; }
die() { printf '%s restore: ERROR %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >&2; exit 1; }

force=0
with_env=0
with_samples=0
target=""

while (( $# )); do
    case "$1" in
        --force)        force=1 ;;
        --with-env)     with_env=1 ;;
        --with-samples) with_samples=1 ;;
        -h|--help)
            sed -n '2,12p' "$0" | sed 's/^# \?//'
            exit 0 ;;
        -*) die "unknown option: $1" ;;
        *)  [[ -z $target ]] || die "more than one snapshot given"
            target="$1" ;;
    esac
    shift
done

[[ -n $target ]] || die "usage: restore.sh [--force] [--with-env] [--with-samples] <snapshot|latest>"

command -v zstd >/dev/null 2>&1 || die "zstd is not installed"

# --- resolve the snapshot -----------------------------------------------------
if [[ $target == latest ]]; then
    archive=$(find "$HP_BACKUP_DIR" -maxdepth 1 -name 'honeypot-*.tar.zst' | sort | tail -1)
    [[ -n $archive ]] || die "no snapshots in $HP_BACKUP_DIR"
elif [[ -f $target ]]; then
    archive=$target
elif [[ -f $HP_BACKUP_DIR/$target ]]; then
    archive=$HP_BACKUP_DIR/$target
else
    die "snapshot not found: $target"
fi
archive=$(readlink -f "$archive")
log "using $archive"

# --- verify before touching anything -----------------------------------------
if [[ -f $archive.sha256 ]]; then
    ( cd "$(dirname "$archive")" && sha256sum --quiet -c "$archive.sha256" ) \
        || die "checksum mismatch — refusing to restore $archive"
else
    log "WARNING no .sha256 sidecar; falling back to the in-archive manifest"
fi

stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT

zstd -dc "$archive" | tar -C "$stage" -xf - || die "archive is unreadable: $archive"
[[ -f $stage/honeypot.db && -f $stage/MANIFEST.json ]] || die "archive is missing its database or manifest"

"$HP_PYTHON" - "$stage" <<'PY' || exit 1
import hashlib
import json
import sqlite3
import sys
from pathlib import Path

stage = Path(sys.argv[1])
manifest = json.loads((stage / "MANIFEST.json").read_text())
db = stage / "honeypot.db"

digest = hashlib.sha256()
with db.open("rb") as handle:
    for chunk in iter(lambda: handle.read(1 << 20), b""):
        digest.update(chunk)
if digest.hexdigest() != manifest["db_sha256"]:
    sys.exit("extracted database does not match the manifest digest")

conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
try:
    status = conn.execute("PRAGMA integrity_check").fetchone()[0]
finally:
    conn.close()
if status != "ok":
    sys.exit(f"extracted database failed integrity_check: {status}")

rows = sum(manifest["row_counts"].values())
print(f"snapshot taken {manifest['created_utc']} — {rows} rows, "
      f"{manifest['sample_count']} samples, git {manifest['git_sha'][:8]}")
PY

# --- refuse to silently discard newer data -----------------------------------
if [[ -f $HP_DB && $force -eq 0 ]]; then
    snapshot_epoch=$("$HP_PYTHON" -c \
        'import json,sys; print(json.load(open(sys.argv[1]))["created_epoch"])' \
        "$stage/MANIFEST.json")
    db_epoch=$(stat -c %Y "$HP_DB")
    if (( db_epoch > snapshot_epoch )); then
        die "$HP_DB was modified after this snapshot was taken — rerun with --force to overwrite it"
    fi
fi

# --- swap ---------------------------------------------------------------------
if [[ -n $HP_SERVICE ]]; then
    log "stopping $HP_SERVICE"
    sudo systemctl stop "$HP_SERVICE"
fi

stamp=$(date -u +%Y%m%dT%H%M%SZ)
if [[ -f $HP_DB ]]; then
    mv "$HP_DB" "$HP_DB.pre-restore-$stamp"
    log "previous database kept as $(basename "$HP_DB").pre-restore-$stamp"
fi
# The WAL and shared-memory files belong to the database being displaced;
# leaving them next to a restored database would corrupt it. They are moved
# aside under names that do not collide with the database's own glob.
for suffix in wal shm; do
    [[ -f $HP_DB-$suffix ]] && mv "$HP_DB-$suffix" "$HP_DB-$suffix.pre-restore-$stamp"
done

install -m 0600 "$stage/honeypot.db" "$HP_DB"
log "database restored"

if (( with_env )); then
    if [[ -f $stage/env/backend.env ]]; then
        mkdir -p "$(dirname "$HP_ENV_FILE")"
        install -m 0600 "$stage/env/backend.env" "$HP_ENV_FILE"
        log "restored $HP_ENV_FILE"
    else
        log "WARNING --with-env given but this snapshot contains no .env"
    fi
fi

if (( with_samples )); then
    mkdir -p "$HP_SAMPLES_DIR"
    if compgen -G "$stage/samples/*" >/dev/null; then
        cp -a "$stage"/samples/. "$HP_SAMPLES_DIR"/
        log "restored $(find "$stage/samples" -type f | wc -l) sample(s) to $HP_SAMPLES_DIR"
    else
        log "WARNING --with-samples given but this snapshot contains no samples"
    fi
fi

# --- bring it back up ---------------------------------------------------------
if [[ -n $HP_SERVICE ]]; then
    log "starting $HP_SERVICE"
    sudo systemctl start "$HP_SERVICE"
fi

if [[ -n $HP_HEALTH_URL ]]; then
    for _ in $(seq 1 30); do
        if curl -fsS "$HP_HEALTH_URL" >/dev/null 2>&1; then
            log "health check passed"
            exit 0
        fi
        sleep 2
    done
    die "health check failed after 60s — check: sudo journalctl -u $HP_SERVICE -n 50"
fi

log "done"
