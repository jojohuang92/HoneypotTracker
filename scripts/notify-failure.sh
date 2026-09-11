#!/usr/bin/env bash
# Push an alert when a scheduled unit fails. Wired up as
# OnFailure=honeypot-backup-failed.service.
#
#   notify-failure.sh <unit-name>
#
# Reuses the NTFY_URL already configured in backend/.env rather than inventing
# a second alerting path. Exits 0 even when it cannot deliver: a notifier that
# fails loudly would just replace one silent problem with another.
set -uo pipefail

unit=${1:-unknown.service}
HP_ENV_FILE=${HP_ENV_FILE:-/home/jopi/HoneypotTracker-release/backend/.env}

log() { printf 'notify-failure: %s\n' "$*"; }

ntfy_url=""
if [[ -f $HP_ENV_FILE ]]; then
    # Read the one key we need without sourcing the file — .env holds API keys
    # and is not shell-safe to execute.
    ntfy_url=$(grep -E '^NTFY_URL=' "$HP_ENV_FILE" | tail -1 | cut -d= -f2- | tr -d '"'"'"'')
else
    log "no env file at $HP_ENV_FILE — nothing to notify"
    exit 0
fi

if [[ -z $ntfy_url ]]; then
    log "NTFY_URL is not set — nothing to notify"
    exit 0
fi

detail=$(journalctl -u "$unit" -n 15 --no-pager 2>/dev/null | tail -15)
[[ -n $detail ]] || detail="(no journal output available)"

body="$unit failed on $(hostname) at $(date -u +%Y-%m-%dT%H:%M:%SZ)

$detail"

if curl -fsS \
    -H "Title: Honeypot backup failed" \
    -H "Priority: high" \
    -H "Tags: rotating_light,floppy_disk" \
    -d "$body" \
    "$ntfy_url" >/dev/null 2>&1; then
    log "alert delivered for $unit"
else
    log "WARNING could not deliver alert for $unit"
fi

exit 0
