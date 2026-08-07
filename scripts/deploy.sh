#!/usr/bin/env bash
# Production deploy for the Pi. Invoked by .github/workflows/deploy.yml on the
# self-hosted runner after CI passes on main. Deploys the release checkout at
# $RELEASE — never the development tree.
#
# Safe to run repeatedly: the frontend swap is atomic, the backend restarts
# only when backend files changed, and the nginx/systemd cutover away from the
# dev tree happens once, on the first run.
set -euo pipefail

export PATH="/home/jopi/.npm-global/bin:/usr/local/bin:/usr/bin:/bin"

RELEASE=/home/jopi/HoneypotTracker-release
DATA=/home/jopi/honeypot-data
DEV_TREE=/home/jopi/HoneypotTracker
STATE_DIR=/home/jopi/.honeypot-deploy
NGINX_SITE=$(readlink -f /etc/nginx/sites-enabled/honeypot)
UNIT=/etc/systemd/system/honeypot-api.service
HEALTH_URL=http://127.0.0.1:8000/api/health

cd "$RELEASE"
NEW_SHA=$(git rev-parse HEAD)
LAST_SHA=$(cat "$STATE_DIR/last_sha" 2>/dev/null || echo "")
echo "Deploying $NEW_SHA (previous: ${LAST_SHA:-none})"

# --- sanity checks ------------------------------------------------------------
[[ -f backend/.env ]] || { echo "ERROR: $RELEASE/backend/.env missing"; exit 1; }
[[ -L backend/data && -d backend/data ]] || {
  echo "ERROR: $RELEASE/backend/data must be a symlink to $DATA"; exit 1; }

# --- what changed since the last deploy? -------------------------------------
BACKEND_CHANGED=1
if [[ -n "$LAST_SHA" ]] && git cat-file -e "$LAST_SHA" 2>/dev/null; then
  if git diff --quiet "$LAST_SHA" "$NEW_SHA" -- backend; then
    BACKEND_CHANGED=0
  fi
fi

# --- frontend: build, then swap atomically -----------------------------------
cd "$RELEASE/frontend"
npm ci --no-audit --no-fund
rm -rf dist-next
npm run build -- --outDir dist-next --emptyOutDir
rm -rf dist-prev
[[ -d dist ]] && mv dist dist-prev
mv dist-next dist
echo "Frontend built and swapped."

# --- backend: deps + conditional restart -------------------------------------
cd "$RELEASE/backend"
[[ -d venv ]] || python3 -m venv venv
if [[ "$BACKEND_CHANGED" == 1 ]]; then
  venv/bin/pip install -q -r requirements.txt
fi

NEED_RESTART=$BACKEND_CHANGED

# --- one-time cutover: point nginx + systemd at the release checkout ---------
if grep -q "$DEV_TREE/frontend/dist" "$NGINX_SITE"; then
  echo "Cutover: pointing nginx at $RELEASE/frontend/dist"
  sudo sed -i "s|$DEV_TREE/frontend/dist|$RELEASE/frontend/dist|" "$NGINX_SITE"
  sudo nginx -t
  sudo systemctl reload nginx
fi
if grep -q "$DEV_TREE/backend" "$UNIT"; then
  echo "Cutover: pointing honeypot-api.service at $RELEASE/backend"
  sudo sed -i "s|$DEV_TREE/backend|$RELEASE/backend|g" "$UNIT"
  sudo systemctl daemon-reload
  NEED_RESTART=1
fi

# --- restart + health check ---------------------------------------------------
if ! systemctl is-active --quiet honeypot-api; then
  NEED_RESTART=1
fi
if [[ "$NEED_RESTART" == 1 ]]; then
  echo "Restarting honeypot-api..."
  sudo systemctl restart honeypot-api
else
  echo "Backend unchanged — skipping restart."
fi

for i in $(seq 1 30); do
  if curl -fsS "$HEALTH_URL" >/dev/null 2>&1; then
    echo "Health check passed."
    mkdir -p "$STATE_DIR"
    echo "$NEW_SHA" > "$STATE_DIR/last_sha"
    echo "Deployed $NEW_SHA successfully."
    exit 0
  fi
  sleep 2
done

echo "ERROR: health check failed after 60s — check: sudo journalctl -u honeypot-api -n 50"
exit 1
