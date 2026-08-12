#!/usr/bin/env bash
# Install the honeypot sensor agent as a systemd service.
#
# Run on the SENSOR machine (not the hub), as root:
#   sudo ./install.sh --hub https://honeypottracker.live --token <TOKEN> \
#                     --log /home/cowrie/cowrie/var/log/cowrie/cowrie.json
set -euo pipefail

HUB=""
TOKEN=""
COWRIE_LOG="/home/cowrie/cowrie/var/log/cowrie/cowrie.json"
INSTALL_DIR=/opt/honeypot-sensor
STATE_DIR=/var/lib/honeypot-sensor
SERVICE=/etc/systemd/system/honeypot-sensor.service
ENV_FILE=/etc/honeypot-sensor.env
RUN_USER=honeypot-sensor

while [[ $# -gt 0 ]]; do
  case "$1" in
    --hub) HUB="$2"; shift 2 ;;
    --token) TOKEN="$2"; shift 2 ;;
    --log) COWRIE_LOG="$2"; shift 2 ;;
    --user) RUN_USER="$2"; shift 2 ;;
    *) echo "Unknown option: $1"; exit 1 ;;
  esac
done

if [[ -z "$HUB" || -z "$TOKEN" ]]; then
  echo "Usage: sudo $0 --hub <url> --token <token> [--log <path>] [--user <name>]"
  exit 1
fi
if [[ $EUID -ne 0 ]]; then
  echo "Run as root (sudo)."
  exit 1
fi
command -v python3 >/dev/null || { echo "python3 is required"; exit 1; }

if [[ ! -r "$COWRIE_LOG" ]]; then
  echo "WARNING: $COWRIE_LOG is not readable yet — the agent will wait for it."
fi

# Unprivileged service account: the agent only needs to read one log file.
if ! id -u "$RUN_USER" >/dev/null 2>&1; then
  useradd --system --no-create-home --shell /usr/sbin/nologin "$RUN_USER"
  echo "Created service user $RUN_USER"
fi

install -d -m 755 "$INSTALL_DIR"
install -m 755 "$(dirname "$0")/agent.py" "$INSTALL_DIR/agent.py"
install -d -o "$RUN_USER" -g "$RUN_USER" -m 750 "$STATE_DIR"

# The token lives only here, readable by root and the service account.
umask 077
cat > "$ENV_FILE" <<EOF
HUB_URL=$HUB
SENSOR_TOKEN=$TOKEN
COWRIE_LOG_PATH=$COWRIE_LOG
STATE_PATH=$STATE_DIR/state.json
EOF
chown root:"$RUN_USER" "$ENV_FILE"
chmod 640 "$ENV_FILE"

# Let the service account read Cowrie's log without widening anything else.
if [[ -r "$COWRIE_LOG" ]]; then
  LOG_GROUP=$(stat -c '%G' "$COWRIE_LOG")
  if [[ "$LOG_GROUP" != "$RUN_USER" ]]; then
    usermod -aG "$LOG_GROUP" "$RUN_USER" || true
    echo "Added $RUN_USER to group $LOG_GROUP for log access"
  fi
fi

cat > "$SERVICE" <<EOF
[Unit]
Description=Honeypot sensor agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$RUN_USER
EnvironmentFile=$ENV_FILE
ExecStart=/usr/bin/python3 $INSTALL_DIR/agent.py
Restart=always
RestartSec=10
# The agent reads one log and writes one state file; deny everything else.
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=$STATE_DIR
ProtectKernelTunables=true
ProtectControlGroups=true
RestrictSUIDSGID=true
MemoryMax=256M

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now honeypot-sensor.service
sleep 2
systemctl status honeypot-sensor.service --no-pager || true

echo
echo "Installed. Follow it with:  journalctl -u honeypot-sensor -f"
