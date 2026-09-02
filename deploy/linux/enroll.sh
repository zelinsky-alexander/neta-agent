#!/usr/bin/env bash
set -euo pipefail

# Enroll this Linux endpoint into a NETA fleet.
# Usage:
#   sudo ./deploy/linux/enroll.sh <coordinator-https-url> <fleet-ca.crt> <display-name> [fleet-id]
# The enrollment token is read without echo and is not placed in shell history.

if [[ ${EUID} -ne 0 ]]; then
  echo "ERROR: run this script with sudo" >&2
  exit 1
fi

if [[ $# -lt 3 || $# -gt 4 ]]; then
  echo "Usage: sudo $0 <coordinator-https-url> <fleet-ca.crt> <display-name> [fleet-id]" >&2
  exit 2
fi

COORDINATOR="$1"
FLEET_CA="$2"
DISPLAY_NAME="$3"
FLEET_ID="${4:-fleet-dev}"
STATE_DIR="/var/lib/neta/identity"

if [[ "$COORDINATOR" != https://* ]]; then
  echo "ERROR: coordinator URL must use https://" >&2
  exit 1
fi
if [[ ! -r "$FLEET_CA" ]]; then
  echo "ERROR: Fleet CA is not readable: $FLEET_CA" >&2
  exit 1
fi
if [[ ! -x /usr/local/bin/neta-agent ]]; then
  echo "ERROR: /usr/local/bin/neta-agent is not installed" >&2
  exit 1
fi
if [[ -e "$STATE_DIR/agent.key" ]]; then
  echo "ERROR: this endpoint is already enrolled:" >&2
  /usr/local/bin/neta-agent fleet status --state-dir "$STATE_DIR" >&2 || true
  echo "Refusing to overwrite the existing private identity." >&2
  exit 1
fi

read -r -s -p "Enrollment token: " TOKEN
echo
if [[ -z "$TOKEN" ]]; then
  echo "ERROR: enrollment token cannot be empty" >&2
  exit 1
fi
trap 'unset TOKEN' EXIT

mkdir -p "$STATE_DIR"
chmod 0700 "$STATE_DIR"

/usr/local/bin/neta-agent fleet enroll \
  --coordinator "$COORDINATOR" \
  --fleet-id "$FLEET_ID" \
  --fleet-ca "$FLEET_CA" \
  --token "$TOKEN" \
  --display-name "$DISPLAY_NAME" \
  --state-dir "$STATE_DIR"

chmod 0700 "$STATE_DIR"
chmod 0600 "$STATE_DIR/agent.key" "$STATE_DIR/identity.conf" "$STATE_DIR/sequence"
chmod 0644 "$STATE_DIR/agent.crt" "$STATE_DIR/fleet-ca.crt"

unset TOKEN
trap - EXIT

echo "==> Verifying identity"
/usr/local/bin/neta-agent fleet status --state-dir "$STATE_DIR"

echo "==> Verifying coordinator messaging"
/usr/local/bin/neta-agent fleet hello --state-dir "$STATE_DIR"
/usr/local/bin/neta-agent fleet heartbeat --state-dir "$STATE_DIR"

echo "==> Restarting always-on service"
systemctl restart neta-agent.service
systemctl status neta-agent.service --no-pager || true

echo
echo "Recent service log:"
journalctl -u neta-agent.service -n 30 --no-pager
