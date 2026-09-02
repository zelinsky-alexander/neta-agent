#!/usr/bin/env bash
set -u

# Small read-only health check for an installed neta-agent Linux service.
# Run with: sudo ./deploy/linux/health-check.sh

if [[ ${EUID} -ne 0 ]]; then
  echo "ERROR: run this script with sudo" >&2
  exit 1
fi

SERVICE="neta-agent.service"
BIN="/usr/local/bin/neta-agent"
DB="/var/lib/neta/neta.db"
STATE_DIR="/var/lib/neta/identity"
FAILED=0

echo "NETA Linux health check"
echo "======================="

if [[ -x "$BIN" ]]; then
  echo "[OK]   binary: $BIN"
else
  echo "[FAIL] binary missing: $BIN"
  FAILED=1
fi

if systemctl is-active --quiet "$SERVICE"; then
  PID="$(systemctl show -p MainPID --value "$SERVICE")"
  STARTED="$(systemctl show -p ActiveEnterTimestamp --value "$SERVICE")"
  echo "[OK]   service: active (pid=$PID)"
  echo "       started: $STARTED"
else
  echo "[FAIL] service: not active"
  FAILED=1
fi

if systemctl is-enabled --quiet "$SERVICE" 2>/dev/null; then
  echo "[OK]   service: enabled at boot"
else
  echo "[WARN] service: not enabled"
fi

if [[ -f "$STATE_DIR/identity.conf" ]]; then
  echo "[OK]   fleet identity present"
  if [[ -x "$BIN" ]]; then
    "$BIN" fleet status --state-dir "$STATE_DIR" 2>&1 | sed 's/^/       /'
  fi
else
  echo "[WARN] fleet identity not present"
fi

if [[ -f "$DB" && -x "$BIN" ]]; then
  echo "[OK]   local database: $DB"
  "$BIN" storage status --db "$DB" 2>&1 | sed 's/^/       /'
else
  echo "[WARN] local database not present yet"
fi

echo
echo "Recent fleet/service events (last 15 minutes):"
RECENT="$(journalctl -u "$SERVICE" --since '-15 minutes' --no-pager 2>/dev/null \
  | grep -E 'AgentHello accepted|heartbeat accepted|Fleet live reporting|Fleet service:.*(failed|error)|NETA service TLS context endpoint' \
  | tail -20 || true)"
if [[ -n "$RECENT" ]]; then
  echo "$RECENT"
else
  echo "  <none>"
  echo "[WARN] no recent fleet/service health event found"
fi

echo
if [[ "$FAILED" -eq 0 ]]; then
  echo "NETA HEALTH: OK"
  exit 0
fi

echo "NETA HEALTH: FAILED"
exit 1
