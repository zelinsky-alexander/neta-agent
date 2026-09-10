#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "ERROR: run this script with sudo" >&2
  exit 1
fi
if [[ $# -ne 1 ]]; then
  echo "Usage: sudo $0 <neta-agent-linux-*.tar.gz>" >&2
  exit 2
fi

PACKAGE="$1"
[[ -r "$PACKAGE" ]] || { echo "ERROR: package is not readable: $PACKAGE" >&2; exit 1; }

INSTALL_ROOT="${NETA_INSTALL_ROOT:-/opt/neta-agent}"
STATE_DIR="${NETA_FLEET_STATE_DIR:-/var/lib/neta/identity}"
WORK="$(mktemp -d -t neta-agent-package-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

tar -xzf "$PACKAGE" -C "$WORK"
for required in neta-agent neta-agent-updater BUILD_INFO.txt; do
  [[ -f "$WORK/$required" ]] || { echo "ERROR: package is missing $required" >&2; exit 1; }
done

case "$(uname -m)" in
  x86_64|amd64) EXPECTED='x86-64' ;;
  aarch64|arm64) EXPECTED='aarch64|ARM aarch64' ;;
  *) echo "ERROR: unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac
file "$WORK/neta-agent" | grep -Eq "$EXPECTED" || { echo "ERROR: package architecture does not match host" >&2; file "$WORK/neta-agent" >&2; exit 1; }

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y ca-certificates openssl libbpf1 libsqlite3-0 curl file

BUILD_ID="$(sed -n 's/^Build ID:[[:space:]]*//p' "$WORK/BUILD_INFO.txt" | head -n1)"
COMMIT="$(sed -n 's/^Commit:[[:space:]]*//p' "$WORK/BUILD_INFO.txt" | head -n1)"
[[ -n "$BUILD_ID" ]] || BUILD_ID="package-$(date -u +%Y%m%dT%H%M%SZ)"
VERSION_DIR="$INSTALL_ROOT/versions/$BUILD_ID"

mkdir -p "$VERSION_DIR" "$INSTALL_ROOT/versions" /usr/local/libexec /usr/local/lib/neta "$STATE_DIR" /etc/neta /var/lib/neta
install -m 0755 "$WORK/neta-agent" "$VERSION_DIR/neta-agent"
install -m 0755 "$WORK/neta-agent-updater" "$VERSION_DIR/neta-agent-updater"
install -m 0644 "$WORK/BUILD_INFO.txt" "$VERSION_DIR/BUILD_INFO.txt"
[[ -f "$WORK/LICENSE" ]] && install -m 0644 "$WORK/LICENSE" "$VERSION_DIR/LICENSE"
[[ -f "$WORK/THIRD_PARTY_NOTICES.md" ]] && install -m 0644 "$WORK/THIRD_PARTY_NOTICES.md" "$VERSION_DIR/THIRD_PARTY_NOTICES.md"
if [[ -f "$WORK/install-yarax-runtime.sh" ]]; then
  install -m 0755 "$WORK/install-yarax-runtime.sh" /usr/local/libexec/neta-install-yarax-runtime
fi
if [[ -f "$WORK/libneta_tls_context.so" ]]; then
  install -m 0755 "$WORK/libneta_tls_context.so" "$VERSION_DIR/libneta_tls_context.so"
  install -m 0755 "$WORK/libneta_tls_context.so" /usr/local/lib/neta/libneta_tls_context.so
fi

ln -sfn "versions/$BUILD_ID" "$INSTALL_ROOT/current.new"
mv -Tf "$INSTALL_ROOT/current.new" "$INSTALL_ROOT/current"
ln -sfn "$INSTALL_ROOT/current/neta-agent" /usr/local/bin/neta-agent
ln -sfn "$INSTALL_ROOT/current/neta-agent-updater" /usr/local/libexec/neta-agent-updater
chmod 0700 "$STATE_DIR"

if [[ ! -f /etc/neta/neta-agent.env ]]; then
  cat >/etc/neta/neta-agent.env <<EOF
NETA_FLEET_STATE_DIR=$STATE_DIR
NETA_FLEET_REPORTING_MODE=SIGNIFICANT_ONLY
NETA_FLEET_MIN_CONFIDENCE=0.80
NETA_FLEET_REPORTING_COOLDOWN_SECONDS=1800
NETA_FLEET_HEARTBEAT_SECONDS=300
NETA_FLEET_HEARTBEAT_JITTER_PERCENT=20
NETA_YARAX_RUNTIME_POLL_SECONDS=60
NETA_TLS_CONTEXT_SOCKET=@neta-agent-tls-service
EOF
  chmod 0600 /etc/neta/neta-agent.env
fi

cat >/etc/systemd/system/neta-agent.service <<EOF
[Unit]
Description=NETA Endpoint Connection Assurance Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=/etc/neta/neta-agent.env
ExecStart=$INSTALL_ROOT/current/neta-agent run --all --db /var/lib/neta/neta.db --max-db-mb 200
Restart=on-failure
RestartSec=5
LimitMEMLOCK=infinity
WorkingDirectory=/var/lib/neta
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable neta-agent.service
systemctl restart neta-agent.service

echo "Installed prebuilt NETA package"
echo "  build_id=$BUILD_ID"
echo "  commit=${COMMIT:-unknown}"
/usr/local/bin/neta-agent capabilities
