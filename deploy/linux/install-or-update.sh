#!/usr/bin/env bash
set -euo pipefail

# Install or update neta-agent from this repository on Debian/Ubuntu Linux.
# Run with: sudo ./deploy/linux/install-or-update.sh

if [[ ${EUID} -ne 0 ]]; then
  echo "ERROR: run this script with sudo" >&2
  exit 1
fi

CALLER="${SUDO_USER:-root}"
if [[ "$CALLER" == "root" ]]; then
  CALLER_HOME="/root"
else
  CALLER_HOME="$(getent passwd "$CALLER" | cut -d: -f6)"
fi

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd -- "$SCRIPT_DIR/../.." && pwd)"
TEST_BUILD_DIR="${NETA_TEST_BUILD_DIR:-$REPO_DIR/build-install-test}"
RELEASE_BUILD_DIR="${NETA_BUILD_DIR:-$REPO_DIR/build-release}"
JOBS="${NETA_BUILD_JOBS:-$(nproc)}"

run_as_caller() {
  if [[ "$CALLER" == "root" ]]; then
    "$@"
  else
    sudo -u "$CALLER" -H "$@"
  fi
}

echo "==> Installing build dependencies"
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y \
  git build-essential cmake clang pkg-config \
  libbpf-dev libsqlite3-dev libssl-dev

echo "==> Updating repository main branch"
cd "$REPO_DIR"
if ! run_as_caller git diff --quiet || ! run_as_caller git diff --cached --quiet; then
  echo "ERROR: repository has local changes; commit/stash them before updating" >&2
  exit 1
fi
run_as_caller git fetch origin main
run_as_caller git checkout main
run_as_caller git pull --ff-only origin main

# The current test suite uses assertions as test checks. CMake Release defines
# NDEBUG, which disables those checks and makes some legacy tests invalid.
# Validate the source in Debug (same mode used by CI), then build a separate
# production Release binary with tests disabled.
echo "==> Configuring validation build with eBPF required"
run_as_caller cmake -S "$REPO_DIR" -B "$TEST_BUILD_DIR" \
  -DCMAKE_BUILD_TYPE=Debug \
  -DNETA_EBPF=ON \
  -DNETA_ENABLE_TESTS=ON

echo "==> Building validation targets"
run_as_caller cmake --build "$TEST_BUILD_DIR" -j "$JOBS"

echo "==> Running tests"
run_as_caller ctest --test-dir "$TEST_BUILD_DIR" --output-on-failure

echo "==> Configuring production Release build"
run_as_caller cmake -S "$REPO_DIR" -B "$RELEASE_BUILD_DIR" \
  -DCMAKE_BUILD_TYPE=Release \
  -DNETA_EBPF=ON \
  -DNETA_ENABLE_TESTS=OFF

echo "==> Building production Release binary"
run_as_caller cmake --build "$RELEASE_BUILD_DIR" -j "$JOBS"

echo "==> Installing binary and TLS context shim"
install -m 0755 "$RELEASE_BUILD_DIR/neta-agent" /usr/local/bin/neta-agent
mkdir -p /usr/local/lib/neta
if [[ -f "$RELEASE_BUILD_DIR/libneta_tls_context.so" ]]; then
  install -m 0755 "$RELEASE_BUILD_DIR/libneta_tls_context.so" /usr/local/lib/neta/libneta_tls_context.so
fi

mkdir -p /var/lib/neta/identity /etc/neta
chmod 0700 /var/lib/neta/identity

if [[ ! -f /etc/neta/neta-agent.env ]]; then
  cat >/etc/neta/neta-agent.env <<'EOF'
NETA_FLEET_STATE_DIR=/var/lib/neta/identity
NETA_FLEET_REPORTING_MODE=SIGNIFICANT_ONLY
NETA_FLEET_MIN_CONFIDENCE=0.80
NETA_FLEET_REPORTING_COOLDOWN_SECONDS=1800
NETA_FLEET_HEARTBEAT_SECONDS=300
NETA_FLEET_HEARTBEAT_JITTER_PERCENT=20
NETA_TLS_CONTEXT_SOCKET=@neta-agent-tls-service
EOF
  chmod 0600 /etc/neta/neta-agent.env
else
  echo "==> Preserving existing /etc/neta/neta-agent.env"
fi

cat >/etc/systemd/system/neta-agent.service <<'EOF'
[Unit]
Description=NETA Endpoint Connection Assurance Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=/etc/neta/neta-agent.env
ExecStart=/usr/local/bin/neta-agent run --all --db /var/lib/neta/neta.db --max-db-mb 200
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

echo "==> Installed"
/usr/local/bin/neta-agent capabilities

echo
echo "Service status:"
systemctl status neta-agent.service --no-pager || true

echo
echo "If this machine is not enrolled yet, run:"
echo "  sudo $REPO_DIR/deploy/linux/enroll.sh <coordinator-https-url> <fleet-ca.crt> <display-name> [fleet-id]"
