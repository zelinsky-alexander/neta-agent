#!/usr/bin/env bash
set -euo pipefail

# Install or update neta-agent from this repository on Debian/Ubuntu Linux.
# Supports native x86_64/amd64 and arm64/aarch64 builds.
# Run with: sudo ./deploy/linux/install-or-update.sh
#
# NETA_UPDATE_BRANCH can select a side branch for validation. It defaults to main.
# YARA-X is always excluded as a link-time dependency; the Linux provider loads the
# optional prebuilt runtime from /usr/local/lib/neta/yara-x/current at runtime.

if [[ ${EUID} -ne 0 ]]; then
  echo "ERROR: run this script with sudo" >&2
  exit 1
fi

CALLER="${SUDO_USER:-root}"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd -- "$SCRIPT_DIR/../.." && pwd)"
JOBS="${NETA_BUILD_JOBS:-$(nproc)}"
UPDATE_BRANCH="${NETA_UPDATE_BRANCH:-main}"

run_as_caller() {
  if [[ "$CALLER" == "root" ]]; then
    "$@"
  else
    sudo -u "$CALLER" -H "$@"
  fi
}

if [[ ! "$UPDATE_BRANCH" =~ ^[A-Za-z0-9._/-]+$ ]] || [[ "$UPDATE_BRANCH" == -* ]]; then
  echo "ERROR: invalid NETA_UPDATE_BRANCH: $UPDATE_BRANCH" >&2
  exit 1
fi

KERNEL_ARCH="$(uname -m)"
DEB_ARCH="$(dpkg --print-architecture 2>/dev/null || true)"
case "$KERNEL_ARCH" in
  x86_64|amd64)
    NETA_ARCH="x86_64"
    EXPECTED_DEB_ARCH="amd64"
    ;;
  aarch64|arm64)
    NETA_ARCH="arm64"
    EXPECTED_DEB_ARCH="arm64"
    ;;
  *)
    echo "ERROR: unsupported architecture: $KERNEL_ARCH" >&2
    echo "Supported native Linux architectures: x86_64/amd64 and arm64/aarch64" >&2
    exit 1
    ;;
esac

if [[ -n "$DEB_ARCH" && "$DEB_ARCH" != "$EXPECTED_DEB_ARCH" ]]; then
  echo "ERROR: kernel architecture $KERNEL_ARCH does not match Debian architecture $DEB_ARCH" >&2
  exit 1
fi

TEST_BUILD_DIR="${NETA_TEST_BUILD_DIR:-$REPO_DIR/build-install-test-$NETA_ARCH}"
RELEASE_BUILD_DIR="${NETA_BUILD_DIR:-$REPO_DIR/build-release-$NETA_ARCH}"

echo "==> Platform"
echo "    kernel: $(uname -sr)"
echo "    machine: $KERNEL_ARCH"
echo "    package architecture: ${DEB_ARCH:-unknown}"
echo "    NETA native build architecture: $NETA_ARCH"
echo "    update branch: $UPDATE_BRANCH"
if [[ -r /sys/kernel/btf/vmlinux ]]; then
  echo "    kernel BTF: available"
else
  echo "WARNING: /sys/kernel/btf/vmlinux is not readable; eBPF runtime capability may be unavailable" >&2
fi

echo "==> Installing build dependencies"
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y \
  git build-essential cmake clang pkg-config \
  libbpf-dev libsqlite3-dev libssl-dev

echo "==> Updating repository branch $UPDATE_BRANCH"
cd "$REPO_DIR"
if ! run_as_caller git diff --quiet || ! run_as_caller git diff --cached --quiet; then
  echo "ERROR: repository has local changes; commit/stash them before updating" >&2
  exit 1
fi
run_as_caller git fetch origin "$UPDATE_BRANCH"
run_as_caller git checkout "$UPDATE_BRANCH"
run_as_caller git pull --ff-only origin "$UPDATE_BRANCH"

# CMake detects the native CPU architecture. Architecture-specific build directories
# prevent stale CMake caches from another CPU architecture being reused.
#
# NETA_YARA_X=OFF here deliberately disables the old pkg-config/link-time integration.
# The provider itself is runtime-loaded on Linux and does not need the YARA-X headers,
# pkg-config file, Rust, Cargo, or the shared library to build neta-agent.
echo "==> Configuring $NETA_ARCH validation build with eBPF required"
run_as_caller cmake -S "$REPO_DIR" -B "$TEST_BUILD_DIR" \
  -DCMAKE_BUILD_TYPE=Debug \
  -DNETA_EBPF=ON \
  -DNETA_YARA_X=OFF \
  -DNETA_ENABLE_TESTS=ON

echo "==> Building validation targets"
run_as_caller cmake --build "$TEST_BUILD_DIR" -j "$JOBS"

echo "==> Running tests"
run_as_caller ctest --test-dir "$TEST_BUILD_DIR" --output-on-failure

echo "==> Configuring $NETA_ARCH production Release build"
run_as_caller cmake -S "$REPO_DIR" -B "$RELEASE_BUILD_DIR" \
  -DCMAKE_BUILD_TYPE=Release \
  -DNETA_EBPF=ON \
  -DNETA_YARA_X=OFF \
  -DNETA_ENABLE_TESTS=OFF

echo "==> Building production Release binary"
run_as_caller cmake --build "$RELEASE_BUILD_DIR" -j "$JOBS"

echo "==> Verifying installed artifact architecture before install"
BINARY_ARCH="$(file -b "$RELEASE_BUILD_DIR/neta-agent")"
echo "    $BINARY_ARCH"
case "$NETA_ARCH" in
  x86_64)
    grep -q 'x86-64' <<<"$BINARY_ARCH" || { echo "ERROR: built binary is not x86_64" >&2; exit 1; }
    ;;
  arm64)
    grep -Eq 'aarch64|ARM aarch64' <<<"$BINARY_ARCH" || { echo "ERROR: built binary is not arm64/aarch64" >&2; exit 1; }
    ;;
esac

if ldd "$RELEASE_BUILD_DIR/neta-agent" 2>/dev/null | grep -qi 'yara'; then
  echo "ERROR: neta-agent unexpectedly has a link-time YARA dependency" >&2
  ldd "$RELEASE_BUILD_DIR/neta-agent" >&2 || true
  exit 1
fi

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

echo "==> Installed $NETA_ARCH build"
/usr/local/bin/neta-agent capabilities

echo
echo "Service status:"
systemctl status neta-agent.service --no-pager || true

echo
echo "Optional YARA-X runtime:"
echo "  sudo $REPO_DIR/deploy/linux/install-yarax-runtime.sh <version>"
echo
echo "If this machine is not enrolled yet, run:"
echo "  sudo $REPO_DIR/deploy/linux/enroll.sh <coordinator-https-url> <fleet-ca.crt> <display-name> [fleet-id]"
