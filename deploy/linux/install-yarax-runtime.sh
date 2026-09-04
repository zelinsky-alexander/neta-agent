#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "ERROR: run this script with sudo" >&2
  exit 1
fi

if [[ $# -lt 1 || $# -gt 2 ]]; then
  echo "usage: sudo $0 <yara-x-version> [release-base-url]" >&2
  echo "example: sudo $0 1.20.0" >&2
  exit 2
fi

VERSION="$1"
BASE_URL="${2:-https://github.com/zelinsky-alexander/neta-agent/releases/download/yarax-runtime-v${VERSION}}"
ROOT="/usr/local/lib/neta/yara-x"

if [[ ! "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+([.-][A-Za-z0-9._-]+)?$ ]]; then
  echo "ERROR: invalid YARA-X version: $VERSION" >&2
  exit 1
fi

case "$(uname -m)" in
  x86_64|amd64)
    ARCH="x86_64"
    FILE_ARCH_PATTERN='x86-64|x86_64'
    ;;
  aarch64|arm64)
    ARCH="arm64"
    FILE_ARCH_PATTERN='aarch64|ARM aarch64'
    ;;
  *)
    echo "ERROR: unsupported architecture: $(uname -m)" >&2
    exit 1
    ;;
esac

for tool in curl tar sha256sum file; do
  command -v "$tool" >/dev/null 2>&1 || {
    echo "ERROR: required tool not found: $tool" >&2
    exit 1
  }
done

ASSET="neta-yarax-runtime-v${VERSION}-linux-${ARCH}.tar.gz"
CHECKSUM="${ASSET}.sha256"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo "==> Downloading YARA-X runtime $VERSION for $ARCH"
curl --fail --location --proto '=https' --tlsv1.2 \
  "$BASE_URL/$ASSET" -o "$TMP/$ASSET"
curl --fail --location --proto '=https' --tlsv1.2 \
  "$BASE_URL/$CHECKSUM" -o "$TMP/$CHECKSUM"

(
  cd "$TMP"
  sha256sum -c "$CHECKSUM"
)

STAGE="$TMP/stage"
mkdir -p "$STAGE"
tar -xzf "$TMP/$ASSET" -C "$STAGE"

LIB="$STAGE/libyara_x_capi.so"
if [[ ! -f "$LIB" ]]; then
  echo "ERROR: runtime package does not contain libyara_x_capi.so" >&2
  exit 1
fi
if [[ ! -f "$STAGE/VERSION" ]] || [[ "$(tr -d '[:space:]' < "$STAGE/VERSION")" != "$VERSION" ]]; then
  echo "ERROR: runtime VERSION does not match requested version $VERSION" >&2
  exit 1
fi

LIB_INFO="$(file -b "$LIB")"
echo "    $LIB_INFO"
if ! grep -Eq "$FILE_ARCH_PATTERN" <<<"$LIB_INFO"; then
  echo "ERROR: YARA-X runtime architecture does not match $ARCH" >&2
  exit 1
fi

mkdir -p "$ROOT"
DEST="$ROOT/$VERSION"
if [[ -e "$DEST" ]]; then
  echo "==> Runtime $VERSION already exists; replacing only after package validation"
  rm -rf "$DEST.previous"
  mv "$DEST" "$DEST.previous"
fi

mkdir -p "$DEST"
install -m 0755 "$LIB" "$DEST/libyara_x_capi.so"
install -m 0644 "$STAGE/VERSION" "$DEST/VERSION"
[[ -f "$STAGE/LICENSE.YARA-X" ]] && install -m 0644 "$STAGE/LICENSE.YARA-X" "$DEST/LICENSE.YARA-X"
[[ -f "$STAGE/MANIFEST" ]] && install -m 0644 "$STAGE/MANIFEST" "$DEST/MANIFEST"

ln -sfn "$VERSION" "$ROOT/current.new"
mv -Tf "$ROOT/current.new" "$ROOT/current"

if [[ -d "$DEST.previous" ]]; then
  rm -rf "$DEST.previous"
fi

echo "==> Activated YARA-X runtime"
echo "    $ROOT/current -> $VERSION"
echo "    library: $ROOT/current/libyara_x_capi.so"

if systemctl list-unit-files neta-agent.service >/dev/null 2>&1 && \
   systemctl is-active --quiet neta-agent.service; then
  echo "==> Restarting neta-agent.service"
  systemctl restart neta-agent.service
fi

echo "YARA-X runtime $VERSION installed without Rust/Cargo on this endpoint."
