#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "ERROR: run this script with sudo" >&2
  exit 1
fi

if [[ $# -lt 1 || $# -gt 3 ]]; then
  echo "usage: sudo $0 <yara-x-version> [release-base-url] [expected-archive-sha256]" >&2
  exit 2
fi

VERSION="$1"
BASE_URL="${2:-https://github.com/zelinsky-alexander/neta-agent/releases/download/yarax-runtime-v${VERSION}}"
EXPECTED_SHA="${3:-}"
ROOT="/usr/local/lib/neta/yara-x"

if [[ ! "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+([.-][A-Za-z0-9._-]+)?$ ]]; then
  echo "ERROR: invalid YARA-X version: $VERSION" >&2
  exit 1
fi
if [[ ! "$BASE_URL" =~ ^https://github\.com/zelinsky-alexander/neta-agent/releases/download/yarax-runtime-v${VERSION}$ ]]; then
  echo "ERROR: runtime source is not the matching NETA GitHub release" >&2
  exit 1
fi
if [[ -n "$EXPECTED_SHA" && ! "$EXPECTED_SHA" =~ ^[0-9a-fA-F]{64}$ ]]; then
  echo "ERROR: invalid expected SHA-256" >&2
  exit 1
fi

case "$(uname -m)" in
  x86_64|amd64) ARCH="x86_64"; FILE_ARCH_PATTERN='x86-64|x86_64' ;;
  aarch64|arm64) ARCH="arm64"; FILE_ARCH_PATTERN='aarch64|ARM aarch64' ;;
  *) echo "ERROR: unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac

for tool in curl tar sha256sum file ldd; do
  command -v "$tool" >/dev/null 2>&1 || { echo "ERROR: required tool not found: $tool" >&2; exit 1; }
done

ASSET="neta-yarax-runtime-v${VERSION}-linux-${ARCH}.tar.gz"
CHECKSUM="${ASSET}.sha256"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

curl --fail --location --proto '=https' --tlsv1.2 "$BASE_URL/$ASSET" -o "$TMP/$ASSET"
curl --fail --location --proto '=https' --tlsv1.2 "$BASE_URL/$CHECKSUM" -o "$TMP/$CHECKSUM"
(
  cd "$TMP"
  sha256sum -c "$CHECKSUM"
)
ACTUAL_SHA="$(sha256sum "$TMP/$ASSET" | awk '{print $1}')"
if [[ -n "$EXPECTED_SHA" && "${ACTUAL_SHA,,}" != "${EXPECTED_SHA,,}" ]]; then
  echo "ERROR: coordinator expected SHA-256 $EXPECTED_SHA but downloaded $ACTUAL_SHA" >&2
  exit 1
fi

STAGE="$TMP/stage"
mkdir -p "$STAGE"
tar -xzf "$TMP/$ASSET" -C "$STAGE"
LIB="$STAGE/libyara_x_capi.so"
[[ -f "$LIB" ]] || { echo "ERROR: package lacks libyara_x_capi.so" >&2; exit 1; }
[[ -f "$STAGE/VERSION" ]] && [[ "$(tr -d '[:space:]' < "$STAGE/VERSION")" == "$VERSION" ]] || { echo "ERROR: runtime VERSION mismatch" >&2; exit 1; }
LIB_INFO="$(file -b "$LIB")"
grep -Eq "$FILE_ARCH_PATTERN" <<<"$LIB_INFO" || { echo "ERROR: runtime architecture mismatch: $LIB_INFO" >&2; exit 1; }
ldd -r "$LIB" >/dev/null

mkdir -p "$ROOT"
DEST="$ROOT/$VERSION"
PREVIOUS=""
if [[ -L "$ROOT/current" ]]; then PREVIOUS="$(readlink "$ROOT/current")"; fi
rm -rf "$DEST.new"
mkdir -p "$DEST.new"
install -m 0755 "$LIB" "$DEST.new/libyara_x_capi.so"
install -m 0644 "$STAGE/VERSION" "$DEST.new/VERSION"
[[ -f "$STAGE/LICENSE.YARA-X" ]] && install -m 0644 "$STAGE/LICENSE.YARA-X" "$DEST.new/LICENSE.YARA-X"
[[ -f "$STAGE/MANIFEST" ]] && install -m 0644 "$STAGE/MANIFEST" "$DEST.new/MANIFEST"
printf '%s\n' "$ACTUAL_SHA" > "$DEST.new/ARCHIVE_SHA256"

rm -rf "$DEST.previous"
[[ -e "$DEST" ]] && mv "$DEST" "$DEST.previous"
mv "$DEST.new" "$DEST"
ln -sfn "$VERSION" "$ROOT/current.new"
mv -Tf "$ROOT/current.new" "$ROOT/current"

if ! ldd -r "$ROOT/current/libyara_x_capi.so" >/dev/null 2>&1; then
  echo "ERROR: activated runtime failed load validation; rolling back" >&2
  if [[ -n "$PREVIOUS" && -e "$ROOT/$PREVIOUS" ]]; then
    ln -sfn "$PREVIOUS" "$ROOT/current.rollback"
    mv -Tf "$ROOT/current.rollback" "$ROOT/current"
  else
    rm -f "$ROOT/current"
  fi
  rm -rf "$DEST"
  [[ -d "$DEST.previous" ]] && mv "$DEST.previous" "$DEST"
  exit 1
fi
rm -rf "$DEST.previous"

echo "Activated YARA-X runtime $VERSION ($ACTUAL_SHA)"
if systemctl list-unit-files neta-agent.service >/dev/null 2>&1 && systemctl is-active --quiet neta-agent.service; then
  systemctl restart --no-block neta-agent.service
fi
