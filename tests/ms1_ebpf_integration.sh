#!/usr/bin/env bash
set -euo pipefail

requested_binary="${1:-./build/neta-agent}"
if [[ "$(basename "$requested_binary")" == "neta-agent" ]]; then
    binary="$(dirname "$requested_binary")/neta_ms1_ebpf_integration"
else
    binary="$requested_binary"
fi
if [[ ! -x "$binary" ]]; then
    echo "integration binary not found: $binary" >&2
    exit 2
fi

set +e
"$binary"
status=$?
set -e
if [[ $status -eq 77 ]]; then
    echo "MS1 eBPF integration explicitly skipped: runtime/build capability unavailable"
    exit 0
fi
exit "$status"
