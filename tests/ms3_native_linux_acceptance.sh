#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${1:-$ROOT_DIR/build/neta-agent}"
SHIM="${NETA_MS35_SHIM:-$(dirname "$BIN")/libneta_tls_context.so}"
PORT_OUT="${NETA_MS35_OUTBOUND_PORT:-19443}"
PORT_IN="${NETA_MS35_INBOUND_PORT:-19444}"
KEEP_ARTIFACTS="${NETA_MS35_KEEP_ARTIFACTS:-0}"
PREFLIGHT_ONLY=0
[[ "${2:-}" == "--preflight-only" ]] && PREFLIGHT_ONLY=1

fail() {
    echo "MS3.5 native Linux acceptance FAILED: $*" >&2
    exit 1
}

for command in awk grep openssl sed seq sleep sqlite3 ss uname; do
    command -v "$command" >/dev/null 2>&1 || fail "required command missing: $command"
done
[[ -x "$BIN" ]] || fail "neta-agent executable not found: $BIN"
[[ -f "$SHIM" ]] || fail "OpenSSL application-session shim not found: $SHIM"
[[ "$(uname -s)" == "Linux" ]] || fail "this acceptance requires Linux"
[[ -r /sys/kernel/btf/vmlinux ]] || fail "kernel BTF unavailable at /sys/kernel/btf/vmlinux"
if grep -Eqi '(microsoft|wsl)' /proc/version 2>/dev/null; then
    fail "MS3.5 is a native-Linux acceptance; WSL is intentionally rejected"
fi

CAPABILITIES="$($BIN capabilities)"
echo "$CAPABILITIES"

if (( PREFLIGHT_ONLY )); then
    echo "MS3.5 preflight PASS (no privileged collector attachment attempted)"
    exit 0
fi

if [[ ${EUID} -ne 0 ]]; then
    exec sudo -E bash "$0" "$BIN"
fi

TMP_DIR="$(mktemp -d -t neta-ms35-XXXXXX)"
DB="$TMP_DIR/ms35.db"
ENDPOINT="@neta-ms35-$$"
SERVER_PID=""
OBSERVER_PID=""

cleanup() {
    set +e
    [[ -n "$OBSERVER_PID" ]] && kill "$OBSERVER_PID" >/dev/null 2>&1
    [[ -n "$SERVER_PID" ]] && kill "$SERVER_PID" >/dev/null 2>&1
    [[ -n "$OBSERVER_PID" ]] && wait "$OBSERVER_PID" >/dev/null 2>&1
    [[ -n "$SERVER_PID" ]] && wait "$SERVER_PID" >/dev/null 2>&1
    if [[ "$KEEP_ARTIFACTS" == "1" ]]; then
        echo "MS3.5 artifacts retained at: $TMP_DIR"
    else
        rm -rf "$TMP_DIR"
    fi
}
trap cleanup EXIT

wait_for_port() {
    local port="$1"
    local ca="$2"
    for _ in $(seq 1 60); do
        if openssl s_client -connect "127.0.0.1:$port" -servername localhost -CAfile "$ca" </dev/null >/dev/null 2>&1; then
            return 0
        fi
        sleep 0.1
    done
    return 1
}

wait_for_listen() {
    local port="$1"
    for _ in $(seq 1 60); do
        if ss -ltnH "sport = :$port" 2>/dev/null | grep -q .; then
            return 0
        fi
        sleep 0.1
    done
    return 1
}

latest_exact_tls_connection() {
    local direction="$1"
    local port_column="$2"
    local port="$3"
    local relation="$4"
    sqlite3 "$DB" "SELECT c.id FROM connections c JOIN connection_tls_session_evidence t ON t.connection_id=c.id WHERE c.direction='$direction' AND c.$port_column=$port AND t.relation='$relation' AND t.observation_fidelity='EXACT' AND t.correlation_fidelity='EXACT' ORDER BY c.id DESC LIMIT 1;"
}

assert_contains() {
    local text="$1"
    local expected="$2"
    local label="$3"
    grep -Fq "$expected" <<<"$text" || fail "$label missing expected evidence: $expected"
}

assert_positive_count() {
    local text="$1"
    local prefix="$2"
    local label="$3"
    local count
    count="$(sed -n "s/^${prefix}: \([0-9][0-9]*\)$/\1/p" <<<"$text" | head -n1)"
    [[ -n "$count" && "$count" -gt 0 ]] || fail "$label has no $prefix"
}

assert_replay() {
    local id="$1"
    local label="$2"
    "$BIN" export "$id" --db "$DB" >"$TMP_DIR/$label.json"
    local replay
    replay="$($BIN replay "$TMP_DIR/$label.json")"
    assert_contains "$replay" "Rule set:                   MATCH" "$label replay"
    assert_contains "$replay" "Verdict:                    MATCH" "$label replay"
    assert_contains "$replay" "Host/network environment:    MATCH" "$label replay"
}

openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
    -keyout "$TMP_DIR/ca.key" -out "$TMP_DIR/ca.crt" \
    -subj "/CN=NETA-MS35-Test-CA" >/dev/null 2>&1
cat >"$TMP_DIR/server.ext" <<'EOF'
subjectAltName=DNS:localhost
extendedKeyUsage=serverAuth
keyUsage=digitalSignature,keyEncipherment
EOF
cat >"$TMP_DIR/client.ext" <<'EOF'
extendedKeyUsage=clientAuth
keyUsage=digitalSignature,keyEncipherment
EOF
openssl req -new -newkey rsa:2048 -nodes -keyout "$TMP_DIR/server.key" \
    -out "$TMP_DIR/server.csr" -subj "/CN=localhost" >/dev/null 2>&1
openssl x509 -req -in "$TMP_DIR/server.csr" -CA "$TMP_DIR/ca.crt" -CAkey "$TMP_DIR/ca.key" \
    -set_serial 3501 -days 1 -extfile "$TMP_DIR/server.ext" -out "$TMP_DIR/server.crt" >/dev/null 2>&1
openssl req -new -newkey rsa:2048 -nodes -keyout "$TMP_DIR/client.key" \
    -out "$TMP_DIR/client.csr" -subj "/CN=ms35-client" >/dev/null 2>&1
openssl x509 -req -in "$TMP_DIR/client.csr" -CA "$TMP_DIR/ca.crt" -CAkey "$TMP_DIR/ca.key" \
    -set_serial 3502 -days 1 -extfile "$TMP_DIR/client.ext" -out "$TMP_DIR/client.crt" >/dev/null 2>&1

start_plain_server() {
    openssl s_server -quiet -ign_eof -accept "127.0.0.1:$PORT_OUT" \
        -cert "$TMP_DIR/server.crt" -key "$TMP_DIR/server.key" \
        </dev/null >"$TMP_DIR/outbound-server.log" 2>&1 &
    SERVER_PID=$!
    wait_for_port "$PORT_OUT" "$TMP_DIR/ca.crt" || fail "outbound TLS server did not become ready"
}

stop_server() {
    if [[ -n "$SERVER_PID" ]]; then
        kill "$SERVER_PID" >/dev/null 2>&1 || true
        wait "$SERVER_PID" >/dev/null 2>&1 || true
        SERVER_PID=""
    fi
}

run_outbound_observation() {
    local label="$1"
    env NETA_TLS_CONTEXT_SOCKET="$ENDPOINT" "$BIN" observe \
        --target "localhost:$PORT_OUT" --duration 8 --poll-ms 25 --db "$DB" \
        --ca "$TMP_DIR/ca.crt" >"$TMP_DIR/$label.observe.log" 2>&1 &
    OBSERVER_PID=$!
    sleep 1
    if ! (sleep 4) | env NETA_TLS_CONTEXT_SOCKET="$ENDPOINT" LD_PRELOAD="$SHIM" \
        openssl s_client -quiet -connect "localhost:$PORT_OUT" -servername localhost \
        -CAfile "$TMP_DIR/ca.crt" -verify_return_error -verify_hostname localhost \
        >"$TMP_DIR/$label.client.log" 2>&1; then
        cat "$TMP_DIR/$label.client.log" >&2 || true
        fail "$label outbound client failed"
    fi
    wait "$OBSERVER_PID" || { cat "$TMP_DIR/$label.observe.log" >&2 || true; fail "$label observer failed"; }
    OBSERVER_PID=""
}

# Phase A: native eBPF lifecycle + resolver + exact application TLS + environment.
start_plain_server
run_outbound_observation outbound-baseline
for attempt in 1 2 3; do
    sample_count="$(sqlite3 "$DB" "SELECT COUNT(*) FROM transport_samples;")"
    (( sample_count >= 5 )) && break
    run_outbound_observation "outbound-baseline-$attempt"
done
sample_count="$(sqlite3 "$DB" "SELECT COUNT(*) FROM transport_samples;")"
(( sample_count >= 5 )) || fail "outbound setup produced only $sample_count transport samples"
"$BIN" baseline capture --target "localhost:$PORT_OUT" --db "$DB" --ca "$TMP_DIR/ca.crt" \
    >"$TMP_DIR/baseline.log"
run_outbound_observation outbound-final
OUT_ID="$(latest_exact_tls_connection OUTBOUND remote_port "$PORT_OUT" OUTBOUND_SERVER_IDENTITY)"
[[ -n "$OUT_ID" ]] || fail "no exact outbound OpenSSL assurance connection captured"
OUT_EVIDENCE="$($BIN evidence "$OUT_ID" --db "$DB")"
assert_positive_count "$OUT_EVIDENCE" "Lifecycle observations (eBPF observation, not verdict)" "outbound"
assert_positive_count "$OUT_EVIDENCE" "Name-resolution evidence" "outbound"
assert_positive_count "$OUT_EVIDENCE" "Application TLS session evidence" "outbound"
assert_positive_count "$OUT_EVIDENCE" "TCP samples (EXACT)" "outbound"
assert_contains "$OUT_EVIDENCE" "CONNECT" "outbound lifecycle"
assert_contains "$OUT_EVIDENCE" "provenance=EBPF_CORE" "outbound lifecycle"
assert_contains "$OUT_EVIDENCE" "relation=OUTBOUND_SERVER_IDENTITY" "outbound TLS"
assert_contains "$OUT_EVIDENCE" "observation=EXACT" "outbound TLS"
assert_contains "$OUT_EVIDENCE" "correlation=EXACT" "outbound TLS"
assert_contains "$OUT_EVIDENCE" "Host/network environment" "outbound environment"
assert_contains "$OUT_EVIDENCE" "Fingerprint:" "outbound environment"
assert_replay "$OUT_ID" outbound-final
stop_server

# Phase B: native ACCEPT lifecycle + exact authenticated inbound client identity.
env NETA_TLS_CONTEXT_SOCKET="$ENDPOINT" "$BIN" observe --inbound --local-port "$PORT_IN" \
    --duration 10 --poll-ms 25 --db "$DB" >"$TMP_DIR/inbound.observe.log" 2>&1 &
OBSERVER_PID=$!
sleep 1
env NETA_TLS_CONTEXT_SOCKET="$ENDPOINT" LD_PRELOAD="$SHIM" \
    openssl s_server -quiet -ign_eof -accept "127.0.0.1:$PORT_IN" \
    -cert "$TMP_DIR/server.crt" -key "$TMP_DIR/server.key" \
    -CAfile "$TMP_DIR/ca.crt" -Verify 1 \
    </dev/null >"$TMP_DIR/inbound.server.log" 2>&1 &
SERVER_PID=$!
wait_for_listen "$PORT_IN" || { cat "$TMP_DIR/inbound.server.log" >&2 || true; fail "instrumented mTLS server did not become ready"; }
if ! (sleep 3) | openssl s_client -quiet -connect "127.0.0.1:$PORT_IN" -servername localhost \
    -CAfile "$TMP_DIR/ca.crt" -verify_return_error -verify_hostname localhost \
    -cert "$TMP_DIR/client.crt" -key "$TMP_DIR/client.key" \
    >"$TMP_DIR/inbound.client.log" 2>&1; then
    cat "$TMP_DIR/inbound.client.log" >&2 || true
    fail "authenticated inbound client failed"
fi
wait "$OBSERVER_PID" || { cat "$TMP_DIR/inbound.observe.log" >&2 || true; fail "inbound observer failed"; }
OBSERVER_PID=""
stop_server
IN_ID="$(latest_exact_tls_connection INBOUND local_port "$PORT_IN" INBOUND_CLIENT_IDENTITY)"
[[ -n "$IN_ID" ]] || fail "no exact inbound authenticated-client assurance connection captured"
IN_EVIDENCE="$($BIN evidence "$IN_ID" --db "$DB")"
assert_positive_count "$IN_EVIDENCE" "Lifecycle observations (eBPF observation, not verdict)" "inbound"
assert_positive_count "$IN_EVIDENCE" "Application TLS session evidence" "inbound"
assert_contains "$IN_EVIDENCE" "ACCEPT" "inbound lifecycle"
assert_contains "$IN_EVIDENCE" "provenance=EBPF_CORE" "inbound lifecycle"
assert_contains "$IN_EVIDENCE" "relation=INBOUND_CLIENT_IDENTITY" "inbound TLS"
assert_contains "$IN_EVIDENCE" "observation=EXACT" "inbound TLS"
assert_contains "$IN_EVIDENCE" "correlation=EXACT" "inbound TLS"
assert_contains "$IN_EVIDENCE" "authenticated=yes" "inbound TLS"
assert_contains "$IN_EVIDENCE" "Host/network environment" "inbound environment"

PRE_ACCEPT="$($BIN explain "$IN_ID" --db "$DB")"
assert_contains "$PRE_ACCEPT" "Trust: UNVERIFIED" "pre-accept inbound Trust"
ACCEPT_OUTPUT="$($BIN baseline accept-client "$IN_ID" --db "$DB")"
assert_contains "$ACCEPT_OUTPUT" "Accepted authenticated inbound client identity" "inbound client acceptance"
POST_ACCEPT="$($BIN explain "$IN_ID" --db "$DB")"
assert_contains "$POST_ACCEPT" "Trust: STABLE" "accepted inbound Trust"
assert_replay "$IN_ID" inbound-accepted

$BIN history show "$OUT_ID" --db "$DB" >"$TMP_DIR/outbound-history.txt"
$BIN evidence "$OUT_ID" --db "$DB" >"$TMP_DIR/outbound-evidence.txt"
$BIN explain "$OUT_ID" --db "$DB" >"$TMP_DIR/outbound-explain.txt"
$BIN history show "$IN_ID" --db "$DB" >"$TMP_DIR/inbound-history.txt"
$BIN evidence "$IN_ID" --db "$DB" >"$TMP_DIR/inbound-evidence.txt"
$BIN explain "$IN_ID" --db "$DB" >"$TMP_DIR/inbound-explain.txt"

cat <<EOF
MS3.5 native Linux acceptance PASS
  outbound connection: CONN-$OUT_ID
    eBPF CONNECT lifecycle: PASS
    glibc resolver correlation: PASS
    exact OpenSSL server identity: PASS
    TCP/route/environment context: PASS
    schema-v6 replay: MATCH
  inbound connection: CONN-$IN_ID
    eBPF ACCEPT lifecycle: PASS
    exact authenticated mTLS client identity: PASS
    explicit accepted-client Trust: STABLE
    TCP/route/environment context: PASS
    schema-v6 replay: MATCH
  database: $DB
EOF
