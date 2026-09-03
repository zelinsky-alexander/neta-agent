#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${1:-$ROOT_DIR/build/neta-agent}"
PORT="${NETA_MS0_PORT:-18443}"
TARGET="localhost:$PORT"

if [[ ! -x "$BIN" ]]; then
    echo "MS0 acceptance: executable not found: $BIN" >&2
    exit 2
fi

for command in openssl tc sed grep awk seq sleep sqlite3; do
    if ! command -v "$command" >/dev/null 2>&1; then
        echo "MS0 acceptance: required command missing: $command" >&2
        exit 2
    fi
done

if [[ ${EUID} -ne 0 ]]; then
    exec sudo -E bash "$0" "$@"
fi

TMP_DIR="$(mktemp -d -t neta-ms0-XXXXXX)"
DB="$TMP_DIR/ms0-acceptance.db"
CA_CERT="$TMP_DIR/ca.crt"
CA_KEY="$TMP_DIR/ca.key"
SERVER_PID=""

cleanup() {
    set +e
    tc qdisc del dev lo root >/dev/null 2>&1
    if [[ -n "$SERVER_PID" ]]; then
        kill "$SERVER_PID" >/dev/null 2>&1
        wait "$SERVER_PID" >/dev/null 2>&1
    fi
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT

fail() {
    echo "MS0 acceptance FAILED: $*" >&2
    exit 1
}

openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
    -keyout "$CA_KEY" -out "$CA_CERT" \
    -subj "/CN=neta-ms0-test-ca" >/dev/null 2>&1

cat > "$TMP_DIR/server.ext" <<'EOF'
subjectAltName=DNS:localhost
extendedKeyUsage=serverAuth
keyUsage=digitalSignature,keyEncipherment
EOF

make_server_cert() {
    local name="$1"
    local serial="$2"
    openssl req -new -newkey rsa:2048 -nodes \
        -keyout "$TMP_DIR/$name.key" \
        -out "$TMP_DIR/$name.csr" \
        -subj "/CN=localhost" >/dev/null 2>&1
    openssl x509 -req \
        -in "$TMP_DIR/$name.csr" \
        -CA "$CA_CERT" \
        -CAkey "$CA_KEY" \
        -set_serial "$serial" \
        -days 1 \
        -extfile "$TMP_DIR/server.ext" \
        -out "$TMP_DIR/$name.crt" >/dev/null 2>&1
}

make_server_cert cert-a 1001
make_server_cert cert-b 1002

spki_a="$(openssl x509 -in "$TMP_DIR/cert-a.crt" -pubkey -noout \
    | openssl pkey -pubin -outform DER 2>/dev/null \
    | openssl dgst -sha256 | awk '{print $2}')"
spki_b="$(openssl x509 -in "$TMP_DIR/cert-b.crt" -pubkey -noout \
    | openssl pkey -pubin -outform DER 2>/dev/null \
    | openssl dgst -sha256 | awk '{print $2}')"
[[ -n "$spki_a" && -n "$spki_b" && "$spki_a" != "$spki_b" ]] \
    || fail "cert A and cert B must have different SPKI hashes"

start_server() {
    local name="$1"
    if [[ -n "$SERVER_PID" ]]; then
        kill "$SERVER_PID" >/dev/null 2>&1 || true
        wait "$SERVER_PID" >/dev/null 2>&1 || true
        SERVER_PID=""
    fi

    openssl s_server -quiet -ign_eof \
        -accept "127.0.0.1:$PORT" \
        -cert "$TMP_DIR/$name.crt" \
        -key "$TMP_DIR/$name.key" \
        </dev/null >"$TMP_DIR/$name.server.log" 2>&1 &
    SERVER_PID=$!

    local ready=0
    for _ in $(seq 1 50); do
        if openssl s_client -connect "127.0.0.1:$PORT" \
            -servername localhost -CAfile "$CA_CERT" \
            </dev/null >/dev/null 2>&1; then
            ready=1
            break
        fi
        sleep 0.1
    done
    if [[ $ready -ne 1 ]]; then
        cat "$TMP_DIR/$name.server.log" >&2 || true
        fail "TLS server $name did not become ready"
    fi
}

run_observation() {
    local label="$1"
    local duration="${2:-6}"
    local hold="${3:-4}"

    "$BIN" observe \
        --target "$TARGET" \
        --duration "$duration" \
        --poll-ms 50 \
        --db "$DB" \
        --ca "$CA_CERT" \
        >"$TMP_DIR/$label.observe.log" 2>&1 &
    local observer_pid=$!

    # Keep a validated TLS socket active while the polling observer samples it.
    # Handshake-only loopback traffic can leave tcpi_rtt at zero on some hosted
    # kernels, so send small application records throughout the hold interval to
    # force DATA/ACK exchanges and deterministic tcp_info RTT evidence.
    sleep 1
    local bursts=$((hold * 5))
    if ! { for _ in $(seq 1 "$bursts"); do printf 'neta-ms0-ping\n'; sleep 0.2; done; } | openssl s_client -quiet \
        -connect "127.0.0.1:$PORT" \
        -servername localhost \
        -CAfile "$CA_CERT" \
        -verify_return_error \
        -verify_hostname localhost \
        >"$TMP_DIR/$label.client.log" 2>&1; then
        cat "$TMP_DIR/$label.client.log" >&2 || true
        cat "$TMP_DIR/$label.observe.log" >&2 || true
        fail "active TLS client failed in $label"
    fi

    if ! wait "$observer_pid"; then
        cat "$TMP_DIR/$label.observe.log" >&2 || true
        fail "neta-agent observe failed in $label"
    fi
}

latest_id() {
    "$BIN" history --limit 1 --db "$DB" --json \
        | sed -n 's/.*"id":\([0-9][0-9]*\).*/\1/p'
}

sample_count() {
    "$BIN" storage status --db "$DB" \
        | sed -n 's/^Transport samples: \([0-9][0-9]*\)$/\1/p'
}

rtt_sample_count() {
    sqlite3 "$DB" "SELECT COUNT(*) FROM transport_samples s JOIN connections c ON c.id=s.connection_id WHERE c.target_host='localhost' AND c.remote_port=$PORT AND s.rtt_us>0;"
}

dump_transport_samples() {
    echo "MS0 transport sample diagnostics:" >&2
    sqlite3 -header -column "$DB" "SELECT c.id AS conn_id,c.lifecycle_state,s.tcp_state,s.rtt_us,s.rttvar_us,s.total_retrans,s.snd_cwnd,s.observed_ns FROM transport_samples s JOIN connections c ON c.id=s.connection_id WHERE c.target_host='localhost' AND c.remote_port=$PORT ORDER BY s.observed_ns;" >&2 || true
}

assert_replay_matches() {
    local id="$1"
    local label="$2"
    "$BIN" export "$id" --db "$DB" > "$TMP_DIR/$label.json"
    local replay
    replay="$("$BIN" replay "$TMP_DIR/$label.json")"
    grep -Fq "Evidence input hash:        MATCH" <<<"$replay" \
        || fail "$label replay evidence hash mismatch"
    grep -Fq "Rule set:                   MATCH" <<<"$replay" \
        || fail "$label replay rule-set mismatch"
    grep -Fq "Verdict:                    MATCH" <<<"$replay" \
        || fail "$label replay verdict mismatch"
}

# Stable controlled baseline conditions. A fixed delay avoids loopback's tiny
# RTT making harmless scheduler jitter look like a 2x performance change.
tc qdisc replace dev lo root netem delay 20ms

start_server cert-a
baseline_attempt=1
while :; do
    run_observation "baseline-a-$baseline_attempt"
    samples="$(sample_count)"
    rtt_samples="$(rtt_sample_count)"
    [[ -n "$samples" && -n "$rtt_samples" ]] || fail "could not read persisted sample counts"
    if (( samples >= 5 && rtt_samples >= 1 )); then
        break
    fi
    # Keep the 5-sample baseline requirement and additionally require real RTT
    # evidence before invoking baseline capture. Repeating the controlled active
    # flow is preferable to accepting a zero-RTT baseline.
    if (( baseline_attempt >= 5 )); then
        dump_transport_samples
        cat "$TMP_DIR/baseline-a-$baseline_attempt.observe.log" >&2 || true
        fail "baseline setup persisted $samples samples but only $rtt_samples RTT-bearing samples after $baseline_attempt observations"
    fi
    baseline_attempt=$((baseline_attempt + 1))
done

baseline_id="$(latest_id)"
[[ -n "$baseline_id" ]] || fail "baseline observation produced no connection"

# The current supporting TLS probe must already be visible before a baseline or
# verdict exists.
prebaseline_evidence="$("$BIN" evidence "$baseline_id" --db "$DB")"
grep -Fq "TLS active probe (SUPPORTING)" <<<"$prebaseline_evidence" \
    || fail "pre-baseline connection is missing supporting TLS evidence"

baseline_output="$("$BIN" baseline capture --target "$TARGET" --db "$DB" --ca "$CA_CERT")"
[[ "$baseline_output" == *"Captured baseline"* ]] || fail "baseline capture failed"

# Certificate B: same hostname and CA, different key/SPKI. Transport conditions
# remain the same, so the required result is NORMAL / CHANGED.
start_server cert-b
run_observation cert-b-normal
changed_id="$(latest_id)"
[[ -n "$changed_id" ]] || fail "certificate-change observation produced no connection"
changed_explain="$("$BIN" explain "$changed_id" --db "$DB")"
grep -Fq "Performance: NORMAL" <<<"$changed_explain" \
    || fail "certificate-change case was not NORMAL"
grep -Fq "Trust: CHANGED" <<<"$changed_explain" \
    || fail "certificate-change case was not CHANGED"
grep -Fq "TLS_IDENTITY_CHANGE" <<<"$changed_explain" \
    || fail "certificate-change hypothesis missing"
assert_replay_matches "$changed_id" cert-b-normal

# Keep certificate B and materially degrade the same loopback path. The verdict
# dimensions must remain independent: DEGRADED / CHANGED, with no causal claim.
tc qdisc replace dev lo root netem delay 120ms 10ms loss 1%
run_observation cert-b-degraded
combined_id="$(latest_id)"
[[ -n "$combined_id" ]] || fail "combined observation produced no connection"
combined_explain="$("$BIN" explain "$combined_id" --db "$DB")"
grep -Fq "Performance: DEGRADED" <<<"$combined_explain" \
    || fail "combined case was not DEGRADED"
grep -Fq "Trust: CHANGED" <<<"$combined_explain" \
    || fail "combined case was not CHANGED"
grep -Fq "performance/trust causal relation NOT ESTABLISHED" <<<"$combined_explain" \
    || fail "combined case made or omitted the required causality statement"
assert_replay_matches "$combined_id" cert-b-degraded

echo "MS0 acceptance PASS"
echo "  cert A SPKI: $spki_a"
echo "  cert B SPKI: $spki_b"
echo "  baseline samples: $(sample_count)"
echo "  RTT-bearing samples: $(rtt_sample_count)"
echo "  NORMAL / CHANGED: CONN-$changed_id"
echo "  DEGRADED / CHANGED: CONN-$combined_id"
echo "  replay: MATCH / MATCH / MATCH for both cases"
