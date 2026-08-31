# MS3.5 native Linux end-to-end acceptance and demo

MS3.5 is the final native-Linux validation milestone for Milestone 3. It adds no new Trust or Performance semantics. Its purpose is to prove that the already implemented collectors, correlation rules, persistence, policy, environment capture, and deterministic replay work together on a real native Linux kernel where privileged eBPF attachment is available.

The executable acceptance harness is:

```bash
tests/ms3_native_linux_acceptance.sh
```

## What PASS means

A successful run proves all of the following in one controlled local test environment:

1. **Native Linux / CO-RE prerequisites**
   - Linux, not WSL;
   - `/sys/kernel/btf/vmlinux` is readable;
   - the build contains `neta-agent` and the dynamic OpenSSL instrumentation shim.

2. **Outbound assurance path**
   - a real outbound TCP connection is admitted;
   - lifecycle evidence contains an eBPF `CONNECT` with `EBPF_CORE` provenance;
   - TCP transport snapshots are persisted;
   - glibc application resolver evidence is correlated to the outbound connection;
   - the actual OpenSSL client session is observed and linked as `OUTBOUND_SERVER_IDENTITY`;
   - both observation and TLS-to-connection correlation are `EXACT` for the application TLS session;
   - route and host/network-environment evidence are persisted;
   - an explicit outbound baseline is captured;
   - schema-v6 export/replay reports matching environment, rule set, and verdict.

3. **Inbound assurance path**
   - a real accepted TCP connection is admitted as `INBOUND`, not as a listener;
   - lifecycle evidence contains an eBPF `ACCEPT` with `EBPF_CORE` provenance;
   - a dynamically linked OpenSSL server requests and authenticates a real client certificate;
   - the actual server-side TLS session is linked as `INBOUND_CLIENT_IDENTITY`;
   - both observation and TLS-to-connection correlation are `EXACT`;
   - the client certificate is reported authenticated;
   - before explicit acceptance, the unknown authenticated client remains `UNVERIFIED`;
   - `baseline accept-client` accepts the captured principal;
   - the same captured connection re-evaluates to `STABLE` under the current inbound policy;
   - route and host/network-environment evidence are persisted;
   - schema-v6 export/replay reports matching environment, rule set, and verdict.

The harness deliberately checks evidence provenance and fidelity rather than merely checking that commands exit successfully.

## Build

For the final native validation, explicitly require eBPF support instead of relying on `AUTO` fallback:

```bash
sudo apt install build-essential cmake clang libbpf-dev libsqlite3-dev sqlite3 libssl-dev iproute2 openssl
cmake -S . -B build-ms35 -DCMAKE_BUILD_TYPE=Debug -DNETA_EBPF=ON
cmake --build build-ms35 -j
ctest --test-dir build-ms35 --output-on-failure
```

`NETA_EBPF=ON` is intentional here. If the native host cannot build the eBPF backend, MS3.5 has not been validated on that host.

## Run the final acceptance

```bash
sudo -E bash tests/ms3_native_linux_acceptance.sh ./build-ms35/neta-agent
```

The script creates a private one-day CA plus server/client certificates under a temporary directory, uses only loopback traffic, and cleans the directory on success or failure.

To keep the database, exported bundles, command output, and TLS logs for a demo or bug report:

```bash
sudo -E env NETA_MS35_KEEP_ARTIFACTS=1 \
  bash tests/ms3_native_linux_acceptance.sh ./build-ms35/neta-agent
```

The final output is deliberately compact:

```text
MS3.5 native Linux acceptance PASS
  outbound connection: CONN-...
    eBPF CONNECT lifecycle: PASS
    glibc resolver correlation: PASS
    exact OpenSSL server identity: PASS
    TCP/route/environment context: PASS
    schema-v6 replay: MATCH
  inbound connection: CONN-...
    eBPF ACCEPT lifecycle: PASS
    exact authenticated mTLS client identity: PASS
    explicit accepted-client Trust: STABLE
    TCP/route/environment context: PASS
    schema-v6 replay: MATCH
```

When artifacts are retained, the temporary directory also contains:

```text
ms35.db
outbound-final.json
inbound-accepted.json
outbound-history.txt
outbound-evidence.txt
outbound-explain.txt
inbound-history.txt
inbound-evidence.txt
inbound-explain.txt
*.observe.log
*.client.log
*.server.log
```

These files form the recommended MS3 final demo record.

## Demo walkthrough

After a retained run, use the printed temporary directory:

```bash
DB=/tmp/neta-ms35-XXXXXX/ms35.db
./build-ms35/neta-agent history --db "$DB"
```

Then inspect the two connection IDs printed by the harness:

```bash
./build-ms35/neta-agent evidence OUTBOUND_ID --db "$DB"
./build-ms35/neta-agent explain OUTBOUND_ID --db "$DB"

./build-ms35/neta-agent evidence INBOUND_ID --db "$DB"
./build-ms35/neta-agent explain INBOUND_ID --db "$DB"
```

Finally replay the retained bundles:

```bash
./build-ms35/neta-agent replay /tmp/neta-ms35-XXXXXX/outbound-final.json
./build-ms35/neta-agent replay /tmp/neta-ms35-XXXXXX/inbound-accepted.json
```

The evidence output is the primary demonstration: it shows connection direction, eBPF lifecycle provenance, process/socket identity, resolver context, exact actual-session TLS evidence, TCP snapshots, route context, host/network environment, and supporting evidence without collapsing their different fidelities.

## Preflight mode

CI and developers may validate the harness prerequisites and command surface without attempting privileged BPF attachment:

```bash
bash tests/ms3_native_linux_acceptance.sh ./build/neta-agent --preflight-only
```

Preflight is **not** MS3.5 acceptance. Only a full privileged run that reaches `MS3.5 native Linux acceptance PASS` constitutes native end-to-end validation.

## Failure interpretation

The harness fails instead of weakening assertions. Important examples:

- WSL -> wrong environment for MS3.5; use a native Linux host.
- missing `/sys/kernel/btf/vmlinux` -> required native BTF environment is unavailable.
- no `EBPF_CORE` CONNECT/ACCEPT -> lifecycle collector was not validated.
- no resolver evidence -> MS3.1 native correlation was not validated.
- no exact application TLS evidence -> MS3.2 actual-session path was not validated.
- inbound client not authenticated -> MS3.3 mTLS policy input was not validated.
- missing environment fingerprint -> MS3.4 integration was not validated.
- replay mismatch -> captured evidence/policy cannot be considered deterministically replayable.

A failed sub-check must be investigated; it is not converted into a weaker PASS.

## Scope boundary

MS3.5 validates the currently supported native Linux path. It does not add or claim coverage for unsupported TLS libraries, QUIC/DTLS, Windows/macOS collectors, HTTP/RPC/span correlation, remote fleet identity, or cloud/network enrichment. Those remain separate future work.
