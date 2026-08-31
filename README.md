# neta-agent

**Endpoint connection assurance agent for per-connection performance, trust, and replayable evidence-based diagnostics.**

`neta-agent` observes real endpoint TCP connections without proxying, redirecting, decrypting, or terminating application traffic. The Linux implementation combines CO-RE eBPF lifecycle evidence with `NETLINK_SOCK_DIAG` / `INET_DIAG_INFO`, application resolver correlation, route evidence, and optional exact OpenSSL application-session TLS instrumentation.

## Core principles

- **Endpoint observer, not interceptor.** Application traffic flows normally; `neta-agent` observes host networking state and optional application-library evidence.
- **Direction is explicit.** Eligible connections are `OUTBOUND`, `INBOUND`, or `UNKNOWN`.
- **Local-first history.** SQLite is endpoint-local and never exposed as a network database.
- **Bounded storage.** Default database budget is 200 MB. Sparse evidence is retained and old normal history is pruned before anomalous history.
- **Evidence fidelity is explicit.** TCP state can be `EXACT`; route and resolver-to-socket correlation are `STRONGLY_CORRELATED`; the independent TLS probe is `SUPPORTING`; instrumented OpenSSL session identity can be `EXACT` when socket correlation is exact.
- **Deterministic verdicts.** Rules, rule hashes, baseline hashes, and evidence-input hashes are persisted/exported for replay.
- **Cross-platform architecture, Linux implementation.** Portable semantic model/storage/verdict code is separated from `src/platform/linux/`.

## Current milestone status

Milestone 3 currently includes:

- **MS3.1** — application resolver context from glibc `getaddrinfo()` with bounded, direction-aware correlation to outbound connections;
- **MS3.2** — opt-in actual OpenSSL 3 application TLS-session evidence via `libneta_tls_context.so`, including inbound presented client certificates;
- **MS3.3** — deterministic direction-aware inbound authenticated-client/mTLS Trust policy.

The current rule set is **`neta-rules/0.2.0`**. Historical `neta-rules/0.1.0` replay remains supported.

### MS3.3 inbound Trust semantics

Only an **EXACT actual application TLS session** may drive inbound client-identity Trust. A presented certificate alone is not accepted as authenticated identity.

```text
no exact inbound TLS evidence                         -> UNVERIFIED
no client certificate                                 -> UNVERIFIED
client certificate presented but not authenticated    -> UNVERIFIED
known OpenSSL client-certificate verification failure -> SUSPICIOUS
authenticated client with no accepted principal       -> UNVERIFIED
accepted subject + matching issuer/SPKI               -> STABLE
accepted subject + changed issuer/SPKI                -> CHANGED
ambiguous exact inbound identity evidence              -> UNVERIFIED
```

Accepted client identity is explicit and scoped per inbound service plus client certificate subject. The accepted cryptographic identity is issuer + SPKI, allowing multiple legitimate clients for one service without treating each different client as an identity change.

## Dependencies

- **SQLite** — embedded endpoint-local longitudinal evidence store.
- **OpenSSL 3.x** — supporting TLS probe, certificate/SPKI hashing, and optional exact application-session instrumentation.
- **libbpf** (optional build dependency) — CO-RE relocation, lifecycle/resolver program attachment, and ring-buffer delivery.

The repository is Apache-2.0 licensed.

## Build

Ubuntu/WSL development build:

```bash
sudo apt install build-essential cmake clang libbpf-dev libsqlite3-dev libssl-dev
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build -j
ctest --test-dir build --output-on-failure
```

`NETA_EBPF=AUTO` is the default. `NETA_EBPF=ON` requires the eBPF build prerequisites; `NETA_EBPF=OFF` deliberately builds the polling/context fallback.

Normal dynamic builds also produce:

```text
build/libneta_tls_context.so
```

for explicit OpenSSL 3 actual-session instrumentation. Static-dependency/full-static builds disable that preload mechanism rather than claiming unsupported exact TLS coverage.

## CLI

```text
neta-agent capabilities
neta-agent observe --target host:port [--duration 30] [--poll-ms interval] [--db neta.db]
neta-agent observe --outbound|--inbound|--all [--local-port port] [--remote-port port] [--process name] [--exclude-process name]
neta-agent run [--outbound|--inbound|--all] [filters] [--db neta.db]
neta-agent history [--limit 50] [--json]
neta-agent history show ID [--json]
neta-agent baseline capture --target host:port [--ca file]
neta-agent baseline show --target host:port
neta-agent baseline accept-client ID [--db neta.db]
neta-agent baseline show-client ID [--db neta.db]
neta-agent evidence ID
neta-agent explain ID
neta-agent export ID > conn.json
neta-agent replay conn.json
neta-agent storage status
neta-agent storage prune
```

## Outbound baseline flow

1. Observe a controlled target and generate representative traffic.
2. Explicitly capture the target baseline:

```bash
./build/neta-agent baseline capture \
  --target netassure-vg.test:443 \
  --ca ./lab-ca.crt \
  --db ./neta.db
```

3. Observe again. Target-mode connections receive deterministic Performance and outbound Trust verdicts using the existing supporting-probe policy.

The original POC performance rule remains:

```text
RTT >= 2 x baseline median          +0.50
RTT variation >= 2 x baseline      +0.20
retransmission delta >= 2           +0.30
score >= 0.50 -> DEGRADED
```

Outbound Trust still uses the independent `SUPPORTING` TLS probe:

```text
valid TLS + matching SPKI           -> STABLE
valid TLS + changed SPKI            -> CHANGED / TLS_IDENTITY_CHANGE
invalid chain or hostname           -> SUSPICIOUS / TLS_VALIDATION_FAILURE
```

## Inbound mTLS identity flow

Run the observer for inbound traffic and instrument the OpenSSL server with the same TLS context endpoint:

```bash
sudo env NETA_TLS_CONTEXT_SOCKET=@neta-ms3-test \
  ./build/neta-agent observe --inbound --local-port 9443 --duration 30 --db ./neta.db
```

Launch the supported dynamically linked OpenSSL server with:

```bash
NETA_TLS_CONTEXT_SOCKET=@neta-ms3-test \
LD_PRELOAD="$PWD/build/libneta_tls_context.so" \
  ./your-mtls-server
```

After an authenticated inbound client connection is captured, inspect it:

```bash
./build/neta-agent evidence CONN_ID --db ./neta.db
./build/neta-agent explain CONN_ID --db ./neta.db
```

Before explicit acceptance, an authenticated but unknown client is `UNVERIFIED`. Accept that exact authenticated client principal with:

```bash
./build/neta-agent baseline accept-client CONN_ID --db ./neta.db
```

The selected connection is re-evaluated immediately. A later connection from the same subject with matching accepted issuer + SPKI is `STABLE`; a changed issuer/SPKI for that accepted subject is `CHANGED`.

## Export and replay

Current exports use schema version **5**. Schema 5 adds the exact inbound Trust-policy inputs needed to replay MS3.3 decisions. Schema versions 1-4 remain supported and replay under their historical rule semantics.

```bash
./build/neta-agent export CONN_ID --db ./neta.db > evidence.json
./build/neta-agent replay evidence.json
```

Replay independently checks name-resolution evidence, application TLS-session evidence, rule-set hash, verdict input hash, and Performance/Trust verdict.

See [`docs/MILESTONE3.md`](docs/MILESTONE3.md) for MS3 architecture, fidelity rules, limitations, and remaining work. [`docs/POC1.md`](docs/POC1.md) remains the original MS0 design contract.
