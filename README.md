# neta-agent

**Endpoint connection assurance agent for per-connection performance, trust, and replayable evidence-based diagnostics.**

`neta-agent` observes real endpoint TCP connections without proxying or redirecting application traffic. POC1 is an on-demand Linux implementation: it identifies sockets and processes, reads exact TCP transport state through `NETLINK_SOCK_DIAG` / `INET_DIAG_INFO`, records sparse bounded evidence in a local SQLite history, performs a separate supporting TLS identity probe, compares observations with an explicitly accepted baseline, and produces deterministic Performance + Trust verdicts that can be exported and replayed.

## POC1 principles

- **Endpoint observer, not interceptor.** Application traffic flows normally; `neta-agent` queries kernel diagnostics.
- **On-demand first.** `observe` runs for a bounded duration and exits. No daemon/service is required.
- **Local-first history.** SQLite is endpoint-local and never exposed as a network database.
- **Bounded storage.** Default database budget is 200 MB. Evidence is sparse and old normal history is pruned before anomalous history.
- **Evidence fidelity is explicit.** TCP socket state is `EXACT`; local route is `STRONGLY_CORRELATED`; the independent TLS probe is `SUPPORTING` and is never claimed to be the certificate used by the application socket.
- **Deterministic verdicts.** POC1 rule set is `neta-rules/0.1.0`; rules and input hashes are persisted/exported.
- **Cross-platform architecture, Linux implementation.** Platform-neutral model/storage/verdict interfaces are separated from `src/platform/linux/`.
- **Single-binary deployment target.** SQLite and TLS libraries can be statically linked. `NETA_FULL_STATIC=ON` is intended for a musl release toolchain.

POC1 intentionally excludes eBPF, packet capture, HTTP inspection, DNS interception, QUIC, STAMP, BGP/RPKI feeds, RIPE Atlas, a remote agent, web UI, AI, cloud/fleet collection, Windows/macOS backends, Wi-Fi analysis, and generic ping/speed-test functionality.

## Dependencies

Only two substantial runtime libraries are used:

- **SQLite** — Public Domain. Used as the embedded endpoint-local longitudinal evidence store. Mature and actively maintained. The C API is wrapped behind `HistoryStore`; other code does not call SQLite directly.
- **OpenSSL 3.x** — Apache-2.0. Used for TLS handshake, certificate/hostname validation, SPKI/certificate SHA-256, and evidence hashing. Security-sensitive; production builds should track supported OpenSSL releases.

The repository itself is Apache-2.0 licensed. Perform normal dependency/license/security review before public production distribution, especially for statically linked release artifacts.

## Build

Ubuntu/WSL development build:

```bash
sudo apt install build-essential cmake libsqlite3-dev libssl-dev
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build -j
ctest --test-dir build --output-on-failure
```

Strict C++20 is required (`CMAKE_CXX_EXTENSIONS=OFF`).

For a release toolchain where static archives are available:

```bash
cmake -S . -B build-static \
  -DCMAKE_BUILD_TYPE=Release \
  -DNETA_STATIC_DEPS=ON \
  -DNETA_FULL_STATIC=ON
cmake --build build-static -j
```

A fully static Linux release should preferably be produced with a musl-based toolchain rather than forcing a fully static glibc build.

## First run

Check evidence capabilities:

```bash
./build/neta-agent capabilities
```

Observe a controlled target for 30 seconds while you create real traffic from another terminal:

```bash
sudo ./build/neta-agent observe \
  --target example.com:443 \
  --duration 30 \
  --db ./neta.db
```

For the controlled AWS lab, pass its hostname and lab CA:

```bash
sudo ./build/neta-agent observe \
  --target netassure-vg.test:443 \
  --ca ./lab-ca.crt \
  --duration 30 \
  --db ./neta.db
```

Generate a sufficiently long-lived connection from another terminal (large transfer/persistent request). POC1 polling may miss very short-lived sockets; lifecycle eBPF is deliberately deferred.

## CLI

```text
neta-agent capabilities
neta-agent observe --target host:port [--duration 30] [--poll-ms 100] [--db neta.db]
neta-agent history [--limit 50] [--json]
neta-agent history show ID [--json]
neta-agent baseline capture --target host:port [--ca file]
neta-agent baseline show --target host:port
neta-agent evidence ID
neta-agent explain ID
neta-agent export ID > conn.json
neta-agent replay conn.json
neta-agent storage status
neta-agent storage prune
```

### Baseline flow

1. Run `observe` against the target and generate representative real traffic. Twenty or more persisted samples are recommended.
2. Explicitly accept the baseline:

```bash
./build/neta-agent baseline capture --target netassure-vg.test:443 --ca ./lab-ca.crt --db ./neta.db
```

3. Run `observe` again. Connections collected after a baseline exists receive deterministic Performance and Trust verdicts.

POC1 performance rule:

```text
RTT >= 2 x baseline median          +0.50
RTT variation >= 2 x baseline      +0.20
retransmission delta >= 2           +0.30
score >= 0.50 -> DEGRADED
```

Trust rules:

```text
valid TLS + matching SPKI           -> STABLE
valid TLS + changed SPKI            -> CHANGED / TLS_IDENTITY_CHANGE
invalid chain or hostname           -> SUSPICIOUS / TLS_VALIDATION_FAILURE
```

The TLS result is supporting evidence from an independent connection; it is not asserted to be the exact TLS session used by the application.

## POC1 acceptance target

The controlled lab should demonstrate:

```text
baseline              Performance NORMAL     Trust STABLE
tc netem impairment   Performance DEGRADED   Trust STABLE
certificate A -> B     Performance NORMAL     Trust CHANGED
both                   Performance DEGRADED   Trust CHANGED
```

For combined anomalies, POC1 reports that a causal relation between performance and trust changes is **NOT ESTABLISHED**.

Finally:

```bash
./build/neta-agent export ID --db ./neta.db > evidence.json
./build/neta-agent replay evidence.json
```

must report matching rule set, evidence-input hash, and verdict.

See [docs/POC1.md](docs/POC1.md) for the exact scope and design constraints.
