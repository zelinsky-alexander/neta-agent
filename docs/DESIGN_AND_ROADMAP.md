# neta-agent — Current Design and Roadmap

_Last updated: 2026-08-28_

This document summarizes the current `neta-agent` architecture after Milestone 1 and the planned evolution from a targeted Linux proof-of-concept into a cross-platform endpoint connection assurance agent.

The normative POC1 constraints remain in [`POC1.md`](POC1.md). This document is a broader design/status/roadmap view.

## 1. Product definition

`neta-agent` is an **endpoint connection assurance agent for per-connection performance, trust, and replayable evidence-based diagnostics**.

The core product idea is:

```text
observe a real endpoint connection
        |
        v
collect provenance-rich evidence
        |
        v
compare against accepted local history / baseline
        |
        v
produce deterministic Performance + Trust verdicts
        |
        v
retain bounded evidence that can be inspected, exported, and replayed
```

The project is intentionally **endpoint-centered**. It is not a router, gateway, proxy, packet-forwarder, VPN, generic ping/traceroute utility, or traffic decryption system.

The long-term product scope includes eligible connections in **both directions**:

```text
OUTBOUND: local process  -> remote peer
INBOUND:  remote peer    -> local service/process
```

POC1 is currently outbound-target-scoped for controlled validation; outbound-only observation is not a product-level restriction.

## 2. Architectural invariants

The following rules are intended to remain true as the project grows.

### 2.1 Observer, not interceptor

Application traffic does not pass through `neta-agent`:

```text
application ------------------------------> network
    |
    | kernel owns the real socket
    v
OS networking stack
    ^
    | native observation APIs
    |
neta-agent
```

`neta-agent` observes the host's own networking state. It does not redirect, proxy, decrypt, or modify application traffic.

### 2.2 Evidence and verdicts are separate

The architecture has two first-class concepts:

1. **Connection Evidence** — facts that were observed, with source, fidelity, time, and provenance.
2. **Assurance Verdict** — deterministic interpretation of those facts under a versioned rule set.

Collectors should produce observations, not conclusions.

```text
collectors -> evidence -> deterministic rule engine -> verdict
```

If explanatory AI is ever added, it belongs after the deterministic verdict:

```text
evidence -> deterministic verdict -> optional explanation
```

AI must not become the authoritative security/performance decision engine.

### 2.3 Performance and Trust are independent dimensions

A connection can independently be:

```text
Performance: NORMAL | DEGRADED | FAILED | INSUFFICIENT_EVIDENCE
Trust:       STABLE | CHANGED | SUSPICIOUS | UNVERIFIED
```

For example, a slow connection does not automatically imply a trust problem, and a changed TLS identity does not automatically imply a performance problem.

### 2.4 Fidelity must be explicit

Current evidence classes use semantic fidelity rather than pretending all observations have the same certainty:

```text
EXACT
STRONGLY_CORRELATED
SUPPORTING
CONTEXTUAL
```

POC1 examples:

- kernel TCP state / `tcp_info` from the observed socket: **EXACT**
- process attribution via socket inode and `/proc/<pid>/fd`: **EXACT** for the matched socket at observation time
- route lookup near the connection observation: **STRONGLY_CORRELATED**
- independent TLS probe: **SUPPORTING**

The active TLS probe must never be described as the certificate actually used by the application connection.

### 2.5 Local-first and bounded storage

SQLite is an **endpoint-local longitudinal evidence store**, not a telemetry warehouse and not a network-facing database.

The storage invariant is:

> Persist sparse, deduplicated evidence and compact history rather than every poll.

Current default DB budget:

```text
200 MB
```

Normal transport samples are persisted on meaningful change or approximately once per second when unchanged. Old normal history is pruned before anomalous history. WAL is checkpointed on clean observation finalization/pruning.

### 2.6 Cross-platform semantic core

Linux is the first implementation, not the product architecture.

Portable code works with semantic types such as:

```text
SocketObservation
ProcessIdentity
TcpSnapshot
RouteObservation
TlsObservation
Baseline
AssuranceVerdict
```

Platform-specific mechanisms stay behind platform interfaces.

```text
portable model / storage / rules / CLI
               |
       platform abstraction
       /        |        \
   Linux      Windows    macOS
```

Linux UAPI details are confined to `src/platform/linux/`.

Connection direction is also a portable semantic property. Once bidirectional observation is introduced, the core model should represent it explicitly rather than inferring direction from conventional port numbers:

```text
ConnectionDirection = OUTBOUND | INBOUND | UNKNOWN
```

## 3. Connection identity model

The connection/socket is the primary runtime unit.

```text
HOST
 `-- PROCESS
      `-- CONNECTION / SOCKET
           |-- direction
           |-- transport observations
           |-- route observation
           |-- DNS identity        [future/exact where available]
           |-- TLS identity        [currently supporting probe]
           `-- application ops     [future/optional]
```

A five-tuple alone is not treated as a durable connection identity because tuples can be reused.

POC1 combines the strongest available identifiers, including:

- socket cookie
- socket inode
- protocol
- local address/port
- remote address/port
- process identity when resolved
- observation time
- network namespace / host context where available

Future all-connection observation must also record connection direction explicitly.

## 4. Current POC1 implementation

POC1 is an **on-demand Linux/WSL observer**. It is not an always-on daemon.

Typical invocation:

```bash
sudo ./build/neta-agent observe \
  --target speed.cloudflare.com:443 \
  --duration 90 \
  --poll-ms 50 \
  --db ./db/neta.db
```

### 4.1 Linux connection discovery and TCP state

Implemented with native kernel APIs:

```text
NETLINK_SOCK_DIAG
SOCK_DIAG_BY_FAMILY
INET_DIAG_INFO
struct tcp_info
```

POC1 captures fields including:

- TCP state
- RTT
- RTT variance
- retransmissions
- lost packets
- unacked packets
- congestion window (`cwnd`)
- slow-start threshold
- MSS values
- send/receive queue sizes

No parsing of `ss` or similar shell tools is used by the agent.

### 4.2 Process attribution

Linux process attribution is reconstructed using:

```text
SOCK_DIAG socket inode
       |
       v
/proc/<pid>/fd/* -> socket:[inode]
       |
       v
PID / UID / process start / comm / executable
```

This has been validated on WSL with a long-lived `curl` connection.

### 4.3 Route observation

POC1 uses rtnetlink to record the kernel-selected local route near observation time, including source, gateway, interface, and destination context.

This is marked **STRONGLY_CORRELATED**, not proof of the exact packet path taken by every packet.

### 4.4 TLS supporting probe

`neta-agent` opens a separate TLS connection to the configured target using OpenSSL 3.x and records supporting trust evidence such as:

- TLS version
- cipher
- ALPN
- leaf certificate SHA-256
- SPKI SHA-256
- subject / issuer
- validity range
- chain validation
- hostname validation

This is an independent contemporaneous check, not application-session interception.

### 4.5 Target-scoped outbound observation

Current POC1 requires a target:

```text
--target host:port
```

The hostname is resolved and the observer records matching destination IPs + port only. In the current POC this is an **outbound** observation model: a local process connects to the configured remote target.

This is intentional for POC1 so unrelated endpoint traffic does not flood the history while the evidence model is being validated. It is not intended to restrict later versions to outbound traffic.

### 4.6 TCP lifecycle admission hardening

SOCK_DIAG still returns all TCP states so already-tracked connections can progress through their lifecycle.

However, a previously unseen socket is not allowed to create a new history record if its first observed state is an obvious post-owner/non-connection seed state such as:

```text
TIME_WAIT
CLOSE
LISTEN
```

Conceptually:

```text
known connection: ESTABLISHED -> ... -> TIME_WAIT
    keep lifecycle evidence

unknown socket first seen in TIME_WAIT
    ignore as a new connection
```

The admission decision lives in the Linux platform backend rather than leaking Linux TCP constants into portable code.

A listening socket is not itself a per-connection assurance object. In future inbound observation, the accepted sockets created from a listener are the connection records of interest; the listening socket may be retained separately as service/discovery metadata.

### 4.7 Graceful observation stop

`SIGINT` / `SIGTERM` now request a graceful stop rather than terminating the process immediately.

```text
Ctrl-C
  -> stop requested
  -> polling loop exits
  -> tracked connections finalized
  -> verdicts produced when baseline exists
  -> storage pruning / WAL checkpoint
  -> normal process exit
```

If the observer stops while a connection is still present, its final local lifecycle state is `OBSERVATION_ENDED` rather than falsely claiming the socket disappeared.

### 4.8 Detailed evidence inspection

The `evidence` command exposes the actual stored normalized values, not only evidence counts/hashes:

```bash
neta-agent evidence ID --db ./db/neta.db
```

It reports connection/process context, TCP samples, route values, and TLS supporting evidence when associated.

### 4.9 Baselines and deterministic rules

Baseline capture is explicit; new identities are not silently trusted.

```bash
neta-agent baseline capture --target host:443 --db ./db/neta.db
```

POC1 performance rule set: `neta-rules/0.1.0`.

```text
RTT >= 2 x baseline median          +0.50
RTT variance >= 2 x baseline        +0.20
retransmission delta >= 2           +0.30
score >= 0.50                       -> DEGRADED
```

Trust rules:

```text
valid TLS + matching SPKI           -> STABLE
valid TLS + changed SPKI            -> CHANGED
invalid chain or hostname           -> SUSPICIOUS
```

A rule confidence score is a deterministic rule score, not a statistical probability.

### 4.10 Replayability

The history records version/hash metadata needed to reproduce a verdict from stored/exported evidence.

```bash
neta-agent export ID --db ./db/neta.db > evidence.json
neta-agent replay evidence.json
```

The target behavior is matching:

- rule set
- evidence input hash
- Performance verdict
- Trust verdict

## 5. Current CLI surface

```text
neta-agent capabilities
neta-agent observe --target host:port [--duration] [--poll-ms] [--db]
neta-agent observe --outbound|--inbound|--all [filters] [--duration] [--db]
neta-agent run [--outbound|--inbound|--all] [filters] [--db]
neta-agent history [--limit] [--json] [--db]
neta-agent history show ID [--json] [--db]
neta-agent baseline capture --target host:port [--ca] [--db]
neta-agent baseline show --target host:port [--db]
neta-agent evidence ID [--db]
neta-agent explain ID [--db]
neta-agent export ID [--db]
neta-agent replay FILE
neta-agent storage status [--db] [--max-db-mb]
neta-agent storage prune [--db] [--max-db-mb]
```

SQLite remains an implementation detail behind `HistoryStore`; raw SQL is not the supported product interface.

## 6. Current dependencies and deployment model

The project intentionally keeps the dependency set small.

### SQLite

- license: Public Domain
- role: embedded longitudinal evidence/history store
- access: wrapped behind `HistoryStore`

### OpenSSL 3.x

- license: Apache-2.0
- role: TLS probe, validation, certificate/SPKI hashing, SHA-256

### libbpf (optional)

- license: BSD-2-Clause or LGPL-2.1
- role: CO-RE relocation, lifecycle-program attachment, and ring-buffer delivery
- absent from deliberate polling-only builds

The long-term packaging goal is **one self-contained executable per OS/architecture**. SQLite and OpenSSL may be statically linked for release builds. A fully static Linux artifact should preferably use a musl-based release toolchain.

## 7. Current limitations

Current limitations are deliberate and should not be hidden by the product language.

### Fallback polling can miss short-lived connections

When runtime eBPF is unavailable, SOCK_DIAG polling retains the MS0 limitation: a connection that begins and ends between polls can be missed. Capability output distinguishes this unavailable evidence from an absence of lifecycle events.

### Process attribution is race-sensitive

A `/proc` inode-to-process match only works while the process still exposes the socket fd. Event-time PID/TGID/UID/comm now covers this race when lifecycle eBPF is active; the limitation remains on the fallback path.

### Direction capability requires lifecycle evidence

MS2 supports target, outbound, inbound, and bidirectional all-connection modes.
Direction-specific modes require the corresponding eBPF lifecycle hooks and
fail explicitly when they are unavailable. Target mode retains polling fallback;
connections discovered only through SOCK_DIAG have UNKNOWN direction.

### TLS evidence is not exact application-session identity

The TLS probe is a separate supporting connection.

### Exact application DNS attribution is absent

The configured hostname is a correlation target. POC1 does not prove which DNS lookup an application used for an individual socket.

### No QUIC/UDP connection assurance yet

POC1 is TCP-focused.

### Linux/WSL only

The architecture is portable, but only the Linux backend is implemented.

### WSL networking is virtualized

WSL2 observations describe the Linux/WSL network environment. They do not automatically represent native Windows application sockets or physical Wi-Fi identity.

## 8. POC1 validation status and remaining acceptance work

Already demonstrated locally on WSL:

- real outbound target connection discovery
- exact TCP transport sampling via SOCK_DIAG / `tcp_info`
- process attribution for a live `curl` socket
- route evidence persistence
- sparse SQLite transport persistence
- small logical DB footprint
- graceful Ctrl-C finalization
- suppression of obvious post-owner states from seeding new history entries
- detailed evidence CLI output

Remaining controlled POC1 acceptance work:

```text
1. capture a clean explicit baseline
2. verify NORMAL / STABLE under normal controlled conditions
3. inject tc netem latency/loss/reordering and obtain DEGRADED / STABLE
4. rotate controlled TLS certificate key/SPKI and obtain NORMAL / CHANGED
5. combine network impairment + TLS change and obtain DEGRADED / CHANGED
6. export and replay the same connection evidence with identical verdict/input hashes
7. run bounded-storage stress testing under high connection/sample volume
```

## 9. Planned milestones

The roadmap below describes intended evolution, not currently implemented features.

### Milestone 0 — Finish and harden POC1

Goal: make the current Linux targeted observer a reliable, reproducible baseline implementation.

Planned work:

- complete the controlled baseline/netem/certificate/replay acceptance matrix
- improve process-attribution retry behavior for live sockets when the first `/proc` lookup races
- tighten lifecycle state transitions and avoid repeated redundant lifecycle writes
- add stronger evidence CLI formatting/JSON controls for long sample sets
- validate physical DB cap behavior under synthetic high connection volume
- continue fuzzing/sanitizer/static-analysis coverage for parsers and storage boundaries
- document exact WSL vs native Linux behavior

Exit criterion: POC1 acceptance scenarios are reproducible and the DB remains bounded under stress.

### Milestone 1 — Event-driven Linux lifecycle with eBPF (implemented)

Goal: stop relying on polling to discover when connections begin/end.

Architecture:

```text
eBPF lifecycle events -> WHEN + WHO
SOCK_DIAG/tcp_info     -> detailed TCP STATE
```

Planned capabilities:

- connect/accept/close lifecycle events
- stronger PID/process attribution for short-lived sockets
- socket-cookie correlation with later SOCK_DIAG samples
- lower discovery latency with less aggressive polling
- embedded BPF object in the single executable where practical
- CO-RE/BTF-based portability discipline across supported kernels

`accept` lifecycle coverage is important preparation for inbound observation in Milestone 2.

SOCK_DIAG remains the detailed TCP-state collector; eBPF complements it with connect/accept/close timing, event-time process context, and socket-cookie correlation. Runtime load/attach failures are reported and retain the MS0 polling fallback. See [`MILESTONE1_EBPF.md`](MILESTONE1_EBPF.md).

### Milestone 2 — Bidirectional all-connection endpoint observation and optional service mode

Goal: evolve from a target-specific outbound test observer into a real endpoint agent that can observe eligible TCP connections in **both outbound and inbound directions**, while retaining on-demand operation.

#### Required traffic-direction capability

**Milestone 2 MUST support both outbound and inbound TCP connection assurance.** `--all` must mean all eligible endpoint connections in both directions; it must not mean outbound-only traffic.

The portable connection model must record direction explicitly:

```text
OUTBOUND | INBOUND | UNKNOWN
```

Required behavior:

- discover and track outbound connections initiated by local processes
- discover and track inbound accepted connections owned by local server processes
- attribute inbound accepted sockets to the owning local process/service with the strongest native evidence available
- treat each accepted inbound socket as a connection assurance object
- do not create ordinary per-connection history rows for a bare `LISTEN` socket; listener state may be represented separately as service/discovery metadata
- collect the same available exact TCP transport metrics for inbound and outbound sockets
- correlate the response route toward the remote peer for inbound connections, with fidelity stated honestly
- keep trust logic direction-aware: outbound server identity and inbound peer/client identity are different trust questions
- do not reuse the current outbound active TLS probe as if it were exact evidence for an inbound application's TLS session
- preserve bounded CPU, RAM, and SQLite behavior when both traffic directions are enabled

Implemented CLI/operation model:

```text
neta-agent observe --target host:443              # current targeted outbound mode
neta-agent observe --outbound [filters...]         # outbound-only endpoint observation
neta-agent observe --inbound [--local-port 443]    # inbound-only endpoint observation
neta-agent observe --all                           # outbound + inbound
neta-agent run                                     # optional long-lived service mode
```

Exact CLI spelling may evolve, but explicit direction selection and a truly bidirectional `--all` mode are requirements.

Implemented controls include direction, local/remote port, process
include/exclude, periodic sampling, lifecycle-loss reporting, bounded tracker
state, and periodic anomaly-first database maintenance. CIDR filters,
anomaly-triggered evidence bursts, listener inventory, and systemd packaging
remain planned rather than being folded into an oversized MS2 implementation.

Additional future controls:

- local/remote CIDR filters
- service/listener filters for inbound workloads
- anomaly-triggered higher-resolution evidence bursts
- service/systemd integration while preserving the single-binary design

On-demand mode remains supported even after service mode exists.

Exit criterion: on native Linux, `neta-agent` can concurrently observe a controlled outbound client connection and an accepted inbound server connection, attribute each to the correct local process, label direction correctly, persist bounded transport/route evidence for both, and avoid treating the listening socket itself as a normal connection-history entry.

The deterministic MS2 session and bounded-churn coverage pass. A fresh
privileged kernel-path run remains required on a host that grants BPF authority;
the 2026-08-30 restricted WSL execution environment denied BPF loading.

### Milestone 3 — Stronger connection identity and exact application context where available

Goal: reduce uncertainty between socket, name-resolution identity, and cryptographic/application identity.

Planned areas:

- event-correlated DNS observations
- exact TLS identity only where a supported OS/application mechanism can provide it honestly
- direction-aware TLS/client identity evidence, including inbound client identity where mechanisms such as mTLS expose it reliably
- HTTP/RPC/span correlation as optional higher-layer evidence, not as a requirement for transport assurance
- richer host/network-environment identity

Evidence fidelity remains explicit when exact attribution is not available.

### Milestone 4 — Windows backend

Goal: emit the same semantic evidence model from native Windows facilities, including the bidirectional connection model established on Linux.

Candidate native mechanisms include:

- `GetExtendedTcpTable()` owner-PID views
- TCP EStats APIs for transport metrics
- IP Helper route APIs
- ETW/WFP where lifecycle or attribution requires them

The Windows backend should advertise capabilities rather than pretending unavailable fields exist. Where the OS exposes enough evidence, both outbound and inbound accepted connections are in scope.

### Milestone 5 — macOS backend

Goal: support the same high-level assurance model using macOS-supported native facilities, including connection direction where the OS APIs provide sufficient evidence.

This milestone must account for Network Extension/entitlement constraints and may not have metric-for-metric parity with Linux.

The product contract is semantic parity where possible, not identical kernel telemetry on every OS.

### Milestone 6 — Optional fleet / collector architecture

Goal: allow enterprise aggregation without turning SQLite into a remotely exposed database.

Endpoint architecture remains:

```text
endpoint
  neta-agent
    local SQLite
       |
       | explicit export/API protocol
       v
optional collector
```

Possible upload modes:

```text
local-only
summary
incident
full
```

An incident-oriented mode is particularly attractive: detailed evidence remains local unless a connection becomes `DEGRADED`, `CHANGED`, or `SUSPICIOUS`.

### Milestone 7 — External trust and path context

Goal: enrich—not replace—endpoint evidence with broader trust context.

Possible contextual evidence:

- ASN/prefix identity
- BGP origin changes
- RPKI state
- route/path fingerprints
- resolver identity changes
- reputation/context feeds
- external vantage observations such as RIPE Atlas where justified

These remain separate evidence classes. For example, `RPKI INVALID` is an observation; `possible route hijack` would be a hypothesis, not a directly observed fact.

Direction matters here as well: the relevant remote peer and trust expectations for an inbound service connection may differ from those for an outbound client connection.

### Milestone 8 — Protocol expansion

Potential later work:

- QUIC/UDP connection assurance
- STAMP/TWAMP-compatible active measurements where they add value
- richer path-change observation
- controlled remote-agent correlation

The project should reuse existing standards rather than inventing a new RTT/loss protocol.

## 10. Features intentionally not prioritized

The project should resist drifting into generic network-tool territory.

Not primary goals:

- generic ping/traceroute replacement
- speed-test product
- packet sniffer UI
- arbitrary PCAP warehouse
- transparent TLS proxy
- firewall/VPN product
- router appliance
- generic NDR/SASE clone
- opaque AI-generated risk score

The distinctive value should remain:

> real endpoint connection evidence + longitudinal local history + separate deterministic Performance/Trust assurance + reproducibility.

## 11. Milestone acceptance matrix

| Milestone | Primary proof |
|---|---|
| POC1 | Targeted outbound Linux connection -> evidence -> baseline -> deterministic verdict -> replay |
| Linux eBPF | Short-lived connect/accept/close lifecycle and process attribution without depending on snapshot timing |
| Bidirectional all-connections/service | Bounded concurrent outbound + inbound endpoint observation; correct direction/process attribution; accepted inbound sockets are tracked while bare listeners do not become connection-history rows |
| Exact context | Honest direction-aware DNS/TLS/application correlation with explicit fidelity |
| Windows | Same semantic assurance model, including inbound/outbound direction where supported, using native Windows collectors |
| macOS | Useful semantic parity within macOS entitlement/API constraints |
| Fleet | Explicit bounded upload modes; SQLite remains endpoint-local |
| External trust | Contextual routing/trust evidence without overclaiming causality |
| Protocol expansion | Additional protocols/measurements integrated without weakening the evidence model |

## 12. Design rule for future features

Every new collector or feature should answer five questions before being added:

1. **What connection/entity is this evidence about?**
2. **What is the native observation source?**
3. **What fidelity can honestly be claimed?**
4. **How does it affect deterministic verdicts, if at all?**
5. **What are its CPU, memory, storage, portability, dependency, and licensing costs?**

If those answers are unclear, the feature should not enter the core architecture yet.
