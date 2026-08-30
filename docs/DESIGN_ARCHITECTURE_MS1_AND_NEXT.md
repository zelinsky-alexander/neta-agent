# neta-agent architecture after MS1

_Reviewed against committed MS1 code: `fabc3f2860ca37b8afa5bdc3c2b6e8a1524d036a`._

This document describes the implemented Milestone 1 architecture, how it extends the Milestone 0/POC1 evidence pipeline, and the nearest architectural changes expected in Milestone 2 and the boundary with Milestone 3.

The current product remains an endpoint observer, not a proxy or interceptor. Application traffic keeps using its real sockets; `neta-agent` observes kernel state and records provenance-rich evidence.

## 1. Architecture at a glance

Milestone 1 separates **connection lifecycle discovery** from **detailed transport-state sampling**.

```text
application process
      |
      | real TCP socket
      v
Linux TCP stack
      |
      +-------------------- eBPF CO-RE ---------------------+
      |               CONNECT / ACCEPT / CLOSE              |
      |                    WHEN + WHO                        |
      |                                                      v
      |                                              LifecycleObserver
      |                                                      |
      |                                                      v
      |                                             ConnectionTracker
      |                                                      |
      +----------------- SOCK_DIAG / TCP_INFO ---------------+
      |                  detailed TCP STATE                  |
      |                                                      v
      |                                                HistoryStore
      |                                                      |
      +---------------- rtnetlink route ---------------------+
      |                                                      |
      +---------------- OpenSSL probe -----------------------+
                                                             |
                                                             v
                                                        local SQLite
                                                             |
                                  +--------------------------+------------------+
                                  |                                             |
                                  v                                             v
                              baseline                                  deterministic rules
                                  |                                             |
                                  +---------------------> Performance + Trust <-+
                                                             |
                                                             v
                                                       export / replay
```

The fundamental responsibility split is:

```text
eBPF lifecycle        -> when the connection begins/ends and who owns it
SOCK_DIAG/TCP_INFO    -> exact detailed TCP transport state
/proc fallback        -> process resolution when lifecycle attribution is unavailable
rtnetlink             -> strongly correlated local route
OpenSSL active probe  -> supporting TLS identity evidence
HistoryStore          -> bounded longitudinal evidence
verdict engine        -> deterministic interpretation only
```

Collectors do not decide whether a connection is safe, suspicious, fast, or degraded. They record observations; the deterministic rule engine interprets them later.

## 2. Layering and source tree

The code is now split into three major layers.

```text
include/neta/ + src/core/
    portable semantic model and orchestration

src/platform/linux/
    Linux native collectors

src/platform/linux/ebpf/
    Linux eBPF lifecycle implementation
```

The main MS1 components are:

| Component | Responsibility |
|---|---|
| `include/neta/lifecycle.hpp` | Portable lifecycle event and capability model |
| `src/core/lifecycle.cpp` | Portable lifecycle string/semantic helpers |
| `include/neta/connection_tracker.hpp` | Correlation/tracking interface |
| `src/core/connection_tracker.cpp` | Admission, deduplication, cookie/tuple correlation, close handling, sparse TCP persistence |
| `include/neta/observation_session.hpp` | Target-scoped observation-session API |
| `src/core/observation_session.cpp` | Event-driven lifecycle loop plus scheduled SOCK_DIAG enrichment |
| `src/platform/linux/ebpf/lifecycle.bpf.c` | Kernel connect/accept/close programs |
| `src/platform/linux/ebpf/lifecycle_wire.h` | Versioned kernel/userspace wire format |
| `src/platform/linux/ebpf/lifecycle_decoder.cpp` | Bounded conversion from wire records to portable events |
| `src/platform/linux/ebpf/lifecycle_loader.cpp` | Embedded-object loading, PID namespace configuration, hook attach, ring-buffer consumption |
| `src/platform/linux/socket_diag.cpp` | SOCK_DIAG and TCP_INFO detailed transport snapshots |
| `src/platform/linux/process_resolver.cpp` | `/proc/<pid>/fd` inode fallback attribution |
| `src/platform/linux/route_observer.cpp` | rtnetlink route correlation |
| `src/core/history_store.cpp` | SQLite schema, lifecycle/TCP/TLS/route/baseline/verdict persistence |
| `src/main.cpp` | CLI parsing/dispatch, target TLS probe, baseline/verdict orchestration |

This decomposition is materially better than putting lifecycle loading, tracking, storage and CLI logic into one large Linux-specific file.

## 3. Portable lifecycle model

`include/neta/lifecycle.hpp` is the semantic boundary between kernel-specific event production and portable core logic.

The event type is intentionally small:

```cpp
enum class ConnectionLifecycleEventType {
    Connect,
    Accept,
    Close
};
```

A lifecycle event carries optional evidence rather than pretending every hook has every field:

```cpp
struct ConnectionLifecycleEvent {
    ConnectionLifecycleEventType type;
    std::uint64_t timestamp_ns;
    LifecycleProcessContext process;
    std::optional<std::uint64_t> network_namespace_inode;
    std::optional<NetworkEndpoint> local;
    std::optional<NetworkEndpoint> remote;
    std::optional<std::uint64_t> socket_cookie;
    std::optional<std::uint8_t> tcp_state;
};
```

The important design point is the use of `std::optional`: unavailable cookie/PID/endpoint evidence stays unavailable instead of becoming a fabricated zero-value fact.

### 3.1 Process identity and PID namespaces

MS1 keeps two PID views:

```text
kernel PID/TGID
    bpf_get_current_pid_tgid()
    provenance only; may be from a different PID namespace

agent-visible PID/TGID
    bpf_get_ns_current_pid_tgid()
    PID namespace of /proc visible to the agent
    usable for process attribution
```

The portable model reflects that split:

```cpp
struct LifecycleProcessContext {
    LifecycleProcessIds agent_visible;
    LifecycleProcessIds kernel;
    std::optional<ProcessNamespaceIdentity> agent_pid_namespace;
    std::optional<std::uint32_t> uid;
    std::optional<std::uint64_t> start_ticks;
    std::optional<std::string> comm;
};
```

This is not just a WSL workaround. It establishes correct semantics for PID namespaces generally. A kernel/root-namespace TGID must not be used blindly as `/proc/<pid>` inside another namespace.

## 4. Kernel lifecycle collection

`src/platform/linux/ebpf/lifecycle.bpf.c` contains four hook programs.

```text
fexit/tcp_v4_connect      successful IPv4 outbound connect
fexit/tcp_v6_connect      successful IPv6 outbound connect
kretprobe/inet_csk_accept accepted connected socket
fentry/tcp_close          TCP socket close
```

### 4.1 CONNECT

The connect hooks run after successful connection setup so endpoints are populated:

```cpp
SEC("fexit/tcp_v4_connect")
int BPF_PROG(neta_tcp_v4_connect, struct sock *sk,
             struct sockaddr *address,
             int address_length,
             int result)
{
    return result == 0
        ? emit(sk, NETA_LIFECYCLE_CONNECT, bpf_get_socket_cookie(sk))
        : 0;
}
```

CONNECT uses a real kernel socket cookie. That cookie is the preferred identity for later correlation with SOCK_DIAG.

### 4.2 ACCEPT

The accept hook observes the connected socket returned from `inet_csk_accept`:

```cpp
SEC("kretprobe/inet_csk_accept")
int neta_inet_csk_accept(struct pt_regs *ctx)
{
    return emit((struct sock *)PT_REGS_RC(ctx),
                NETA_LIFECYCLE_ACCEPT,
                0);
}
```

The `kretprobe` program type cannot use the socket-cookie helper used by the tracing programs. The implementation therefore does **not** fabricate a cookie and does not read a possibly-uninitialized lazy internal cookie field.

Instead:

```text
ACCEPT event
    cookie = unavailable
        |
        v
active tuple/process/netns fallback
        |
        v
later SOCK_DIAG snapshot
        |
        v
correlate to the accepted socket
```

This is the correct evidence semantics for MS1 and is the basis for Milestone 2 inbound support.

### 4.3 CLOSE

`fentry/tcp_close` produces close evidence without waiting for the socket to disappear from a later snapshot:

```cpp
SEC("fentry/tcp_close")
int BPF_PROG(neta_tcp_close, struct sock *sk, long timeout)
{
    return emit(sk,
                NETA_LIFECYCLE_CLOSE,
                bpf_get_socket_cookie(sk));
}
```

This is especially important for short-lived sockets that could begin and end between two SOCK_DIAG polls.

## 5. BPF event format and delivery

Kernel/userspace communication uses a bounded, versioned ring-buffer record defined in `lifecycle_wire.h`.

Important fields include:

```text
version / size / event type
availability bitmask
kernel PID/TGID
agent-visible PID/TGID
PID namespace device/inode
UID
monotonic timestamp
socket cookie
network namespace inode
process start time
local/remote address + port
TCP state
comm
```

The availability mask is part of the contract. For example:

```text
NETA_HAS_COOKIE
NETA_HAS_AGENT_PID
NETA_HAS_KERNEL_PID
NETA_HAS_AGENT_PID_NAMESPACE
NETA_HAS_NETNS
NETA_HAS_LOCAL
NETA_HAS_REMOTE
```

Userspace does not interpret an unset bit as an observed zero value.

The decoder first validates record size/version:

```cpp
if (wire.version != NETA_LIFECYCLE_WIRE_VERSION ||
    wire.size != sizeof(wire)) {
    return {std::nullopt,
            "unsupported lifecycle event version or size"};
}
```

That gives the wire format a clean compatibility boundary for later fields.

## 6. PID-namespace configuration

Before attaching hooks, `lifecycle_loader.cpp` obtains the PID namespace that the running agent actually sees:

```cpp
::stat("/proc/self/ns/pid", &namespace_stat);
```

The device/inode pair is written to a BPF array map. The BPF program then asks for IDs relative to that namespace:

```text
userspace
  stat(/proc/self/ns/pid)
       |
       v
lifecycle_config BPF map
       |
       v
bpf_get_ns_current_pid_tgid()
       |
       v
agent-visible PID/TGID
```

At the same time the program retains `bpf_get_current_pid_tgid()` as kernel provenance.

This distinction was validated on WSL2, where the root/host-side PID namespace differed from the distro-visible PID namespace. The same design remains valid on ordinary native Linux where the values may be identical.

## 7. Embedded BPF object and CO-RE build

The build supports three explicit policies:

```text
NETA_EBPF=AUTO   build eBPF when clang/libbpf are available; otherwise fallback
NETA_EBPF=ON     eBPF prerequisites are mandatory
NETA_EBPF=OFF    deliberate polling-only binary
```

CMake maps the release architecture to libbpf tracing ABI definitions:

```text
x86_64 / amd64 -> __TARGET_ARCH_x86
aarch64 / arm64 -> __TARGET_ARCH_arm64
```

The object pipeline is:

```text
lifecycle.bpf.c
      |
      | clang -target bpf -g -O2
      v
build/generated/lifecycle.bpf.o
      |
      | cmake/EmbedBinary.cmake
      v
build/generated/lifecycle_bpf_bytes.inc
      |
      v
lifecycle_loader.cpp
      |
      v
neta-agent executable
```

There is no runtime `.bpf.o` sidecar, Python process, `bpftool` invocation, or companion daemon. libbpf is used for CO-RE/BTF relocation, loading, link lifetime and ring-buffer consumption.

## 8. Runtime capability probing

Build-time inclusion and runtime usability are deliberately separate.

`LifecycleCapability` reports:

```text
built_in
btf_core_runtime
connect_events
accept_events
close_events
unavailable_reason
```

The loader attempts each hook independently. Successfully attached links are preserved even if another hook cannot attach. This lets capabilities distinguish, for example:

```text
CONNECT  YES
ACCEPT   NO
CLOSE    YES
```

from complete unavailability.

For the current target-scoped outbound flow, `CONNECT + CLOSE` are enough to enable event-driven outbound discovery:

```cpp
bool outbound_available() const noexcept {
    return connect_events && close_events;
}
```

Full lifecycle capability still requires connect + accept + close.

## 9. ConnectionTracker: identity and deduplication

`ConnectionTracker` is the central MS1 correlation component. It receives lifecycle observations and SOCK_DIAG snapshots and ensures they refer to one logical history connection.

### 9.1 Preferred identity: socket cookie

For lifecycle events:

```cpp
if (event.socket_cookie && valid_cookie(*event.socket_cookie)) {
    return "c:" + std::to_string(*event.socket_cookie);
}
```

For SOCK_DIAG observations:

```cpp
if (valid_cookie(socket.socket_cookie)) {
    return "c:" + std::to_string(socket.socket_cookie);
}
```

So the ideal path is:

```text
eBPF CONNECT cookie=1234
        |
        v
tracker identity c:1234
        |
        v
SOCK_DIAG idiag_cookie=1234
        |
        v
same history connection
```

### 9.2 Fallback identity

When a lifecycle event has no cookie, the fallback identity includes more than the five-tuple:

```text
network namespace
process TGID
local endpoint
remote endpoint
lifecycle timestamp
```

The tuple index is then used only for one **unambiguous active** match.

If two active candidate connections share the same tuple index, the tracker refuses to guess.

### 9.3 Lifecycle admission

`observe_lifecycle()`:

1. rejects non-TCP events;
2. derives cookie/fallback identity;
3. handles CLOSE against an existing identity or unique tuple match;
4. rejects LISTEN state;
5. requires endpoints and agent-visible process attribution;
6. creates one history connection;
7. persists the lifecycle event;
8. indexes the active tuple.

The process identity used for history is specifically the agent-visible TGID:

```cpp
if (!event.process.agent_visible.tgid || !event.process.uid)
    return std::nullopt;

process.pid = *event.process.agent_visible.tgid;
```

This prevents a root/kernel PID from being presented as a `/proc`-resolvable process identity.

### 9.4 SOCK_DIAG enrichment

`observe_socket()` first tries exact cookie identity and then one unambiguous active tuple fallback.

```text
SOCK_DIAG snapshot
      |
      +-> cookie identity match
      |
      +-> otherwise unique active tuple match
      |
      v
sparse TCP sample persistence
```

If no lifecycle event admitted the connection, the existing MS0 polling path still applies: eligible TCP state + `/proc` inode process resolution are required before creating history.

## 10. ObservationSession: event-driven discovery plus scheduled state sampling

`ObservationSession` moved the observation loop out of `main.cpp`.

The current target-scoped flow is:

```text
start observe --target host:port
       |
       v
resolve target IP set
       |
       v
create LifecycleObserver + SOCK_DIAG observer
       |
       +-----------------------------------+
       | eBPF outbound available           | eBPF unavailable
       |                                   |
       v                                   v
wait for lifecycle events             poll every ~100 ms
       |
CONNECT for target
       |
       +-> admit immediately
       +-> route lookup
       +-> trigger immediate SOCK_DIAG snapshot
       |
       v
periodic SOCK_DIAG enrichment (~1 s default)
       |
       v
CLOSE event finalizes connection
```

In code the mode selection is explicit:

```cpp
result.lifecycle_events_active =
    lifecycle_observer_.capability().outbound_available();
```

When an eBPF event admits a new connection, the session immediately runs a transport snapshot instead of waiting for the next periodic interval.

The default detailed transport interval is therefore relaxed from the MS0 discovery interval:

```text
eBPF active      -> 1000 ms default detailed sampling
polling fallback -> 100 ms discovery polling
```

This is one of the practical values of MS1: event discovery latency no longer requires aggressive detailed-state polling.

## 11. Sparse transport persistence

SOCK_DIAG remains authoritative for detailed TCP evidence.

The tracker persists a TCP sample when:

- it is the first sample;
- retransmission/loss/state changes;
- RTT changes materially;
- RTT variance changes materially; or
- roughly one second has passed since the last persisted sample.

The policy is intentionally sparse to keep the endpoint-local database bounded.

```text
frequent kernel observation
       |
       v
meaningful_change()
       |
       +---- no ----> keep only current in-memory state
       |
      yes
       |
       v
SQLite transport_samples
```

## 12. Evidence persistence

MS1 adds `lifecycle_events` as a separate evidence class rather than folding lifecycle facts into transport samples.

The table records, among other fields:

```text
connection_id
event_type
observed_ns
provenance
agent_pid / agent_tgid
kernel_pid / kernel_tgid
agent PID namespace device/inode
uid / process start / comm
network namespace
family / protocol
local / remote endpoint
socket cookie
tcp_state
```

This preserves the distinction:

```text
lifecycle event   -> observed kernel lifecycle fact
transport sample  -> detailed TCP_INFO state
route             -> strongly correlated local route
TLS probe         -> supporting contemporaneous trust evidence
verdict           -> deterministic interpretation
```

The `evidence` CLI exposes lifecycle events separately from exact TCP samples.

## 13. Route and TLS relation to MS1

Milestone 1 does not change their evidence meaning.

### Route

When a connection is newly admitted, `ObservationSession` performs the route lookup once and stores it as strongly correlated evidence.

```text
new connection
     |
     +-> route_to(remote address)
             |
             v
        rtnetlink route
```

This is local route-selection context, not a claim about every packet's actual Internet path.

### TLS

`cmd_observe()` performs a separate OpenSSL connection to the configured target before observation and stores it as `SUPPORTING` evidence.

The active TLS probe still does **not** prove the certificate used on the application socket. MS1 improves socket lifecycle identity but does not turn the independent TLS probe into exact application-session TLS evidence.

## 14. Baseline, verdict and replay path inherited from MS0

MS0 remains the assurance foundation.

```text
stored TCP samples
     |
     +-> aggregate transport metrics
     |
accepted baseline --------------------+
     |                                |
     +-> RTT / rttvar thresholds      |
     +-> retransmission delta         |
                                      v
                                  Performance

supporting TLS probe
     |
accepted SPKI baseline
     |
     +-> validation + SPKI comparison
                                      |
                                      v
                                     Trust
```

Current deterministic dimensions remain independent:

```text
Performance: NORMAL | DEGRADED | FAILED | INSUFFICIENT_EVIDENCE
Trust:       STABLE | CHANGED | SUSPICIOUS | UNVERIFIED
```

The acceptance matrix remains:

| Transport | TLS identity | Expected |
|---|---|---|
| baseline-like | same | `NORMAL / STABLE` |
| degraded | same | `DEGRADED / STABLE` |
| baseline-like | changed valid SPKI | `NORMAL / CHANGED` |
| degraded | changed valid SPKI | `DEGRADED / CHANGED` |

The combined case explicitly does not establish causal relation between transport degradation and trust change.

Export/replay remains verdict-input replay with matching:

```text
Evidence input hash: MATCH
Rule set:            MATCH
Verdict:             MATCH
```

## 15. Fallback architecture

MS1 deliberately preserves the MS0 path.

```text
                    +-----------------------+
                    | lifecycle eBPF usable?|
                    +-----------+-----------+
                                |
               +----------------+----------------+
               | YES                             | NO
               v                                 v
      eBPF drives discovery              SOCK_DIAG drives discovery
      CONNECT/CLOSE events               short polling interval
               |                                 |
               +---------------+-----------------+
                               v
                       SOCK_DIAG / TCP_INFO
                               |
                               v
                        same core tracker/store
```

Unavailable eBPF evidence is reported as a capability limitation. It is never interpreted as “no lifecycle events occurred.”

## 16. Runtime validation status

The current x86-64 MS1 path has been exercised with real privileged BPF load/attach and kernel sockets on two different environments:

```text
WSL2 Ubuntu 24.04
  Microsoft Linux 6.18.33.2

AWS Ubuntu 24.04
  aws kernel 7.0.0-1009-aws
```

Both environments demonstrated:

```text
CONNECT seen                         PASS
ACCEPT seen                          PASS
client + accepted CLOSE seen         PASS
short-lived connect/accept/close     PASS
short-lived process attribution      PASS
CONNECT cookie -> SOCK_DIAG          PASS
ACCEPT fallback -> SOCK_DIAG         PASS
fabricated ACCEPT cookie             NO
MS0 regression                       PASS
```

ARM64 runtime validation remains pending and is tracked separately in [`ARM64_RUNTIME_VALIDATION.md`](ARM64_RUNTIME_VALIDATION.md).

## 17. Code review of committed MS1

The committed design is coherent and the main architectural goals are implemented cleanly: lifecycle events are portable semantic objects, Linux/BPF loading is isolated, connection correlation is centralized, observation orchestration is outside the CLI, fallback remains explicit, and real integration tests cover the important kernel path.

The following items are **near-term hardening observations, not failures of the validated MS1 acceptance criteria**.

### 17.1 Linux TCP constant leaks into core

`src/core/connection_tracker.cpp` includes `<netinet/tcp.h>` and checks `TCP_LISTEN` directly.

That is a small violation of the intended boundary that Linux TCP UAPI details remain under `src/platform/linux/`.

Before Windows/macOS work, move this into either:

- a portable semantic TCP state enum, or
- a platform helper that exposes “eligible lifecycle state” semantically.

### 17.2 Fallback identity is correlated, but not promoted to the later canonical cookie

For an ACCEPT event without a cookie, the tracker creates a fallback identity. When SOCK_DIAG later supplies the canonical cookie, `observe_socket()` finds the fallback via the active tuple and enriches the existing connection without duplication.

However, the current tracker does not re-key the in-memory connection from the fallback identity to `c:<cookie>`, and the initially persisted `connections.socket_cookie` is not upgraded from zero.

This is acceptable for the MS1 inbound foundation because correlation correctness is proven, but Milestone 2 should promote a successfully correlated accepted connection to canonical cookie identity once SOCK_DIAG supplies it.

Desired MS2 transition:

```text
ACCEPT
  fallback identity f:...
        |
        v
SOCK_DIAG cookie=9876
        |
        +-> prove unique match
        +-> update persisted socket cookie
        +-> re-key active tracker as c:9876
        v
canonical identity
```

### 17.3 Process start time is optional in lifecycle evidence but not optional in `ProcessIdentity`

`process_from()` currently substitutes `0` when lifecycle process start time is unavailable.

For a short on-demand observation this is low risk, but an always-on service can eventually see PID reuse. A `(pid, start_ticks=0)` process key can then be less robust than intended.

Before long-lived MS2 service mode, model unavailable process-start identity explicitly rather than relying on zero as a durable identity component.

### 17.4 Duplicate lifecycle insert return value

`HistoryStore::add_lifecycle_event()` uses `INSERT OR IGNORE` and returns `sqlite3_last_insert_rowid()`.

If the row was ignored as a duplicate, SQLite's last insert row ID can refer to an earlier insert. Current callers do not depend on the returned lifecycle row ID, so this is not presently harmful. The API should nevertheless return `void`/`optional<id>` or explicitly detect insertion before a future caller relies on it.

### 17.5 Ring-buffer backpressure is currently silent

The BPF ring buffer is bounded. If `bpf_ringbuf_reserve()` fails, the kernel program simply returns without emitting the event.

For target-scoped MS1 this is acceptable, but all-connection MS2 needs observability of evidence loss. Add a small per-CPU/global counter map for dropped lifecycle records and expose it as capability/health evidence.

Otherwise a high-load endpoint could silently turn “collector overloaded” into apparently complete lifecycle history.

### 17.6 Storage enforcement must become periodic for service mode

Current observation commands prune at bounded command points. A future long-lived `neta-agent run` cannot rely only on startup/shutdown pruning.

MS2 service mode should perform periodic or write-triggered budget enforcement while preserving anomaly-first retention.

### 17.7 `main.cpp` remains a future decomposition target

MS1 correctly moved the observation loop into `ObservationSession`, but `main.cpp` still owns many CLI commands plus hand-written JSON export/replay helpers.

This is not an MS1 blocker. Before adding `--all`, inbound filters, service configuration and health/status commands, extracting command modules/CLI parsing will prevent `main.cpp` from becoming the next monolith.

## 18. Relationship to Milestone 0

Milestone 0 established the assurance semantics:

```text
real connection
    -> exact TCP evidence
    -> process + route evidence
    -> supporting TLS evidence
    -> accepted baseline
    -> deterministic Performance / Trust
    -> bounded history
    -> export / replay
```

MS1 deliberately does **not** replace those semantics. It improves the front of the pipeline:

```text
MS0 discovery:
    poll -> hope the socket still exists

MS1 discovery:
    event at connect/accept/close time
        -> preserve WHO + WHEN
        -> enrich with the same SOCK_DIAG/TCP_INFO evidence
```

Therefore MS1 should be understood as a stronger acquisition layer for the already validated MS0 assurance model.

## 19. Milestone 2: nearest architectural evolution

Milestone 2 is the first major product-shape change after MS1.

Goal:

> Observe eligible endpoint TCP connections in both directions, not only a preselected outbound target, while preserving bounded local evidence and on-demand operation.

### 19.1 Explicit direction becomes a core semantic field

The portable model should gain:

```cpp
enum class ConnectionDirection {
    Outbound,
    Inbound,
    Unknown
};
```

Direction must come from lifecycle context, not port-number heuristics.

```text
CONNECT initiated by local process
        -> OUTBOUND

ACCEPT returned to local listening service
        -> INBOUND
```

A bare LISTEN socket remains service metadata, not a normal connection object.

### 19.2 Inbound lifecycle path

MS1 already provides the kernel primitive needed for inbound connection objects:

```text
local listener
      |
      | inet_csk_accept
      v
ACCEPT lifecycle event
      |
      +-> local service process identity
      +-> remote peer endpoint
      +-> network namespace
      +-> event timestamp
      |
      v
inbound Connection
      |
      v
SOCK_DIAG TCP_INFO enrichment
```

The current target-scoped `ObservationSession` intentionally ignores ACCEPT events for product observation. MS2 should add a direction-aware admission/filter layer rather than special-casing inbound inside the existing target matcher.

### 19.3 Proposed MS2 core decomposition

A clean next step is:

```text
LifecycleObserver
       |
       v
ConnectionAdmissionPolicy
       |
       +-> direction
       +-> include/exclude filters
       +-> listener/service policy
       |
       v
ConnectionTracker
       |
       v
EvidenceScheduler
       |
       +-> SOCK_DIAG enrichment
       +-> route correlation
       +-> adaptive sampling
       v
HistoryStore
```

This keeps filter policy out of the tracker. The tracker should continue to answer identity/correlation/lifecycle questions rather than becoming a CLI filter engine.

### 19.4 All-connection operation

Expected operation modes are conceptually:

```text
observe --target host:443      current targeted outbound investigation
observe --outbound [...]       all/filter outbound
observe --inbound [...]        all/filter inbound
observe --all                  both directions
run                            optional long-lived service
```

Exact CLI spelling can change, but `--all` must truly mean outbound + inbound.

### 19.5 Storage schema additions

At minimum MS2 will need connection direction persisted:

```text
connections.direction
```

Likely additional service/listener metadata should live separately from ordinary connection rows:

```text
listeners/services
    local endpoint
    owning process
    first/last observed
    optional executable/service identity
```

Accepted sockets then reference ordinary connection history; the listening socket itself does not become a fake connection.

### 19.6 Route semantics for inbound

For an inbound accepted connection, route observation should mean:

> the host's current response route toward the remote peer.

It remains strongly correlated evidence, not proof of the inbound packet path.

### 19.7 Trust semantics become direction-aware

Outbound trust asks questions such as:

```text
Did the expected remote server identity change?
Did destination identity/prefix/route context change?
```

Inbound trust asks different questions:

```text
Is this remote peer/network expected for this local service?
Did source network/ASN/prefix context change?
Is an exact authenticated client identity available, for example mTLS?
```

The current outbound active TLS probe must not be reused as if it represented an inbound application's TLS session.

### 19.8 Service-mode requirements

Once `run` is long-lived, the architecture needs additional operational controls:

```text
bounded event queue/backpressure visibility
periodic storage pruning
adaptive sample intervals
health/capability status
clean reload/shutdown
strict CPU/RAM limits
stable process/socket identity under PID and tuple reuse
```

These are product-agent requirements rather than one-shot CLI requirements.

## 20. Milestone 3 boundary: exact application context

Milestone 2 should not expand into application interception.

Milestone 3 is the appropriate boundary for improving exact higher-layer identity where supported:

```text
DNS event correlation
exact TLS identity when a supported native/application mechanism provides it
optional HTTP/RPC/span correlation
direction-aware client identity such as mTLS where exact evidence exists
```

The rule remains:

> stronger attribution is added only when its native observation source and fidelity can be stated honestly.

MS3 should therefore enrich the same connection evidence graph rather than introduce a second independent monitoring model.

## 21. Target architecture through the next milestones

```text
                         MS0                    MS1                     MS2
                         ---                    ---                     ---

application socket
      |
      +-----------------------> eBPF lifecycle ------------------------------+
      |                         CONNECT/ACCEPT/CLOSE                          |
      |                              |                                        |
      |                              v                                        v
      |                       ConnectionTracker                    direction/filter policy
      |                              |                                        |
      +---- SOCK_DIAG/TCP_INFO ------+-----------------------------> all connections
      |                              |                                        |
      +---- rtnetlink ---------------+                                        |
      |                              v                                        v
      +---- TLS support probe ---> HistoryStore <---------------------- bounded service mode
                                      |
                                      v
                                   baseline
                                      |
                                      v
                           deterministic assurance
                                      |
                           +----------+----------+
                           |                     |
                     Performance              Trust
                           |                     |
                           +----------+----------+
                                      |
                                      v
                                export/replay

                                                                    MS3 adds exact context
                                                                    where honestly available
```

The architectural constant across these milestones is the evidence model, not any one Linux collector.

## 22. Design rules to preserve

The closest milestones should preserve these invariants:

1. **Connection/socket remains the main runtime object.**
2. **Collectors emit observations, not verdicts.**
3. **Performance and Trust remain independent dimensions.**
4. **Evidence fidelity and unavailability remain explicit.**
5. **Socket cookie is preferred identity when valid; five-tuple alone is never durable identity.**
6. **PID namespace provenance is preserved; only agent-visible IDs are used for `/proc`.**
7. **SOCK_DIAG remains the detailed Linux TCP-state collector.**
8. **eBPF complements SOCK_DIAG instead of replacing it.**
9. **Bare listeners are service metadata, not per-connection history.**
10. **SQLite remains endpoint-local and bounded.**
11. **Runtime capability loss falls back honestly; it is not interpreted as absence of events.**
12. **Single-executable deployment remains the release objective.**
13. **Cross-platform core types must not depend on Linux kernel structs/UAPI details.**
14. **Any future AI explanation remains downstream of deterministic evidence/verdicts.**

## 23. Recommended next implementation order

After the validated MS1 commit, the nearest implementation sequence should be:

```text
1. Complete ARM64 runtime validation
       |
2. Small MS1 hardening
   - remove TCP_LISTEN Linux constant from core
   - canonical-cookie promotion after fallback correlation
   - lifecycle drop counter/health
   - make process-start identity optional-safe
       |
3. Add ConnectionDirection to portable model + SQLite
       |
4. Extract direction/filter admission policy
       |
5. Enable inbound accepted-socket observation
       |
6. Add --outbound / --inbound / --all modes
       |
7. Add long-lived run/service mode with periodic budgets
       |
8. Stress test simultaneous inbound + outbound high connection churn
       |
9. Proceed to MS3 exact DNS/TLS/application-context work
```

This order keeps MS2 focused on becoming a real endpoint agent without weakening the evidence/replay semantics already proven in MS0 and the lifecycle acquisition semantics proven in MS1.

## 24. Milestone 2 implementation status

The MS2 implementation follows the decomposition proposed in §19.3. Direction,
filters/admission, scheduling, periodic storage maintenance, route relation,
and observation CLI/service handling are separate modules; the tracker remains
responsible only for logical identity, correlation, promotion, and lifecycle
state. See [`MILESTONE2.md`](MILESTONE2.md) for the implemented architecture,
schema/CLI semantics, validation commands, deterministic results, and the
explicitly unvalidated privileged runtime criterion.
