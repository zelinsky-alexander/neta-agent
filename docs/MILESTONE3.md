# Milestone 3: stronger connection identity and exact application context where available

Milestone 3 reduces uncertainty between a transport socket, name-resolution identity, and cryptographic/application identity without changing the core product rule: `neta-agent` observes evidence and states its fidelity honestly; it does not infer exactness from coincidence.

This work extends the completed MS2 bidirectional architecture. MS2 invariants remain requirements: explicit `OUTBOUND`/`INBOUND`/`UNKNOWN` direction, listener exclusion, canonical socket-cookie promotion only after unambiguous correlation, bounded active state and SQLite retention, lifecycle-drop visibility, and no reuse of the outbound supporting TLS probe as inbound application-session evidence.

## Implemented resolver path

The current MS3 branch contains an actual Linux application resolver collector and integrates it into the existing connection evidence graph:

```text
application process
    |
    | dynamically linked glibc getaddrinfo()
    v
uprobes / uretprobes
    |
    | query + API result + returned addrinfo values
    | event-time process/start/netns identity
    v
NameResolutionObserver
    |
    | bounded recent resolver-event window
    v
ObservationSession
    |
    | unique process + identity + address + time correlation
    +-------------------------+
    |                         |
    v                         v
STRONGLY_CORRELATED       ambiguous/no match
or lower fidelity             unresolved
    |
    v
HistoryStore per-connection evidence
    |
    +--> evidence CLI
    +--> export schema 3
    +--> replay integrity check
    |
    v
existing connection retention / delete cascade
```

The collector is implemented with libbpf uprobes on `getaddrinfo` in the dynamically loaded `libc.so.6` used by the agent. The entry probe records the queried name and event start. The return probe records the `getaddrinfo` result code and, on success, reads the returned IPv4/IPv6 `addrinfo` chain.

The event also carries the same forms of process context already used by lifecycle evidence where the kernel exposes them: kernel PID/TGID, agent-visible PID/TGID, UID, process start identity, command name, agent PID namespace, and current network namespace.

## What `EXACT` means here

The resolver collector may label a complete observed `getaddrinfo` call as an `EXACT` **application resolver API event**. That means the instrumented call and the returned values were observed directly at that API boundary.

It does **not** mean that a DNS packet was observed or even sent. A successful `getaddrinfo` call may be satisfied by NSS, `/etc/hosts`, local caches, or another configured backend. For that reason:

```text
PlatformCapabilities::application_name_resolution_events = true
    when the supported collector is active

PlatformCapabilities::exact_dns_observation = false
    because no network DNS transaction is claimed
```

The CLI reports these capabilities separately.

The socket relationship is also kept separate from event fidelity. Even a complete exact resolver API event is linked to a connection at no more than `STRONGLY_CORRELATED` fidelity.

## Correlation policy

The current correlator links only **forward lookups to outbound connections**. A candidate must satisfy all of the following:

- resolver API result is successful when a result code is available;
- the resolver event completed before connection admission;
- the resolver event is within the bounded five-second correlation window;
- the agent-visible process matches the connection process;
- the resolver returned the connection remote IP address;
- available durable process-start identities do not conflict;
- available network-namespace identities do not conflict.

For the strongest current link:

```text
complete resolver event
+ matching PID
+ matching durable process start
+ matching network namespace
+ returned address equals remote socket address
+ exactly one candidate in the bounded window
    -> STRONGLY_CORRELATED
```

If durable start or network-namespace identity is unavailable, the link is downgraded to `SUPPORTING`. Context-only sources remain `CONTEXTUAL`.

If two or more resolver events satisfy the candidate rules, the result is `AMBIGUOUS` and no evidence is attached. The implementation never chooses the closest timestamp or otherwise guesses.

Inbound reverse-name identity remains outside this implemented slice. An inbound peer address is not treated as proof of a reverse DNS name.

## Bounded collection

Resolver instrumentation is intentionally bounded:

- name-resolution ring buffer: 8 MiB;
- in-flight `getaddrinfo` state: 8,192-entry LRU map;
- returned addresses captured per call: at most 8;
- query and canonical-name wire fields: fixed 256-byte buffers;
- `ObservationSession` recent resolver-event buffer: at most 4,096 events;
- correlation retention window: five seconds.

If a query/canonical name or returned result set exceeds the supported capture bounds, or userspace result memory cannot be read completely, the event is marked partial and its observation fidelity is reduced from `EXACT` to `SUPPORTING`.

Nested same-thread `getaddrinfo` calls cannot be represented safely by the single in-flight key. Such a sequence is conservatively suppressed and increments the resolver drop counter rather than risking incorrect attribution.

Resolver event loss is independently observable through `NameResolutionHealth::dropped_events`. It is not conflated with an absence of name-resolution activity.

## Coverage limitations

The live collector currently covers the supported dynamically-linked, 64-bit glibc `getaddrinfo` ABI associated with the `libc.so.6` resolved by the running agent.

It does not claim coverage for:

- static binaries;
- musl or other non-glibc C libraries;
- c-ares or custom DNS implementations that bypass glibc `getaddrinfo`;
- application/runtime resolvers that do not cross this API boundary;
- a distinct libc inode that is not the instrumented object, for example in another mount/container environment;
- direct DNS traffic that bypasses the supported resolver API.

The collector also requires the normal eBPF prerequisites already used by the lifecycle backend, including kernel BTF and sufficient BPF/uprobe authority. Unsupported or denied environments expose an explicit unavailable reason and continue transport assurance without name-resolution enrichment.

`NETA_EBPF=OFF` provides the explicit unavailable stub and does not change MS2 polling/lifecycle fallback semantics.

## Persistence

Correlated evidence is stored per connection in:

```text
connection_name_resolution_evidence
connection_name_resolution_addresses
```

The evidence row includes resolver start/completion time, query kind, mechanism, queried and canonical names, source, API result code, observation fidelity, correlation fidelity, relation, process identity, network namespace, and a deterministic evidence hash. Returned addresses are normalized into the child table.

Both tables use `ON DELETE CASCADE` from the connection. Existing MS2 connection pruning therefore also bounds MS3 resolver evidence. The agent does not persist an unbounded global stream of uncorrelated resolver events.

Databases created by the earlier MS3 slice are migrated idempotently to add the nullable resolver `result_code` column.

## ObservationSession integration

`ObservationSession` accepts an optional `NameResolutionObserver`. Existing callers remain source-compatible.

When the collector is active:

1. resolver events are drained into the bounded transient window;
2. after a lifecycle poll returns, resolver events are drained before processing CONNECT events, because the resolver API call necessarily completes before the subsequent application connect attempt;
3. a newly admitted outbound connection is correlated against the bounded resolver window;
4. one unique match is persisted;
5. ambiguous matches are counted but not persisted;
6. inbound connections are left without forward-resolution attribution.

The same mechanism also works with target-mode transport polling when lifecycle evidence is unavailable, but a polling-discovered connection retains its existing `UNKNOWN` direction semantics and therefore is not upgraded to an outbound resolver relationship merely from coincidence.

## Evidence CLI, export, and replay

`neta-agent evidence ID` now shows resolver evidence separately, including:

- query name;
- resolver source;
- API result code;
- observation fidelity;
- connection-correlation fidelity;
- semantic relation;
- returned addresses.

Export schema version 3 adds `NAME_RESOLUTION` evidence records. Each record has a deterministic SHA-256, and the bundle contains the count and deterministic set hash of all resolver evidence attached to the connection.

Replay behavior is deliberately separated into two questions:

1. **Verdict replay** — unchanged. Name-resolution evidence is not currently an input to Performance or Trust, so the validated MS0 verdict-input hash remains unchanged.
2. **Resolver evidence integrity** — schema-3 replay verifies the exported resolver record count and set hash and reports `MATCH` or `MISMATCH` independently.

Schema-1 and schema-2 bundles remain accepted. They report resolver evidence as not present rather than failing replay.

## Source modules

Portable/core:

```text
include/neta/name_resolution.hpp
src/core/name_resolution.cpp
src/core/history_name_resolution.cpp
include/neta/observation_session.hpp
src/core/observation_session.cpp
```

Linux eBPF collector:

```text
src/platform/linux/ebpf/name_resolution.bpf.c
src/platform/linux/ebpf/name_resolution_wire.h
src/platform/linux/ebpf/name_resolution_decoder.hpp
src/platform/linux/ebpf/name_resolution_decoder.cpp
src/platform/linux/ebpf/name_resolution_loader.cpp
src/platform/linux/ebpf/name_resolution_loader_stub.cpp
```

The existing embedded-BPF helper now accepts a symbol parameter so lifecycle and name-resolution BPF objects can coexist without duplicating the embedding implementation.

No new third-party dependency is introduced. The implementation uses the project's existing C++20, libbpf, SQLite, OpenSSL, Linux API, and platform dynamic-loader facilities.

## Regression requirements

Every MS3 change must continue to preserve MS0/MS1/MS2 behavior. In particular:

- no listener may become an ordinary connection-history row;
- inbound and outbound direction semantics must not change;
- ambiguous cookie or resolver correlation must remain unresolved;
- target-mode supporting TLS behavior must remain unchanged;
- inbound/all modes must not gain fake TLS identity;
- lifecycle and resolver drop health must remain explicit;
- tracker, scheduler, resolver buffers, and storage must remain bounded;
- SQLite cleanup must continue to remove MS3 evidence with its owning connection;
- name-resolution enrichment must not alter the current deterministic Performance/Trust input hash.

Focused MS3 tests cover correlation, ambiguity, fidelity downgrade, wire decoding, persistence/result-code migration, ObservationSession integration, export/replay integrity including tamper detection, and a controlled real `getaddrinfo` eBPF integration path. The privileged integration test uses return code 77 when the host cannot load/attach BPF programs; a skip is not considered a privileged runtime pass.

## Remaining MS3 work

The next major MS3 areas are:

1. exact TLS/session evidence only where an OS or application mechanism observes the real application session;
2. distinct outbound server identity and inbound authenticated-client/mTLS identity relations;
3. optional HTTP/RPC/span correlation as higher-layer evidence, never as a prerequisite for transport assurance;
4. richer stable, privacy-conscious host/network-environment identity;
5. additional resolver backends only when their coverage and event semantics can be stated precisely.
