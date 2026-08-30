# Milestone 2 Chat Summary and Codex Handoff

_Last updated: 2026-08-30_

## Purpose

This document summarizes the Milestone 2 design discussion and the Codex implementation handoff for `neta-agent`.

The discussion was based primarily on `docs/DESIGN_ARCHITECTURE_MS1_AND_NEXT.md`, especially:

- section 17 — MS1 hardening observations;
- section 19 — Milestone 2: nearest architectural evolution;
- section 22 — design rules to preserve;
- section 23 — recommended implementation order.

The broader roadmap in `docs/DESIGN_AND_ROADMAP.md` remains authoritative for product scope.

---

## 1. Milestone 2 objective

Milestone 2 is the first major product-shape change after MS1.

The goal is to evolve from the current target-scoped outbound observer into a real endpoint TCP connection-assurance agent that can observe eligible TCP connections in both directions while preserving bounded local evidence, deterministic verdicts, replayability, and on-demand operation.

Required connection direction semantics:

```text
OUTBOUND
INBOUND
UNKNOWN
```

Direction must be derived from lifecycle evidence:

```text
CONNECT -> OUTBOUND
ACCEPT  -> INBOUND
```

Direction must not be inferred from conventional port numbers.

A bare `LISTEN` socket is not a normal per-connection assurance object. Accepted sockets are.

---

## 2. Target MS2 architecture

The intended decomposition is:

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
       +-> immediate SOCK_DIAG enrichment
       +-> periodic TCP_INFO sampling
       +-> route correlation
       +-> adaptive sampling
       |
       v
HistoryStore
       |
       +-> bounded SQLite history
       +-> baseline/verdict/replay
```

The responsibility boundaries are important:

- `ConnectionTracker` owns identity, correlation, lifecycle tracking and deduplication.
- `ConnectionAdmissionPolicy` decides whether a candidate should be observed.
- `EvidenceScheduler` owns evidence collection timing and enrichment policy.
- `HistoryStore` persists evidence and history.
- CLI parsing and service orchestration should not expand `main.cpp` into a monolith.

Substantial features should have dedicated `.hpp` and `.cpp` files.

---

## 3. MS1 hardening required before or during MS2

The design review identified several items that MS2 should fix rather than carrying forward.

### 3.1 Remove Linux TCP state leakage from portable core

`ConnectionTracker` should not include Linux TCP headers or reason directly about `TCP_LISTEN` numeric constants.

Linux-specific state should stay under `src/platform/linux/` and be mapped to portable semantics.

### 3.2 Canonical socket-cookie promotion

An inbound `ACCEPT` event may initially lack a usable socket cookie.

Current correlation can therefore begin with a fallback identity:

```text
ACCEPT
  -> fallback identity f:...
```

Later `SOCK_DIAG` may expose the canonical cookie:

```text
SOCK_DIAG cookie=9876
```

After an unambiguous correlation, MS2 should:

- preserve the same logical connection/history ID;
- update the persisted socket cookie;
- re-key the active tracker to the canonical cookie identity;
- avoid creating a duplicate connection.

Desired transition:

```text
f:... -> c:9876
```

If correlation is ambiguous, the tracker must refuse to guess.

### 3.3 Optional-safe process start identity

Missing process start time must remain unavailable.

It must not be converted to `0` and then treated as a real durable process identity, especially in long-lived service mode where PID reuse matters.

### 3.4 Lifecycle drop/backpressure visibility

The eBPF ring buffer can lose events if `bpf_ringbuf_reserve()` fails.

For all-connection MS2, silent evidence loss is unacceptable.

A small BPF-side dropped-event counter should be exposed to userspace so the agent can distinguish:

```text
no lifecycle event occurred
```

from:

```text
collector may have lost lifecycle events
```

---

## 4. Bidirectional observation behavior

Expected operation modes are conceptually:

```text
neta-agent observe --target host:443
neta-agent observe --outbound [filters...]
neta-agent observe --inbound [filters...]
neta-agent observe --all [filters...]
neta-agent run
```

`--all` must mean both outbound and inbound.

### Outbound

```text
local process
    |
    | CONNECT
    v
remote peer
```

The existing target-scoped mode remains supported.

### Inbound

```text
remote peer
    |
    v
local listener
    |
    | ACCEPT
    v
accepted connected socket
```

The accepted connected socket becomes the assurance object and should receive:

- direction = `INBOUND`;
- owning local process/service attribution;
- remote peer endpoint;
- network namespace context;
- SOCK_DIAG/TCP_INFO transport enrichment;
- route correlation toward the remote peer.

The listener itself must not become an ordinary connection-history row.

---

## 5. Direction-aware evidence semantics

### Route evidence

For outbound connections, route observation means the host-selected route toward the remote destination.

For inbound connections, route observation means the host's current response route toward the remote peer.

Both remain strongly correlated evidence, not proof of the exact packet path.

### Trust evidence

The current active TLS probe is supporting evidence for outbound target observations.

It must not be reused as if it described an inbound application's real TLS session.

For inbound connections, exact peer/client identity should remain unavailable or `UNVERIFIED` unless a future supported mechanism provides exact evidence.

MS2 must not drift into MS3 DNS/TLS/application instrumentation.

---

## 6. Filter and admission model

Filtering should be a portable responsibility outside `ConnectionTracker`.

The minimal useful filter model should support direction and may include:

```text
process include/exclude
local port
remote port
local CIDR
remote CIDR
```

The important architectural rule is:

> A filter decides whether a connection should be observed. It must not alter connection identity.

CLI option parsing and filter evaluation should remain separate concerns.

---

## 7. Evidence scheduling

Evidence timing should be extracted from general observation orchestration.

A dedicated scheduler should own policies such as:

```text
new admitted connection
    -> immediate SOCK_DIAG enrichment
    -> route observation

active connection
    -> periodic SOCK_DIAG/TCP_INFO enrichment

meaningful/anomalous state
    -> optionally higher-resolution sampling

closed connection
    -> stop scheduling active enrichment
```

This keeps timing policy out of `ConnectionTracker` and prevents `ObservationSession` from becoming another monolith.

---

## 8. Long-lived service mode

MS2 may add:

```text
neta-agent run
```

The service mode must reuse the same observation core as on-demand `observe`; it should not become a second parallel implementation.

Required operational behavior includes:

- graceful `SIGINT` / `SIGTERM` shutdown;
- bounded in-memory state;
- periodic storage-budget enforcement;
- lifecycle-loss visibility;
- adaptive/scheduled transport sampling;
- no busy polling when lifecycle eBPF is healthy;
- honest runtime capability reporting;
- no false socket-disappearance state merely because the observer stops.

SQLite remains endpoint-local and bounded.

---

## 9. File-size and architecture discipline

A strict requirement for the Codex implementation was to keep existing files small.

New responsibilities should use dedicated files rather than expanding:

```text
src/main.cpp
src/core/connection_tracker.cpp
src/core/observation_session.cpp
src/core/history_store.cpp
```

In particular:

```text
filter/admission logic       -> dedicated component
connection direction         -> dedicated portable component
evidence scheduling          -> dedicated component
storage maintenance          -> dedicated component
CLI command implementation   -> dedicated command modules where useful
portable TCP-state semantics -> dedicated portable component
```

Portable code must not acquire dependencies on Linux kernel/UAPI headers.

---

## 10. Interrupted Codex implementation status

The first Codex MS2 implementation session reached the 5-hour usage limit before completion.

At interruption, the worktree was still intact on `main`, with `origin/main` unchanged.

Modified files included:

```text
CMakeLists.txt
README.md
docs/DESIGN_AND_ROADMAP.md
docs/DESIGN_ARCHITECTURE_MS1_AND_NEXT.md
include/neta/connection_tracker.hpp
include/neta/history_store.hpp
include/neta/lifecycle.hpp
include/neta/model.hpp
include/neta/observation_session.hpp
include/neta/platform.hpp
src/core/connection_admission.cpp
src/core/connection_tracker.cpp
src/core/history_store.cpp
src/core/observation_session.cpp
src/main.cpp
src/platform/linux/ebpf/lifecycle.bpf.c
src/platform/linux/ebpf/lifecycle_decoder.cpp
src/platform/linux/ebpf/lifecycle_loader.cpp
src/platform/linux/ebpf/lifecycle_loader_stub.cpp
src/platform/linux/environment.cpp
src/platform/linux/process_resolver.cpp
src/platform/linux/socket_diag.cpp
tests/ms0_tests.cpp
tests/ms1_ebpf_integration.cpp
tests/ms1_tests.cpp
tests/tests.cpp
```

New/untracked files included:

```text
docs/MILESTONE2.md
include/neta/cli/
include/neta/connection_admission_policy.hpp
include/neta/connection_direction.hpp
include/neta/connection_filter.hpp
include/neta/evidence_scheduler.hpp
include/neta/route_semantics.hpp
include/neta/storage_maintenance.hpp
include/neta/tcp_state.hpp
src/cli/
src/core/connection_admission_policy.cpp
src/core/connection_direction.cpp
src/core/connection_filter.cpp
src/core/evidence_scheduler.cpp
src/core/history_maintenance.cpp
src/core/history_schema.cpp
src/core/history_schema.hpp
src/core/route_semantics.cpp
src/core/storage_maintenance.cpp
src/core/tcp_state.cpp
tests/connection_admission_policy_test.cpp
tests/connection_direction_test.cpp
tests/connection_tracker_test.cpp
tests/evidence_scheduler_test.cpp
tests/history_store_ms2_test.cpp
tests/lifecycle_health_test.cpp
tests/observation_options_test.cpp
tests/storage_maintenance_test.cpp
```

This indicates that the interrupted session had already followed the requested decomposition reasonably well: direction, filtering/admission, scheduling, storage maintenance, route semantics, portable TCP state, CLI modules and focused tests were being split into dedicated files.

The correct next step is therefore recovery/completion, not restarting MS2 from scratch.

---

## 11. Recommended recovery procedure for a fresh Codex session

Because the interrupted session had little context remaining, a fresh Codex session should inspect the dirty worktree and infer implementation state from the code.

The continuation session should first run:

```bash
git status --short
git diff --stat
git diff -- CMakeLists.txt
git diff -- src/main.cpp
git diff -- src/core/connection_tracker.cpp
git diff -- src/core/observation_session.cpp
git diff -- src/core/history_store.cpp
git diff -- src/platform/linux/ebpf/lifecycle.bpf.c
```

It should then read all new MS2 source/header/test files before making major changes.

The session should classify each MS2 requirement as:

```text
complete
partial
not implemented
```

and identify:

- duplicate or obsolete partial implementations;
- responsibility violations;
- missing CMake wiring;
- documentation claims ahead of implementation.

Only after this recovery assessment should it continue coding.

---

## 12. Completion order after recovery

Recommended implementation order:

```text
1. Make the current tree compile.
2. Fix focused unit-test failures.
3. Verify MS1 regressions.
4. Verify portable direction semantics.
5. Verify admission/filter architecture.
6. Complete inbound ACCEPT observation.
7. Complete fallback -> canonical cookie promotion.
8. Make process-start identity optional-safe.
9. Complete lifecycle drop accounting.
10. Verify EvidenceScheduler boundaries.
11. Complete --target / --outbound / --inbound / --all modes.
12. Complete run/service mode if in scope.
13. Complete SQLite migration/storage maintenance.
14. Verify history/evidence/explain/JSON/export direction output.
15. Verify deterministic export/replay.
16. Run privileged Linux integration tests.
17. Run bounded high-churn/resource validation.
18. Finalize documentation only after test state is known.
```

The implementation should build and test incrementally rather than accumulating a large broken diff.

---

## 13. Testing expectations

Focused MS2 tests already visible in the interrupted worktree should remain separate:

```text
connection_admission_policy_test.cpp
connection_direction_test.cpp
connection_tracker_test.cpp
evidence_scheduler_test.cpp
history_store_ms2_test.cpp
lifecycle_health_test.cpp
observation_options_test.cpp
storage_maintenance_test.cpp
```

Key behaviors to test:

### Direction

```text
CONNECT -> OUTBOUND
ACCEPT  -> INBOUND
unavailable -> UNKNOWN
```

No port-number heuristics.

### Tracker

```text
ACCEPT fallback identity
        |
        v
later SOCK_DIAG cookie
        |
        v
same history connection + canonical identity
```

Ambiguous tuple correlation must not be guessed.

### Process identity

Missing `start_ticks` remains unavailable.

### Scheduler

- immediate enrichment after admission;
- periodic enrichment while active;
- no active enrichment after close.

### Storage

- safe schema migration;
- old records become direction `UNKNOWN`;
- canonical cookie update persists;
- periodic budget enforcement preserves existing anomaly-first retention semantics.

### Integration

Run controlled outbound and inbound traffic concurrently.

Verify:

- outbound connection is `OUTBOUND`;
- accepted inbound socket is `INBOUND`;
- both are attributed to the correct local process;
- listener does not create a normal connection row;
- SOCK_DIAG enrichment reaches both;
- close lifecycle events finalize the correct tracked connections.

---

## 14. MS2 acceptance checklist

MS2 should not be called complete until the following are actually true:

```text
[ ] ConnectionDirection is portable, persisted and exposed.
[ ] CONNECT -> OUTBOUND.
[ ] ACCEPT -> INBOUND.
[ ] UNKNOWN remains available.
[ ] No direction inference from port numbers.
[ ] Accepted inbound sockets are connection-assurance objects.
[ ] Bare LISTEN sockets are not ordinary connection-history rows.
[ ] Inbound socket attribution resolves to the correct local process.
[ ] ACCEPT fallback identity can promote to canonical SOCK_DIAG cookie.
[ ] Promotion does not create duplicate logical connections.
[ ] Missing process start time stays unavailable.
[ ] Linux TCP constants no longer leak into portable core/tracker logic.
[ ] Lifecycle ring-buffer losses are observable.
[ ] Target mode still works.
[ ] Outbound mode works.
[ ] Inbound mode works.
[ ] --all means inbound + outbound.
[ ] Admission/filter policy is outside ConnectionTracker.
[ ] Evidence scheduling is outside ConnectionTracker.
[ ] Existing files have not become MS2 monoliths.
[ ] Inbound route semantics are documented honestly.
[ ] Inbound traffic does not misuse the outbound TLS probe.
[ ] Long-running storage enforcement is bounded.
[ ] Graceful shutdown remains correct.
[ ] Export/replay remains deterministic.
[ ] Unit tests pass.
[ ] NETA_EBPF=OFF build/tests pass.
[ ] BPF-enabled build/tests pass where supported.
[ ] Privileged lifecycle integration passes where supported.
[ ] High-churn observation does not show unbounded tracker/storage growth.
```

---

## 15. Dependency and licensing constraints

MS2 should not add a new third-party dependency unless genuinely necessary.

Existing dependencies remain sufficient for the intended design:

```text
C++20
libbpf
SQLite
OpenSSL
Linux native APIs
```

If a new dependency is proposed, its package, purpose, license, maintenance status, security implications and necessity should be reviewed before introduction.

GPL, AGPL, SSPL, source-available or similarly restrictive dependencies should not be introduced without explicit approval.

---

## 16. Non-goals

MS2 should not expand into:

```text
packet interception
transparent proxying
application traffic decryption
exact DNS/application-TLS instrumentation
HTTP inspection
QUIC support
fleet/cooperative assurance
threat-emulation framework work
BGP/RPKI enrichment
AI-based verdicts
generic firewall/IDS/NDR functionality
```

Those belong to later milestones or separate project tracks.

---

## 17. Final engineering principle

The key MS2 architecture rule remains:

> Make the agent broader in traffic coverage without making the core less precise.

That means:

```text
more connections
    must not mean
less explicit identity

more automation
    must not mean
hidden evidence loss

inbound support
    must not mean
heuristic direction inference

service mode
    must not mean
unbounded memory/database growth

more features
    must not mean
larger monolithic source files
```

MS2 should become a real bidirectional endpoint agent while preserving the evidence-first, reproducible architecture established by MS0 and MS1.
