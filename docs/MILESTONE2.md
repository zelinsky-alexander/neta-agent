# Milestone 2: bidirectional endpoint TCP assurance

Milestone 2 extends the MS1 lifecycle pipeline from a target-only outbound
observer to direction-aware endpoint observation. It does not intercept or
modify traffic.

```text
CONNECT / ACCEPT / CLOSE
          |
          v
  eBPF lifecycle observer ---------> lifecycle drop health
          |
          v
 ConnectionAdmissionPolicy
   direction + filters + listener exclusion
          |
          v
   ConnectionTracker
 identity + canonical-cookie promotion
          |
          v
   EvidenceScheduler
    |             |
    v             v
 SOCK_DIAG     response/selected route
 TCP_INFO      (STRONGLY_CORRELATED)
    |             |
    +------> HistoryStore
                 |
          periodic bounded maintenance
```

## Direction and admission

`ConnectionDirection` is portable and persisted as `OUTBOUND`, `INBOUND`, or
`UNKNOWN`. CONNECT proves outbound direction and ACCEPT proves inbound
direction. SOCK_DIAG by itself does not prove direction, so polling-only target
discovery remains `UNKNOWN`; no port-number heuristic is used.

`ConnectionAdmissionPolicy` owns direction selection, target matching, local
and remote port filters, process inclusion/exclusion, and listener rejection.
It neither creates history rows nor performs collection. Bare LISTEN sockets
are classified by the Linux collector as listeners and cannot seed connection
history.

Supported modes are:

```text
neta-agent observe --target host:443
neta-agent observe --outbound [filters]
neta-agent observe --inbound [filters]
neta-agent observe --all [filters]
neta-agent run [--outbound|--inbound|--all] [filters]
```

`run` defaults to `--all`, uses the same admission/tracker/scheduler/session as
`observe`, and exits cleanly on SIGINT or SIGTERM. Direction modes require the
corresponding lifecycle hooks; they fail explicitly when exact direction is
unavailable. Target mode retains the polling fallback and records its direction
as UNKNOWN.

Current filters are `--local-port`, `--remote-port`, repeatable `--process`, and
repeatable `--exclude-process`. CIDR filters are intentionally deferred rather
than implemented as an ad-hoc parser.

## Identity and evidence

An ACCEPT event may initially use a fallback identity because its kretprobe
cannot obtain the lazy canonical socket cookie. When a unique active tuple
matches a later SOCK_DIAG record, the tracker rekeys the active identity to
`c:<cookie>` only after updating the existing SQLite connection row. An
ambiguous tuple is never promoted or guessed.

Process start ticks are optional throughout the portable model. Missing or zero
start time remains SQL NULL in the semantic column; a private negative storage key is
used only to prevent unsafe PID-only row reuse in the legacy uniqueness column.
It is never exposed as observed process evidence.

SOCK_DIAG/TCP_INFO remains the exact transport collector. Socket correlation
includes the observed network namespace, and that namespace is retained on the
connection row as well as its lifecycle evidence. `EvidenceScheduler`
requests immediate enrichment after lifecycle admission and periodic sampling
thereafter, and stops tracking closed connections. Closed tracker entries and
their tuple indexes are removed, bounding in-memory state to active sockets.
If a close record is lost, three consecutive complete SOCK_DIAG snapshots that
do not contain the socket reconcile the stale tracker entry as
`RECONCILED_ABSENT`.

Outbound route evidence means the host's selected route toward the remote
destination. Inbound route evidence is labeled `INBOUND_RESPONSE_ROUTE`: the
host's current response route toward the peer. Both are STRONGLY_CORRELATED and
neither proves the path traversed by received packets.

The independent OpenSSL probe remains SUPPORTING evidence only for target-mode
outbound observation. Inbound/all modes do not run that probe or claim an
inbound application/client TLS identity; Trust therefore remains UNVERIFIED
without applicable evidence.

## Health, storage, and fallback

The BPF program increments `lifecycle_drops` whenever ring-buffer reservation
fails. `LifecycleHealth` exposes the counter separately from event decoding.
Command output warns that lifecycle evidence may be incomplete after any drop;
zero events and lost events are no longer conflated.

`StorageMaintenance` invokes the existing anomaly-first 200 MiB/180 MiB cleanup
policy at configurable bounded intervals (`--maintenance-seconds`, default 60)
instead of pruning on every sample. Storage SQL maintenance lives in
`history_maintenance.cpp`; schema-column migrations live in
`history_schema.cpp`.

Schema additions migrate existing databases with conservative defaults:

```text
connections.direction                 default UNKNOWN
connections.network_namespace_inode   nullable
processes.start_ticks_observed         nullable
routes.relation                        default UNKNOWN
```

Export schema version 2 includes direction. Replay still accepts schema-1
bundles, treating absent direction as UNKNOWN, and direction does not alter the
validated MS0 verdict-input hash.

## Source modules

```text
include/neta/connection_direction.hpp
include/neta/connection_filter.hpp
include/neta/connection_admission_policy.hpp
include/neta/evidence_scheduler.hpp
include/neta/storage_maintenance.hpp
include/neta/route_semantics.hpp
include/neta/cli/observation_options.hpp
include/neta/cli/observation_command.hpp

src/core/connection_direction.cpp
src/core/connection_filter.cpp
src/core/connection_admission_policy.cpp
src/core/evidence_scheduler.cpp
src/core/storage_maintenance.cpp
src/core/history_schema.cpp
src/core/history_maintenance.cpp
src/core/route_semantics.cpp
src/cli/observation_options.cpp
src/cli/observation_command.cpp
```

## Validation and limitations

Deterministic tests cover direction, filters, listener rejection, fallback
cookie promotion, namespace/canonical ambiguity rejection, nullable process
start, idempotent migrations, scheduling, health semantics, periodic
maintenance, CLI conflicts, and bounded tracker churn. A deterministic session
test covers concurrent logical inbound/outbound admission, process attribution,
SOCK_DIAG enrichment followed by route observation, listener exclusion, and
finalization.
The privileged integration test covers the equivalent real kernel lifecycle
path when the host grants BPF authority.

The privileged test must be run on native/WSL Linux with sufficient BPF
authority:

```bash
sudo ./build-ms2/neta_ms1_ebpf_integration
and broader
sudo ctest --test-dir build \
  -R neta_ms1_ebpf_integration \
  --output-on-failure -V
```

A CI skip is not a runtime pass. ARM64 build support is retained; ARM64 runtime
validation remains pending. Adaptive anomaly-triggered sampling, CIDR filters,
listener inventory, exact inbound TLS/client identity, and systemd packaging
remain future work.

Validation on 2026-08-30 completed both `NETA_EBPF=ON` and `NETA_EBPF=OFF`
builds. Each configuration passed all 13 runnable tests; the privileged BPF
integration was skipped because the execution environment denied BPF loading
and set `no_new_privs`, so this session does not claim a fresh privileged
runtime pass. The 2,000-connection churn test ended with zero tracker and
scheduler entries and pruned SQLite to 626,688 bytes under a 716,800-byte cap.
