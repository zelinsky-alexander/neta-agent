# NETA Windows Broad-Support Roadmap

**Status:** Proposed Windows implementation roadmap  
**Target:** Windows 10 22H2 x64 and Windows 11 x64  
**Goal:** Reproduce the current Linux NETA functionality through MS3.x using the same portable evidence model, assurance rules, history, baselines, export, and replay semantics.

## 1. Definition of Windows parity

Windows parity means **semantic parity**, not identical operating-system mechanisms.

The Windows backend must produce the same portable NETA concepts wherever the operating system can prove them:

- connection discovery;
- process attribution;
- explicit direction: `OUTBOUND`, `INBOUND`, `UNKNOWN`;
- connection lifecycle;
- TCP transport evidence;
- route/interface evidence;
- host/network-environment evidence;
- application resolver evidence and DNS-to-connection correlation;
- actual application TLS-session evidence;
- outbound TLS server identity;
- inbound authenticated mTLS client identity;
- Trust and Performance decisions;
- baselines;
- bounded SQLite history;
- export and deterministic replay.

A Windows collector must never fabricate Linux-equivalent values when Windows cannot provide the same evidence. Unsupported or unavailable evidence remains explicitly unavailable.

The portable architecture remains:

```text
LifecycleObserver
        |
        v
ConnectionAdmissionPolicy
        |
        v
ConnectionTracker
        |
        v
EvidenceScheduler
        |
        v
HistoryStore
```

Platform-specific implementations sit below these interfaces.

---

# Milestone W0 — Portable-core boundary cleanup

## Goal

Make the existing core genuinely operating-system-neutral before adding Windows collectors.

## Work

1. Remove remaining Linux kernel/UAPI headers and Linux TCP numeric constants from portable core code.
2. Move Linux-specific state mapping into `src/platform/linux/`.
3. Introduce or finalize platform-neutral interfaces for:
   - lifecycle observation;
   - socket/connection snapshots;
   - process identity;
   - TCP transport evidence;
   - route/interface evidence;
   - host/network-environment evidence;
   - resolver observation;
   - TLS-session observation.
4. Preserve the existing portable evidence structures where they already express the required semantics.
5. Add explicit capability reporting for evidence that a platform cannot provide.
6. Ensure unavailable evidence remains `unknown/unavailable`, never a synthetic zero or false value.
7. Keep Performance and Trust semantics independent.
8. Preserve existing SQLite, baseline, export, replay, and rule-engine behavior.

## Acceptance criteria

- Linux still builds and passes existing regression tests.
- `NETA_EBPF=OFF` portable validation still works.
- Portable/core code has no Windows- or Linux-specific networking constants.
- A stub Windows backend can compile against the same core interfaces.

**Estimated effort:** 2–3 engineering days.

---

# Milestone W1 — Windows build and runtime foundation

## Goal

Produce a native `neta-agent.exe` using the existing core.

## Work

1. Add Windows CMake/build targets.
2. Create `src/platform/windows/`.
3. Add Windows error/result translation into portable NETA error semantics.
4. Implement Windows timestamps and monotonic-time helpers.
5. Implement process creation/start identity primitives.
6. Add Windows capability enumeration.
7. Establish SQLite database paths and file handling.
8. Preserve the existing CLI behavior where meaningful on Windows.
9. Initially support elevated console execution.
10. Prepare for later Windows Service operation.

## Target platforms

- Windows 10 22H2 x64
- Windows 11 x64

Windows Server can be validated after desktop parity is stable.

## Acceptance criteria

- `neta-agent.exe` builds natively.
- Basic CLI, database creation, storage status, history, export, and replay run on Windows.
- Core unit tests run on Windows.

**Estimated effort:** 2–3 days.

---

# Milestone W2 — TCP connection discovery and process attribution

## Goal

Reproduce Linux connection enumeration and ownership.

## Primary Windows mechanisms

- IP Helper API
- `GetExtendedTcpTable()`
- Windows process APIs

## Work

1. Enumerate IPv4 TCP connections.
2. Enumerate IPv6 TCP connections.
3. Capture:
   - local address;
   - local port;
   - remote address;
   - remote port;
   - TCP state;
   - owning PID.
4. Resolve PID to process metadata:
   - executable;
   - process creation identity;
   - available user/security identity;
   - command/process name where permitted.
5. Distinguish listening sockets from connected sockets.
6. Keep listeners as listener/service metadata, not normal connection-history objects.
7. Feed connected sockets through the existing admission/tracker pipeline.

## Acceptance criteria

For a normal Windows client connection NETA records:

```text
process
PID
process creation identity
local IP:port
remote IP:port
TCP state
```

without duplicate connection-history objects.

**Estimated effort:** 2–3 days.

---

# Milestone W3 — Exact/strong Windows TCP lifecycle and direction

## Goal

Move beyond polling and obtain Linux-like connect/accept/close semantics.

## Primary Windows mechanism

**ETW** TCP/IP lifecycle observation, with TCP-table reconciliation.

WFP should remain a fallback only if ETW cannot prove required lifecycle semantics.

## Work

1. Add an ETW lifecycle collector.
2. Capture outbound connect events.
3. Capture inbound accepted-connection events where the provider gives sufficient evidence.
4. Capture close/lifecycle termination.
5. Correlate events with:
   - PID/process-start identity;
   - local/remote tuple;
   - timestamps;
   - available ETW connection identity.
6. Build a stable Windows connection-identity strategy.
7. Reconcile event-driven observations with TCP-table snapshots.
8. Preserve the NETA rules:
   - local connect → `OUTBOUND`;
   - local accept → `INBOUND`;
   - ambiguous direction → `UNKNOWN`;
   - never infer direction from conventional port numbers;
   - listener is not an ordinary connection object;
   - accepted connected socket is an inbound assurance object.
9. Make ETW event loss/backpressure observable.
10. Ensure short-lived sockets are not silently missed when ETW evidence exists.

## Acceptance criteria

Local deterministic tests prove:

```text
client connect -> OUTBOUND
server accept  -> INBOUND
listener       -> not stored as ordinary CONN-x
close          -> lifecycle reflected correctly
```

No ambiguous correlation is guessed.

**Estimated effort:** 4–7 days.

---

# Milestone W4 — Windows TCP transport/performance evidence

## Goal

Reproduce the existing Linux TCP evidence as far as Windows can actually expose it.

## Primary Windows mechanisms

- TCP Extended Statistics (EStats)
- IP Helper APIs
- ETW where useful for event/counter enrichment

## Work

Map available Windows evidence into the portable NETA transport model, including where supported:

- RTT;
- RTT variation or nearest valid Windows equivalent;
- retransmissions;
- congestion/window information;
- byte counters;
- TCP state;
- other existing Performance inputs.

Every field must carry truthful availability/fidelity.

## Acceptance criteria

A Windows connection produces real observed TCP evidence and the existing Performance engine consumes it without Windows-specific rule duplication.

If a Linux metric has no semantically equivalent Windows source, the field is explicitly unavailable.

**Estimated effort:** 3–5 days.

---

# Milestone W5 — Route, interface, and MS3.4 host/network-environment identity

## Goal

Implement the Windows equivalent of route/interface context and MS3.4 environment identity.

## Primary Windows mechanisms

Windows IP Helper and system/network configuration APIs.

## Work

Capture per connection:

- selected interface;
- interface identity/index;
- source address;
- current route toward the peer;
- next hop/default gateway where applicable;
- route metric where useful.

Capture host/environment evidence such as:

- Windows version/build;
- stable host identity appropriate for the NETA model;
- boot/session identity where supported;
- interface identities and types;
- configured addresses;
- DNS server configuration;
- current network environment/profile;
- virtual/VPN interface indicators where reliably detectable.

For inbound connections, route evidence retains the existing meaning:

> the current host response route toward the remote peer.

## Acceptance criteria

`history show` on Windows presents the same conceptual route/interface/environment evidence consumed by the portable core.

**Estimated effort:** 3–4 days.

---

# Milestone W6 — Windows DNS resolver observation and connection correlation

## Goal

Reproduce MS3.1 semantics: observe application name resolution and connect the result to the actual TCP connection.

## Candidate Windows mechanisms

- Windows DNS Client ETW provider;
- documented Windows resolver APIs where event metadata is insufficient;
- application instrumentation only if required for exact API-level fidelity.

## Work

1. Observe DNS queries.
2. Attribute them to the originating process where provable.
3. Capture returned/resolved addresses where exposed.
4. Preserve query timestamps.
5. Correlate resolver evidence with subsequent TCP connections using:
   - process identity;
   - returned address;
   - time window;
   - connection tuple.
6. Retain correlation grades rather than overstating certainty.
7. Keep ambiguous correlation unresolved.
8. Clearly distinguish:
   - `EXACT`;
   - `STRONGLY_CORRELATED`;
   - weaker evidence;
   - unavailable evidence.

## Acceptance criteria

A deterministic Windows client test can show a connection with resolver evidence attached to the correct connection and no incorrect attachment to competing connections.

The implementation must not label ETW-derived evidence `EXACT` unless the evidence proves the exact semantic claim.

**Estimated effort:** 4–7 days.

---

# Milestone W7 — OpenSSL application TLS sessions on Windows

## Goal

Reproduce MS3.2 first for Windows applications that use OpenSSL.

## Linux behavior to preserve

Current Linux MS3.2 observes actual application OpenSSL sessions and supports handshakes completed through explicit handshake calls and through `SSL_read*` / `SSL_write*` I/O paths.

The Windows implementation must preserve equivalent semantics:

- TLS role;
- version;
- cipher;
- SNI;
- peer certificate presence;
- verification result;
- expected/matched peer identity where available;
- leaf SHA-256;
- SPKI SHA-256;
- exact-once session emission;
- association with the actual connection;
- no TLS MITM/proxying.

## Work

1. Build a Windows OpenSSL observation/instrumentation mechanism.
2. Support explicit:
   - `SSL_connect`;
   - `SSL_accept`;
   - `SSL_do_handshake`.
3. Support I/O-driven completion through:
   - `SSL_read`;
   - `SSL_read_ex`;
   - `SSL_write`;
   - `SSL_write_ex`.
4. Preserve application-visible OpenSSL behavior and errors.
5. Emit one completed-session event per live `SSL*`.
6. Clean state on `SSL_free`.
7. Correlate the TLS session with the Windows connection identity.
8. Support both outbound client and inbound server roles.
9. Do not claim support for Schannel/.NET/BoringSSL applications in this milestone.

## Acceptance criteria

A Windows OpenSSL client demonstrates:

```text
relation=OUTBOUND_SERVER_IDENTITY
observation=EXACT
correlation=EXACT
TLS version
cipher
SNI
peer certificate
verification
leaf SHA-256
SPKI SHA-256
```

A Windows OpenSSL server emits exact server-side session evidence.

**Estimated effort:** 5–10 days.

---

# Milestone W8 — Windows OpenSSL inbound mTLS Trust parity

## Goal

Reproduce MS3.3 using the Windows OpenSSL evidence from W7.

## Reused portable functionality

The existing Trust engine should remain common code:

- exact-session-only inbound mTLS Trust policy;
- per-principal accepted-client baselines;
- `STABLE`;
- `CHANGED`;
- `UNVERIFIED`;
- `SUSPICIOUS`;
- baseline hashes;
- rule-set provenance;
- deterministic replay.

## Work

1. Feed Windows inbound OpenSSL client-certificate evidence into the existing schema.
2. Preserve:
   - subject/principal;
   - issuer;
   - SPKI;
   - authentication/verification state.
3. Support existing baseline operations such as:
   - `baseline accept-client`;
   - `baseline show-client`.
4. Verify baseline matching and changed-identity behavior.
5. Ensure Windows and Linux produce equivalent Trust outcomes for equivalent evidence.

## Acceptance criteria

Windows deterministic mTLS scenario:

```text
authenticated + no accepted baseline
    -> UNVERIFIED

accept-client
    -> baseline created

same accepted identity
    -> STABLE

same principal + changed issuer/SPKI
    -> CHANGED

certificate verification failure
    -> SUSPICIOUS

ambiguous/non-exact TLS identity
    -> UNVERIFIED
```

**Estimated effort:** 3–5 days.

---

# Milestone W9 — Broad native Windows TLS support: Schannel / SSPI

## Goal

Move beyond OpenSSL-only applications and support the dominant native Windows TLS stack.

This is required for **broad Windows support**, because many Windows applications do not use OpenSSL.

## Scope

Investigate and implement a passive, evidence-first collector for applications using:

- Schannel;
- SSPI;
- and Windows networking stacks layered on them where evidence can be reliably associated with a process/connection.

Potential application families include:

- WinHTTP;
- WinINet;
- native Windows services;
- software using Schannel directly.

## Required evidence, where Windows can prove it

- client/server TLS role;
- TLS version;
- cipher;
- SNI/target identity where visible;
- peer certificate identity;
- chain/verification result where available;
- leaf fingerprint;
- SPKI fingerprint;
- connection association;
- inbound client certificate for mTLS when exposed.

## Rule

Do not call evidence `EXACT` unless the collection mechanism proves that it came from the actual application TLS session.

## Acceptance criteria

At least one native Schannel client and one Schannel server/mTLS test produce trustworthy application-session evidence mapped into the same portable TLS schema.

Existing Trust logic works without a separate Windows Trust engine.

**Estimated effort:** 2–4+ weeks.

This is the largest uncertainty in broad Windows parity.

---

# Milestone W10 — Additional Windows TLS/runtime coverage

## Goal

Close important gaps left by OpenSSL + Schannel.

## Candidate stacks

Evaluate based on actual NETA user/application coverage:

- .NET `SslStream` when not sufficiently covered through Schannel-level observation;
- Chromium/BoringSSL;
- applications statically linking OpenSSL;
- other TLS implementations encountered in production.

## Policy

Do not create fragile hooks merely to claim universal TLS support.

Each collector must declare:

```text
collector
evidence source
supported library/runtime versions
fidelity
known blind spots
```

Unsupported applications remain explicitly unsupported for exact application TLS identity while still receiving network/process/route/TCP evidence.

## Acceptance criteria

A documented Windows TLS capability matrix exists and each supported runtime has deterministic tests.

**Estimated effort:** open-ended; roughly 1–3+ weeks per major additional mechanism depending on instrumentation difficulty.

---

# Milestone W11 — Windows service, privilege model, and operational hardening

## Goal

Turn the development executable into a normal long-running Windows agent.

## Work

1. Add Windows Service execution.
2. Define least-privilege requirements.
3. Use `LocalSystem` only if required; otherwise prefer a narrower service identity.
4. Secure local IPC between CLI and privileged collector/service if separated.
5. Protect database/configuration/baseline files with appropriate ACLs.
6. Handle service startup/shutdown cleanly.
7. Handle suspend/resume and interface changes.
8. Handle user logon/logoff and process churn.
9. Preserve bounded memory and bounded SQLite storage.
10. Add observable collector failure/degradation states.
11. Ensure event-source loss cannot silently become “no evidence.”

## Acceptance criteria

The Windows agent runs unattended through reboot and network changes without corrupting history or creating misleading lifecycle records.

**Estimated effort:** 4–7 days.

---

# Milestone W12 — Cross-platform schema, export, replay, and parity validation

## Goal

Prove that Windows is another evidence producer for the same NETA assurance product, not a separate implementation.

## Work

1. Verify Windows evidence persists in the existing SQLite model or a backward-compatible schema evolution.
2. Verify bounded database cleanup.
3. Verify baseline operations.
4. Verify export.
5. Verify deterministic replay.
6. Replay Windows-generated evidence on Linux where the replay engine is platform-independent.
7. Replay Linux-generated evidence on Windows where applicable.
8. Confirm equal semantic inputs produce equal Trust/Performance results.
9. Preserve rule-set/version provenance.
10. Add a platform capability manifest to exports if necessary.

## Acceptance criteria

Equivalent portable evidence produces equivalent decisions independent of where replay occurs.

**Estimated effort:** 3–5 days.

---

# Milestone W13 — Windows 10/11 end-to-end parity suite

## Goal

Declare first supported Windows release only after deterministic end-to-end validation.

## Required test environments

- Windows 10 22H2 x64
- Windows 11 x64

Later:

- Windows Server 2019/2022/2025
- Windows ARM64

## Required test scenarios

### Outbound

1. application resolves hostname;
2. resolver evidence observed;
3. TCP connect observed;
4. process identified;
5. direction = `OUTBOUND`;
6. TCP evidence collected;
7. route/interface evidence collected;
8. TLS application session captured for a supported TLS stack;
9. TLS evidence attached to the correct connection;
10. history stored;
11. export generated;
12. replay returns `MATCH`.

### Inbound

1. server listener exists;
2. listener itself is not stored as an ordinary connection;
3. client connects;
4. accepted connection is observed;
5. server process identified;
6. direction = `INBOUND`;
7. response-route evidence collected;
8. supported TLS/mTLS session captured;
9. client identity evaluated;
10. baseline workflow tested;
11. Trust result persisted;
12. export/replay returns `MATCH`.

### Lifecycle stress

- very short-lived connections;
- rapid repeated same-tuple usage;
- PID reuse;
- simultaneous DNS queries;
- simultaneous connections to the same address;
- interface change;
- VPN connect/disconnect;
- suspend/resume;
- event loss/backpressure;
- agent shutdown while sockets remain alive.

## Acceptance criteria

No known semantic regression relative to the supported Linux feature set, subject to the published Windows capability matrix.

**Estimated effort:** 4–7 days.

---

# Milestone W14 — Windows Server and ARM64 expansion

## Goal

Broaden platform coverage after x64 desktop parity.

## Windows Server

Validate:

- service operation;
- server workloads;
- high inbound connection rates;
- Schannel server TLS;
- mTLS;
- multiple NICs/routes;
- server security policy interactions.

Target:

- Windows Server 2019
- Windows Server 2022
- Windows Server 2025

## ARM64

1. Build Windows ARM64.
2. Validate SQLite/OpenSSL components used by NETA.
3. Validate Windows native collectors.
4. Validate process and TLS instrumentation architecture differences.
5. Run the same semantic E2E suite.

**Estimated effort:** 1–2 weeks after x64 Windows implementation is mature.

---

# Implementation order

The recommended dependency order is:

```text
W0  Portable core cleanup
 |
 v
W1  Native Windows build
 |
 v
W2  TCP tables + process attribution
 |
 v
W3  ETW lifecycle + direction
 |
 +----------+
 |          |
 v          v
W4 TCP      W5 Route + MS3.4
 |          |
 +----+-----+
      |
      v
W6 DNS resolver correlation
      |
      v
W7 OpenSSL TLS
      |
      v
W8 OpenSSL inbound mTLS Trust
      |
      v
W9 Schannel/SSPI broad TLS
      |
      v
W10 Additional TLS/runtime coverage
      |
      v
W11 Windows service/hardening
      |
      v
W12 Cross-platform replay/parity
      |
      v
W13 Windows 10/11 E2E acceptance
      |
      v
W14 Server + ARM64 expansion
```

---

# Delivery levels

## Level A — First useful Windows NETA

Includes approximately:

- W0–W5;
- native Windows build;
- TCP discovery;
- process attribution;
- inbound/outbound visibility;
- lifecycle;
- TCP performance evidence;
- routes/interfaces;
- MS3.4 environment identity;
- existing history/storage/core rules.

**Expected effort:** approximately 2–3 weeks.

This is already a useful Windows network-assurance agent, but it does not yet reproduce MS3.1–MS3.3 application-level evidence.

---

## Level B — Linux-like parity for OpenSSL applications

Includes:

- W0–W8;
- DNS correlation;
- exact OpenSSL TLS sessions;
- exact outbound server TLS identity;
- inbound OpenSSL mTLS identity;
- existing Trust policy;
- export/replay.

**Expected total effort:** approximately 6–9 engineering weeks for one engineer.

This is the closest practical definition of direct parity with the current Linux MS3 implementation because Linux MS3.2/MS3.3 are themselves OpenSSL-specific.

---

## Level C — Broad Windows parity

Includes:

- W0–W13;
- OpenSSL;
- Schannel/SSPI;
- native Windows applications;
- operational Windows Service;
- capability matrix;
- Windows 10/11 deterministic acceptance.

**Expected total effort:** approximately 2–3 months for one engineer, with TLS instrumentation being the largest uncertainty.

Additional runtimes such as BoringSSL or application-specific TLS stacks may extend this.

---

# Compatibility target

Initial supported matrix:

| Platform | Target |
|---|---|
| Windows 10 22H2 x64 | Supported compatibility target |
| Windows 11 x64 | Primary supported/test platform |
| Windows Server 2019 | Follow-up validation |
| Windows Server 2022 | Follow-up validation |
| Windows Server 2025 | Follow-up validation |
| Windows ARM64 | Later expansion |

The same NETA semantic core should be used on every platform.

---

# Non-negotiable correctness rules

Windows support must preserve the current NETA evidence-first guarantees:

1. Never infer direction from port numbers.
2. Do not turn listeners into ordinary connection-history objects.
3. Do not guess ambiguous connection, DNS, or TLS correlations.
4. Do not convert unavailable evidence to zero/false.
5. Make collector event loss/backpressure observable.
6. Preserve deterministic Trust and Performance decisions.
7. Preserve deterministic export/replay.
8. Preserve bounded local storage.
9. Keep actual application TLS evidence distinct from active-probe TLS evidence.
10. Use the same portable evidence model and rule engine across Linux and Windows.
11. Platform capability differences must be explicit.
12. A Windows implementation must not claim `EXACT` evidence unless its source proves that exact semantic relation.

---

# Expected final architecture

```text
                         NETA portable core
                                |
          +---------------------+----------------------+
          |                     |                      |
   ConnectionTracker      EvidenceScheduler      Assurance Engine
          |                     |               Performance / Trust
          +---------------------+----------------------+
                                |
                         Platform interfaces
                        /                   \
                       /                     \
                 Linux backend           Windows backend
                 -------------           ---------------
                 eBPF lifecycle          ETW lifecycle
                 procfs/socket APIs      IP Helper tables
                 Linux TCP info          TCP EStats
                 netlink/route           IP Helper route APIs
                 glibc resolver shim     DNS ETW / resolver evidence
                 OpenSSL .so shim        OpenSSL Windows collector
                                        Schannel/SSPI collector
                                |
                                v
                          Common evidence model
                                |
                                v
                    SQLite / Baselines / History
                                |
                                v
                       Export / Replay / CLI
```

The target is therefore **not** two separate NETA products.

It is:

> **one portable assurance engine, one evidence schema, one history/replay model, and OS-specific collectors that make only the claims their evidence can prove.**

---

## Source basis and planning status

This roadmap is based on the current NETA project architecture and MS3 status:

- the core architecture requires `LifecycleObserver -> ConnectionAdmissionPolicy -> ConnectionTracker -> EvidenceScheduler -> HistoryStore`;
- portable core code must not depend on Linux kernel/UAPI details;
- direction, listener handling, ambiguity handling, unavailable-evidence semantics, deterministic replay, bounded storage, and Performance/Trust separation are existing project invariants;
- current MS3.1 provides resolver correlation;
- current MS3.2 provides exact actual OpenSSL application TLS sessions, including I/O-driven handshake completion;
- current MS3.3 provides exact-session-only inbound mTLS Trust policy, per-principal baselines, schema-5 export, and deterministic replay;
- MS3.4 is the next Linux milestone for host/network-environment identity.

The `W*` milestones above are a proposed Windows execution plan derived from those existing requirements. Windows-specific collector choices are implementation proposals and should be validated against the exact semantics and reliability observed during implementation.
