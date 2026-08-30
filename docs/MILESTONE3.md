# Milestone 3: stronger connection identity and exact application context where available

Milestone 3 reduces uncertainty between a transport socket, name-resolution identity, and cryptographic/application identity without changing the core product rule: `neta-agent` observes evidence and states its fidelity honestly; it does not infer exactness from coincidence.

This implementation starts from the completed MS2 bidirectional architecture on `main`. MS2 invariants remain requirements: explicit `OUTBOUND`/`INBOUND`/`UNKNOWN` direction, listener exclusion, canonical socket-cookie promotion only after unambiguous correlation, bounded active state and SQLite retention, lifecycle-drop visibility, and no reuse of the outbound supporting TLS probe as inbound application-session evidence.

## First implementation slice

The first MS3 slice adds the portable name-resolution evidence and correlation layer:

```text
future native/application resolver event
              |
              v
   NameResolutionObservation
      exact event semantics
              |
              v
 correlate_name_resolution()
   process + start identity
   network namespace
   resolved remote address
   bounded event-to-connect time
   direction-aware policy
              |
       +------+------+
       |             |
   unique match   ambiguous/no match
       |             |
       v             v
STRONGLY_CORRELATED  unresolved
or lower fidelity
       |
       v
HistoryStore per-connection evidence
       |
       v
bounded by existing connection retention
```

New portable types live in `include/neta/name_resolution.hpp` and do not depend on Linux UAPI headers.

A `NameResolutionObservation` records:

- start and completion timestamps;
- forward/reverse/unknown query kind;
- mechanism (`APPLICATION_RESOLVER_API`, `SYSTEM_RESOLVER_EVENT`, `APPLICATION_PROVIDED`, or unknown);
- event-time process context;
- optional network-namespace identity;
- queried name and optional canonical name;
- returned addresses;
- the fidelity of the observation itself;
- a mechanism/source label.

The initial correlator links only **forward lookups to outbound connections**. It requires the same agent-visible process, a returned address equal to the connection remote address, a completed lookup before connection admission, and a bounded maximum age (default five seconds). Conflicting durable process-start or network-namespace identities reject a candidate.

If more than one lookup satisfies the rules, the result is `AMBIGUOUS` and no evidence is attached. The implementation never chooses the nearest timestamp or otherwise guesses.

## Fidelity semantics

Two fidelity questions are kept separate:

1. **Was the name-resolution event itself observed exactly?**
2. **How confidently can that event be attributed to this socket?**

A future application resolver hook may legitimately mark an observed resolver API call as `EXACT` for that API event. That still does **not** prove that a DNS packet was sent: NSS, `/etc/hosts`, local caches, or another resolver backend may have satisfied the request.

The socket correlation produced by this first slice is therefore never `EXACT`:

```text
exact/strong resolver event
+ matching PID and durable process start
+ matching network namespace
+ returned address equals remote socket address
+ unique bounded-time candidate
    -> STRONGLY_CORRELATED

missing durable identity component
    -> SUPPORTING

context-only source
    -> CONTEXTUAL

multiple plausible lookup events
    -> AMBIGUOUS / no link
```

This preserves the roadmap rule that configured hostnames or temporal proximity alone must not be presented as exact application DNS attribution.

## Persistence and MS2 storage guarantees

Correlated evidence is stored per connection in two lazily-created SQLite tables:

```text
connection_name_resolution_evidence
connection_name_resolution_addresses
```

Both are owned by the connection through foreign keys with `ON DELETE CASCADE`. When the existing MS2 storage-maintenance policy prunes a connection, its MS3 name-resolution rows are removed as well. The initial design intentionally does not persist an unbounded global stream of uncorrelated resolver events.

The API is:

```cpp
HistoryStore::add_name_resolution_evidence(...)
HistoryStore::name_resolution_evidence_for_connection(...)
```

Existing export/replay and verdict hashes are not changed by this first slice. Name-resolution evidence does not yet affect Performance or Trust verdicts.

## Capability honesty

This slice does **not** claim a live exact DNS collector. `PlatformCapabilities::exact_dns_observation` remains `false`.

The next Linux implementation step should add a capability-advertised resolver event source. A likely mechanism is bounded instrumentation of a supported resolver API such as dynamically-linked glibc `getaddrinfo`, capturing the queried name and returned addresses with explicit coverage limitations. Such an event would describe an application resolver API call, not automatically a network DNS transaction.

Unsupported runtimes (for example static binaries or resolver implementations not covered by the selected mechanism) must remain explicitly unsupported rather than silently downgraded into an exact claim.

## Next MS3 slices

After the resolver collector is proven and integrated with the observation session:

1. surface correlated name-resolution evidence in `evidence`, export, and replay without changing old-bundle compatibility;
2. add exact TLS/session evidence only where an OS or application mechanism observes the real application session;
3. keep outbound server identity and inbound authenticated client identity as separate relations;
4. add optional HTTP/RPC/span correlation as higher-layer evidence, never as a prerequisite for transport assurance;
5. enrich host/network-environment identity with stable, privacy-conscious provenance suitable for longitudinal comparison.

## Regression requirements

Every MS3 change must continue to pass the MS0/MS1/MS2 regression suite. In particular:

- no listener may become an ordinary connection-history row;
- inbound and outbound direction semantics must not change;
- ambiguous cookie or resolver correlation must remain unresolved;
- target-mode supporting TLS behavior must remain unchanged;
- inbound/all modes must not gain fake TLS identity;
- lifecycle drop health and bounded tracker/scheduler state must remain intact;
- SQLite growth from MS3 evidence must remain bounded by connection retention.

The first slice adds focused deterministic tests for unique/ambiguous resolver correlation, direction isolation, identity-fidelity downgrade, persistence round-trip, idempotent evidence update, and delete cascade.
