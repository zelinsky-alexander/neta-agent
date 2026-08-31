# Milestone 3: stronger connection identity and exact application context where available

Milestone 3 reduces uncertainty between a transport socket, name-resolution identity, and cryptographic/application identity without changing the product rule: `neta-agent` observes evidence and states its fidelity honestly; it does not infer exactness from coincidence.

This work extends the completed MS2 bidirectional architecture. MS2 invariants remain requirements: explicit `OUTBOUND`/`INBOUND`/`UNKNOWN` direction, listener exclusion, canonical socket-cookie promotion only after unambiguous correlation, bounded active state and SQLite retention, lifecycle-drop visibility, and no reuse of the outbound supporting TLS probe as inbound or actual-application TLS evidence.

## Implemented MS3.1: application name-resolution context

The Linux resolver path observes dynamically linked glibc `getaddrinfo()` calls with libbpf uprobes/uretprobes, then correlates successful forward-resolution results to outbound connections by process, durable process start identity, network namespace, returned remote address, direction, and a bounded time window.

A complete `getaddrinfo` event can be `EXACT` for the application resolver API call. It is not an exact DNS packet claim because NSS, `/etc/hosts`, a local cache, or another configured backend may satisfy the call. `PlatformCapabilities::exact_dns_observation` therefore remains false.

Resolver-to-socket correlation is at most `STRONGLY_CORRELATED`. Multiple plausible resolver events remain `AMBIGUOUS` and are not attached. Collector and ObservationSession buffers are bounded, event loss is visible, and only correlated per-connection evidence is persisted.

## Implemented MS3.2: actual OpenSSL application TLS sessions

MS3.2 adds opt-in OpenSSL 3 application instrumentation that observes the real TLS session used by the application. It does not proxy, redirect, decrypt, terminate, or create a substitute connection.

```text
instrumented application
        |
        | SSL_connect / SSL_accept / SSL_do_handshake
        | SSL_read[_ex] / SSL_write[_ex] completed-handshake state
        | SSL BIO read/write completed-handshake state
        v
libneta_tls_context.so
        |
        | OpenSSL public session/certificate APIs
        | SO_COOKIE + socket endpoints
        | bounded Unix datagram evidence event
        v
TlsSessionObserver
        |
        | SCM_CREDENTIALS sender validation
        v
ObservationSession
        |
        | exact cookie correlation when available
        | bounded tuple/process/netns/time fallback otherwise
        v
HistoryStore connection_tls_session_evidence
```

Only a completed handshake on a stream socket is emitted, including one driven implicitly by
OpenSSL read or write APIs or by an OpenSSL SSL BIO (`BIO_f_ssl`). The BIO path records a direct
socket-BIO-to-`SSL*` association only when the documented `SSL_set_bio` ownership-transfer API
supplies that socket BIO; a later internal `BIO_read`/`BIO_write` on an unassociated socket BIO
does not produce TLS evidence. Replacing BIOs or `SSL_free` removes the association before pointer
reuse can be observed. Each live `SSL*` emits at most once; `SSL_free` removes that deduplication
state. The shim calls the real OpenSSL function first, preserves `errno`,
isolates its OpenSSL error-queue use, contains exceptions inside the C ABI boundary, and sends
evidence non-blockingly so instrumentation failure cannot fail the application handshake.

### Exact session facts

Where available, an application-session observation contains:

```text
local TLS role: CLIENT / SERVER
process PID / UID / durable start ticks / comm
network namespace
Linux SO_COOKIE
local and remote socket endpoint
TLS protocol version
cipher
selected ALPN
SNI
expected / matched peer hostname
peer certificate presence
peer verification mode/result
peer-authenticated boolean
peer leaf certificate SHA-256
peer public-key/SPKI SHA-256
peer subject / issuer / validity interval
```

For outbound client sessions, `peer_authenticated=true` requires a peer certificate, `X509_V_OK`, an expected peer hostname, and an OpenSSL matched peer hostname.

For inbound server sessions, `peer_authenticated=true` requires a peer certificate, `SSL_VERIFY_PEER`, and `X509_V_OK`.

A peer certificate may therefore be exactly observed without being authenticated.

### TLS-to-connection correlation

When the application's TLS socket has the same Linux socket cookie as the canonical connection and process/direction/non-conflicting netns identity agree, correlation is `EXACT`.

A valid cookie mismatch rejects correlation; the correlator does not fall back to a coincidental tuple. Without a cookie, role/direction, exact tuple, process, non-conflicting start identity/netns, and bounded time are required, and the result is capped at `STRONGLY_CORRELATED`.

Multiple plausible matches remain `AMBIGUOUS` and are not attached.

Direction-aware relations are:

```text
CLIENT + peer certificate  -> OUTBOUND_SERVER_IDENTITY
CLIENT + no peer cert      -> OUTBOUND_TLS_SESSION
SERVER + peer certificate  -> INBOUND_CLIENT_IDENTITY
SERVER + no peer cert      -> INBOUND_TLS_SESSION
```

## Implemented MS3.3: inbound authenticated identity / mTLS Trust policy

MS3.3 turns the exact inbound TLS evidence from MS3.2 into an explicit versioned Trust policy. It does not silently reuse the old outbound supporting-probe rule.

The current rule set is:

```text
neta-rules/0.2.0
```

Historical `neta-rules/0.1.0` remains available to replay older bundles exactly.

### Policy source requirements

Inbound client identity affects Trust only when the application TLS evidence itself and the TLS-to-connection correlation are both `EXACT`.

`STRONGLY_CORRELATED`, `SUPPORTING`, `CONTEXTUAL`, missing, or ambiguous application-session evidence cannot establish an inbound client identity verdict.

### Deterministic inbound Trust mapping

```text
no inbound TLS application evidence
    -> UNVERIFIED / INBOUND_TLS_EVIDENCE_UNAVAILABLE

inbound TLS observed but not EXACT
    -> UNVERIFIED / INBOUND_TLS_EVIDENCE_NOT_EXACT

multiple exact inbound TLS identities
    -> UNVERIFIED / INBOUND_CLIENT_IDENTITY_AMBIGUOUS

no client certificate
    -> UNVERIFIED / INBOUND_CLIENT_CERTIFICATE_ABSENT

certificate presented but not authenticated
    -> UNVERIFIED / INBOUND_CLIENT_CERTIFICATE_NOT_AUTHENTICATED

verification required + known non-X509_V_OK result
    -> SUSPICIOUS / INBOUND_CLIENT_CERTIFICATE_VERIFICATION_FAILURE

authenticated certificate but no usable certificate subject
    -> UNVERIFIED / INBOUND_CLIENT_PRINCIPAL_UNAVAILABLE

authenticated principal not explicitly accepted
    -> UNVERIFIED / INBOUND_CLIENT_IDENTITY_NOT_ACCEPTED

accepted principal + matching issuer and SPKI
    -> STABLE

accepted principal + changed issuer or SPKI
    -> CHANGED / INBOUND_CLIENT_IDENTITY_CHANGE
```

Certificate presence alone never produces `STABLE`.

### Principal and accepted identity model

An inbound service may legitimately have many mTLS clients, so MS3.3 does not store one client identity for the whole service.

The accepted baseline is scoped per:

```text
service UID
+ stable service process identity (executable path when available, otherwise comm)
+ network namespace when available
+ local service port
+ exact client certificate subject
```

The client certificate subject is the principal key. The accepted cryptographic identity is:

```text
issuer + SPKI SHA-256
```

This permits client A and client B to both be accepted independently for the same service. If client A later presents the same principal subject with a different issuer or SPKI, the result is `CHANGED`. A never-accepted client C is `UNVERIFIED`, not mislabeled as client A changing.

PID and process start ticks are deliberately not part of the durable accepted-service key so a normal service restart does not invalidate accepted client principals.

### Explicit acceptance workflow

An operator accepts an observed client only from an already captured inbound connection:

```bash
neta-agent baseline accept-client CONN_ID --db neta.db
```

Acceptance is refused unless the selected connection has exactly one exact, presented, authenticated client certificate with a usable subject and SPKI.

The command stores an immutable `Baseline` row using the existing baseline storage and immediately re-evaluates the selected connection under `neta-rules/0.2.0`.

Inspect the currently accepted identity for the selected principal with:

```bash
neta-agent baseline show-client CONN_ID --db neta.db
```

Using immutable baseline rows preserves the existing property that a historical verdict retains the exact baseline hash used for its decision even after a later identity acceptance/rotation.

### Automatic inbound finalization

At the end of `observe --inbound` or `observe --all`, every admitted inbound connection is finalized under the MS3.3 policy.

The agent derives the exact inbound TLS context, derives that principal's service-scoped baseline key when possible, loads the latest accepted baseline for that principal, evaluates Trust, and persists the verdict.

Inbound Performance remains `INSUFFICIENT_EVIDENCE` under this MS3.3 path. MS3.3 changes only inbound authenticated-identity Trust semantics; it does not invent a new inbound performance baseline model.

### Rule-set compatibility

`neta-rules/0.2.0` retains the existing outbound target performance and supporting-probe Trust behavior while adding the inbound exact-session policy.

`neta-rules/0.1.0` remains replayable and reports inbound authenticated-identity policy as unavailable rather than retroactively applying the new semantics to old evidence.

### Export/replay schema 5

MS3.3 raises export schema to version 5.

Schema 5 retains schema-3 resolver and schema-4 TLS-session evidence integrity fields and adds the inputs required to replay an inbound Trust decision:

```text
baseline_present / baseline_kind
baseline target key / local service port / baseline hash
accepted SPKI / accepted issuer
inbound TLS observed / exact / ambiguous flags
client certificate present
peer verification required
verify-result presence/value
peer authenticated
client subject
client issuer
client SPKI
exact inbound TLS evidence hash
```

Replay chooses the rule set recorded in the bundle. Schema 1-4 bundles remain accepted under their historical rule version; schema 5 inbound bundles replay with the exact persisted policy inputs.

Tampering with the inbound client identity changes the verdict input hash and causes deterministic replay mismatch.

## Local TLS evidence channel and provenance

The shim sends fixed-size bounded events over a local Unix datagram endpoint. The default endpoint is:

```text
@neta-agent-tls-uid-<uid>
```

Both observer and instrumented application may override it with:

```text
NETA_TLS_CONTEXT_SOCKET=@custom-name
```

The receiver requires kernel-supplied `SCM_CREDENTIALS`; payload PID/UID must equal the actual sender credentials. Receiver buffers and unresolved-event queues are bounded, malformed/credential-mismatched events are rejected and counted, and receive-queue overflow is exposed where supported.

Dropped/rejected evidence means application TLS evidence may be incomplete. It is never interpreted as proof that no TLS session occurred.

## Running a supported instrumented application

A normal dynamic build produces:

```text
build/neta-agent
build/libneta_tls_context.so
```

For a root observer and a non-root application/service, use an explicit shared endpoint:

```bash
sudo env NETA_TLS_CONTEXT_SOCKET=@neta-ms3-test \
  ./build/neta-agent observe --inbound --duration 30 --db ./db/neta.db

NETA_TLS_CONTEXT_SOCKET=@neta-ms3-test \
LD_PRELOAD="$PWD/build/libneta_tls_context.so" \
  ./supported-openssl-application
```

Instrumentation is explicit and opt-in.

## Coverage limitations

Actual-session TLS coverage currently applies only to supported dynamically linked OpenSSL 3 applications that execute the instrumented public handshake/read/write entry points, or use an SSL BIO whose stream socket was supplied through `SSL_set_bio`.

It does not claim exact application TLS coverage for:

- uninstrumented applications;
- statically linked OpenSSL;
- BoringSSL, LibreSSL, GnuTLS, rustls, NSS, Schannel, Secure Transport, or custom TLS stacks;
- QUIC/DTLS/UDP;
- inaccessible local evidence endpoints;
- authentication performed entirely outside the observable OpenSSL verification configuration.

Unsupported coverage remains unavailable rather than becoming a false exact claim.

The shim is disabled for static-dependency/full-static builds because `LD_PRELOAD` does not apply to that deployment model.

## Relationship to the legacy active TLS probe

The existing `TlsProbe` remains a separate connection:

```text
neta-agent -> separate OpenSSL connection -> target
```

It remains `SUPPORTING` outbound target evidence only. It is never used as actual inbound TLS/client identity evidence.

MS3.3 therefore has direction-aware Trust inputs:

```text
OUTBOUND target-mode Trust
    -> existing SUPPORTING independent active probe

INBOUND client-identity Trust
    -> EXACT actual application TLS session only
```

## Regression expectations

MS3.3 must preserve:

- MS0 controlled baseline/netem/certificate/replay behavior;
- MS1 lifecycle semantics and drop visibility;
- MS2 direction, listener exclusion, bounded state/storage, and service-mode invariants;
- MS3.1 resolver evidence integrity;
- MS3.2 actual-session TLS evidence, sender validation, correlation anti-misassociation, and schema-4 compatibility;
- `NETA_EBPF=OFF` build/test behavior for the non-eBPF core/TLS receiver paths.

Focused MS3.3 coverage includes:

- no TLS evidence;
- no client certificate;
- presented but unauthenticated certificate;
- verification failure;
- authenticated but unaccepted principal;
- accepted stable principal;
- changed SPKI;
- changed issuer;
- missing principal subject;
- weak correlation refusing Trust promotion;
- ambiguous exact evidence refusing Trust promotion;
- historical rule-set behavior;
- principal key stability across PID/start-time changes;
- principal/service separation across different client subjects and network namespaces;
- schema-5 outbound and inbound export/replay;
- TLS evidence tamper detection;
- inbound policy-input tamper detection.

## Remaining MS3 work after MS3.3

The remaining major MS3 areas are:

1. richer stable, privacy-conscious host/network-environment identity;
2. controlled native-Linux end-to-end acceptance for supported collectors where normal CI cannot exercise privileged BPF attachment;
3. optional HTTP/RPC/span correlation as higher-layer evidence;
4. additional resolver or TLS backends only where source, coverage, fidelity, resource cost, and licensing can be stated precisely.

The intended MS3 finish line remains direction-aware connection assurance with correlated resolver context, actual application TLS identity where supported, authenticated inbound client identity, stable host/network context, explicit fidelity, deterministic replay, and native-Linux validation.
