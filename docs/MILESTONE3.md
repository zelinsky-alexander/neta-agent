# Milestone 3: stronger connection identity and exact application context where available

Milestone 3 reduces uncertainty between a transport socket, name-resolution identity, and cryptographic/application identity without changing the product rule: `neta-agent` observes evidence and states its fidelity honestly; it does not infer exactness from coincidence.

This work extends the completed MS2 bidirectional architecture. MS2 invariants remain requirements: explicit `OUTBOUND`/`INBOUND`/`UNKNOWN` direction, listener exclusion, canonical socket-cookie promotion only after unambiguous correlation, bounded active state and SQLite retention, lifecycle-drop visibility, and no reuse of the outbound supporting TLS probe as inbound or actual-application TLS evidence.

## Implemented MS3.1: application name-resolution context

The Linux resolver path observes dynamically linked glibc `getaddrinfo()` calls with libbpf uprobes/uretprobes, then correlates successful forward-resolution results to outbound connections by process, durable process start identity, network namespace, returned remote address, direction, and a bounded time window.

A complete `getaddrinfo` event can be `EXACT` for the application resolver API call. It is not an exact DNS packet claim because NSS, `/etc/hosts`, a local cache, or another configured backend may satisfy the call. `PlatformCapabilities::exact_dns_observation` therefore remains false.

Resolver-to-socket correlation is at most `STRONGLY_CORRELATED`. Multiple plausible resolver events remain `AMBIGUOUS` and are not attached.

The resolver collector and ObservationSession buffers are bounded, event loss is visible, and only per-connection correlated evidence is persisted. Existing connection pruning cascades to resolver evidence.

## Implemented MS3.2: actual OpenSSL application TLS sessions

MS3.2 adds an opt-in OpenSSL 3 application instrumentation mechanism that observes the real TLS session used by the application. It does not proxy, redirect, decrypt, terminate, or create a substitute connection.

```text
instrumented application
        |
        | real SSL_connect / SSL_accept / SSL_do_handshake
        v
libneta_tls_context.so
        |
        | OpenSSL public session/certificate APIs
        | Linux socket identity (SO_COOKIE + endpoints)
        | bounded Unix datagram evidence event
        v
TlsSessionObserver
        |
        | kernel SCM_CREDENTIALS sender validation
        v
ObservationSession
        |
        | exact cookie correlation when available
        | tuple/process/netns/time fallback otherwise
        v
HistoryStore connection_tls_session_evidence
        |
        +--> evidence CLI
        +--> export schema 4
        +--> replay integrity
```

### Native/application observation source

The instrumentation library is built from:

```text
src/platform/linux/tls_context_shim.cpp
```

It interposes the public OpenSSL handshake entry points:

```text
SSL_connect
SSL_accept
SSL_do_handshake
```

Only a successful handshake on a stream socket is emitted. Immediately after the real handshake returns successfully, the shim queries the same `SSL*` and socket with public OpenSSL/Linux APIs.

The shim preserves application behavior:

- it calls the real OpenSSL function first;
- it preserves and restores `errno`;
- post-handshake evidence extraction is isolated from the application's OpenSSL error queue;
- if an existing OpenSSL error queue cannot be safely marked/restored, evidence extraction is skipped;
- C++ exceptions from observational work are contained inside the shim and never cross the OpenSSL C ABI;
- evidence transport is non-blocking and failure to deliver evidence does not fail the TLS handshake.

### Exact session facts captured

Where available, the exact application-session observation contains:

```text
local TLS role: CLIENT / SERVER
process PID / UID / durable start ticks / comm
network namespace
Linux SO_COOKIE
local and remote socket endpoint
TLS protocol version
cipher
selected ALPN
SNI visible to OpenSSL
expected peer hostname configured in OpenSSL
matched peer hostname reported by OpenSSL verification
peer certificate presence
peer verification mode/result
peer-authenticated boolean under conservative rules
peer leaf certificate SHA-256
peer public-key/SPKI SHA-256
peer subject / issuer / validity interval
```

Certificate hashes are derived from the certificate actually returned by the application's `SSL` session, not from the independent `TlsProbe` connection.

### Identity is not the same as authentication

A peer certificate may be exactly observed without being authenticated.

For an outbound client session, `peer_authenticated=true` is emitted only when:

```text
peer certificate present
+ SSL_get_verify_result() == X509_V_OK
+ an expected peer hostname was configured in OpenSSL
+ OpenSSL reports a matched peer hostname
```

For an inbound server session, `peer_authenticated=true` is emitted only when:

```text
peer certificate present
+ SSL_VERIFY_PEER is enabled
+ SSL_get_verify_result() == X509_V_OK
```

This intentionally underclaims applications that perform custom verification outside the supported OpenSSL verification configuration. MS3 does not infer authentication from certificate presence alone.

## Exact TLS-to-connection correlation

MS3.2 uses the Linux socket cookie from the application's actual TLS socket when available.

```text
actual SSL socket
    |
    +--> SO_COOKIE = 12345
    |
connection history
    +--> canonical socket_cookie = 12345

same process + non-conflicting durable identity/netns + correct direction
    -> EXACT connection correlation
```

A TLS event with a valid cookie that does not match a connection cookie is rejected for that connection. The correlator does not fall back to a coincidental tuple after a cookie mismatch.

If `SO_COOKIE` is unavailable, the fallback requires:

- correct TLS local role mapped to connection direction (`CLIENT -> OUTBOUND`, `SERVER -> INBOUND`);
- exact local/remote endpoint tuple;
- same process;
- non-conflicting durable process-start identity;
- non-conflicting network namespace;
- event time within the connection and bounded tuple-correlation window.

That fallback is capped at `STRONGLY_CORRELATED`. Multiple possible matches are `AMBIGUOUS` and no evidence is persisted.

### Direction-aware semantic relations

MS3.2 keeps transport-session and peer-identity semantics explicit:

```text
CLIENT + peer certificate  -> OUTBOUND_SERVER_IDENTITY
CLIENT + no peer cert      -> OUTBOUND_TLS_SESSION
SERVER + peer certificate  -> INBOUND_CLIENT_IDENTITY
SERVER + no peer cert      -> INBOUND_TLS_SESSION
```

`INBOUND_CLIENT_IDENTITY` means an exact peer certificate was presented on the actual accepted TLS session. Whether that identity was authenticated is separately represented by `peer_authenticated`.

This is the evidence foundation for the dedicated inbound/mTLS policy work that follows; MS3.2 itself does not invent a new inbound Trust verdict rule.

## Local evidence channel and provenance

The shim sends a fixed-size bounded event over a local Unix datagram socket. The default endpoint is an abstract Unix socket scoped by UID:

```text
@neta-agent-tls-uid-<uid>
```

Both `neta-agent` and the instrumented application may override it with:

```text
NETA_TLS_CONTEXT_SOCKET=@custom-name
```

The receiver enables `SO_PASSCRED` and requires kernel-supplied `SCM_CREDENTIALS`. Payload PID/UID must equal the kernel sender PID/UID or the event is rejected. This prevents a different local process from simply asserting another process identity in the evidence payload.

The receiver is bounded:

- 1 MiB requested socket receive buffer;
- at most 256 decoded events per poll;
- `ObservationSession` holds at most 4,096 unresolved TLS-session observations;
- malformed, truncated, or credential-mismatched events are rejected and counted;
- receive-queue overflow is exposed where Linux provides `SO_RXQ_OVFL`.

A dropped/rejected event means TLS evidence may be incomplete; it is never interpreted as proof that no TLS session occurred.

## Running an instrumented application

A normal dynamic build produces the agent and the optional instrumentation library:

```text
build/neta-agent
build/libneta_tls_context.so
```

Start the observer normally, then opt a supported OpenSSL application into exact session evidence:

```bash
sudo ./build/neta-agent observe --outbound --duration 30 --db ./db/neta.db

LD_PRELOAD="$PWD/build/libneta_tls_context.so" \
  curl https://example.com/
```

For a long-lived service, the same preload can be configured in that service's environment. `NETA_TLS_CONTEXT_SOCKET` must match the observer if a non-default endpoint is used.

Instrumentation is explicit and opt-in. Uninstrumented applications continue to receive all existing transport/lifecycle/route/resolver evidence, and target mode retains the independent supporting TLS probe.

## Coverage limitations

MS3.2 currently claims actual-session TLS coverage only for supported dynamically linked OpenSSL 3 applications that execute the instrumented public handshake entry points and use an ordinary stream socket accessible through `SSL_get_fd()`.

It does not claim exact application TLS coverage for:

- applications not launched with the instrumentation library;
- statically linked OpenSSL;
- BoringSSL, LibreSSL, GnuTLS, rustls, NSS, Schannel, Secure Transport, or custom TLS implementations;
- TLS stacks that do not expose the real socket through the supported OpenSSL APIs;
- QUIC/DTLS/UDP;
- processes in environments where the local Unix evidence endpoint is not reachable;
- application authentication performed entirely outside the observable OpenSSL verification configuration.

Unsupported coverage stays unavailable rather than being downgraded into a false exact claim.

The shim is disabled for builds requesting static OpenSSL dependencies or a fully static executable. This avoids pretending the `LD_PRELOAD` mechanism applies to a static deployment model.

## Relationship to the legacy TLS probe and Trust verdict

The existing `TlsProbe` remains unchanged:

```text
neta-agent -> separate OpenSSL connection -> target
```

It remains `SUPPORTING` evidence only.

MS3.2 stores actual application-session evidence as a separate evidence class and does **not** silently alter the established Performance/Trust rule set or verdict input hash. Therefore:

```text
current Trust verdict
    -> still uses the existing versioned supporting-probe input

MS3.2 exact application TLS evidence
    -> independently inspectable and replay-integrity checked
    -> future Trust rule changes require an explicit rule-set/version decision
```

This preserves previously validated MS0/MS1/MS2 verdict/replay behavior while adding stronger evidence.

## Persistence

Actual-session evidence is persisted in:

```text
connection_tls_session_evidence
```

The row is owned by its connection with `ON DELETE CASCADE`, so existing storage maintenance also bounds MS3.2 evidence.

Repeated instrumentation callbacks for the same session are idempotently deduplicated by a deterministic session identity key. The persisted evidence retains a separate deterministic evidence hash for export/replay integrity.

## Evidence CLI, export, and replay

`neta-agent evidence ID` presents actual application TLS evidence separately from the independent active probe. It reports the role/relation, observation and correlation fidelity, TLS version/cipher/ALPN/SNI, peer-certificate hashes, verification result, and authentication status.

Export schema version 4 adds `TLS_SESSION` evidence records plus:

```text
tls_session_count
tls_session_hash
```

Replay verifies the deterministic set of exported TLS-session hashes separately from the existing verdict replay. Schema versions 1-3 remain accepted; they report TLS application-session evidence as not present.

Name-resolution schema-3 integrity behavior is unchanged.

## Build and regression behavior

No new third-party dependency is introduced. MS3.2 uses the existing OpenSSL 3 dependency, C++20, SQLite, Linux socket APIs, and the standard dynamic loader facilities already used by the project.

Normal dynamic builds include `libneta_tls_context.so`. `NETA_EBPF=OFF` still builds and tests the TLS-session receiver/correlation path because MS3.2 does not depend on eBPF. The resolver collector remains unavailable in that configuration exactly as before.

Focused MS3.2 coverage includes:

- exact socket-cookie correlation;
- strongly-correlated tuple fallback;
- cookie mismatch refusing tuple fallback;
- ambiguity remaining unresolved;
- outbound/inbound role isolation;
- inbound peer-certificate relation semantics;
- partial-event fidelity downgrade;
- sender-credential validation and malformed-wire rejection;
- SQLite round-trip/idempotence/delete cascade;
- `ObservationSession` attachment;
- export/replay integrity and tamper detection;
- a real non-privileged OpenSSL client/server handshake executed with `LD_PRELOAD` instrumentation.

## Remaining MS3 work after MS3.2

The remaining major MS3 areas are:

1. dedicated direction-aware Trust policy for inbound authenticated client identity/mTLS, if that evidence should affect deterministic verdicts;
2. richer stable, privacy-conscious host/network-environment identity;
3. optional HTTP/RPC/span correlation as higher-layer evidence;
4. additional resolver or TLS backends only where source, coverage, fidelity, resource cost, and licensing can be stated precisely;
5. controlled native-Linux end-to-end acceptance for supported collectors where CI cannot exercise privileged BPF attachment.

Every later MS3 change must preserve the same rule: stronger attribution is added only when the native/application observation source and fidelity are explicit.
