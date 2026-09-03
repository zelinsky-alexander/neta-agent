# YARA-X Linux Integration Foundation

Status: side-branch implementation design

Branch: `feature/process-artifact-assurance-yarax`

Last reviewed: 2026-09-03

## Goal

Start NETA's Process & Artifact Assurance work with a provider model that is portable in the core but implemented only for Linux in the current repository. YARA-X is the first concrete antimalware provider. The design intentionally supports multiple providers contributing independent evidence to the same artifact/process timeline.

This is not an attempt to turn NETA into a conventional antivirus product. Antimalware findings remain evidence that NETA can correlate with execution, file provenance, memory transitions, DNS/TLS/network activity, baseline state, and later cooperative/fleet evidence.

## What is cross-platform in this slice

The following concepts are platform-neutral and live in the portable NETA API:

- `ArtifactIdentity`;
- normalized antimalware scan states;
- `AntimalwareMatch` and `AntimalwareEvidence`;
- `AntimalwareProvider` interface;
- `AntimalwareProviderSet` fan-out composition;
- provider/ruleset provenance fields;
- the rule that provider output is evidence rather than a final trust verdict.

YARA-X itself provides C/C++ support for Linux, macOS, and Windows. Therefore the provider abstraction and most of the YARA-X userspace scanning logic can be reused when NETA gains non-Linux backends.

## What is Linux-only now

The repository currently rejects non-Linux CMake builds, and the concrete YARA-X provider is currently under `src/platform/linux/`.

Linux-only or Linux-specific work includes:

- discovering and linking `yara_x_capi` through `pkg-config`;
- the future `sched_process_exec` eBPF trigger;
- file-lifecycle eBPF/LSM triggers;
- mmap/mprotect/LSM memory-anomaly triggers;
- `/proc` or `process_vm_readv` based memory collection;
- Linux device/inode/mount-namespace artifact identity;
- any future BPF LSM enforcement path.

The first implementation does not pretend these mechanisms are portable.

## Current branch implementation

The side branch adds:

1. `AntimalwareProvider` — one normalized provider boundary.
2. `AntimalwareProviderSet` — runs all enabled providers and preserves every result independently.
3. `YaraXProvider` — optional Linux provider using the official YARA-X C API.
4. `NETA_YARA_X=AUTO|ON|OFF` CMake selection.
5. Graceful `UNSUPPORTED` evidence when YARA-X is not available in the build.
6. Bounded artifact reads and a YARA-X scan timeout.
7. Rule-set SHA-256 provenance.
8. Focused provider-composition tests that do not require YARA-X to be installed.

The YARA-X backend is intentionally optional. `AUTO` discovers `yara_x_capi`; `ON` makes its absence a configuration error; `OFF` always builds the unsupported stub.

## Why providers are composed rather than merged into one verdict

Different engines answer different questions. NETA should retain their evidence separately:

```text
Artifact / process
      |
      +--> YARA-X             pattern/rule evidence
      +--> Platform AV        vendor/native malware verdict
      +--> Reputation         hash/reputation evidence
      +--> Runtime detector   behavior/anomaly evidence
      |
      v
normalized evidence set
      |
      v
NETA deterministic correlation rules
```

Do not use majority voting. A `NO_MATCH` from one provider must not cancel a high-confidence `MATCH` from another provider, and absence of a match is never proof that an artifact is safe.

Useful deterministic combinations include:

```text
YARA-X high-confidence malware-family match
+ second independent signature/reputation match
    -> very strong artifact evidence

YARA-X suspicious-loader match
+ executable first seen
+ new DNS/TLS destination shortly after exec
    -> strong correlated host/network finding

YARA-X no match
+ platform AV malware verdict
    -> retain both results; do not downgrade the platform AV finding

YARA-X match
+ anonymous RW->RX memory transition
+ new outbound connection
    -> strong process-injection/fileless-style correlation
```

Provider confidence and semantic category should eventually be explicit rather than inferred only from provider name.

## Other providers/frameworks to combine with YARA-X

### Platform-native antimalware provider

This should be the preferred second provider on operating systems that expose a supported antimalware/reputation API.

Future examples:

- Windows: a Microsoft-supported Defender/AMSI/security API integration where the API semantics actually fit artifact scanning.
- macOS: supported Apple security/EndpointSecurity mechanisms where appropriate.
- Linux: there is no single universal native AV API equivalent, so Linux remains provider/plugin oriented.

This provider category is portable at the semantic interface but necessarily platform-specific in implementation.

### ClamAV as an optional external provider

ClamAV can add conventional malware-signature coverage that complements YARA-X. However, `libclamav` is GPL-2.0 and must not be embedded or linked into `neta-agent` under the current dependency policy.

If ClamAV support is added, prefer a separately installed `clamd` service and a small protocol adapter. This still requires explicit license/distribution review, but it avoids making `libclamav` part of the NETA binary.

Potential combination:

```text
YARA-X -> custom/curated structural and threat rules
clamd  -> conventional known-malware signatures
NETA   -> process/file/memory/network correlation
```

### Hash/reputation provider

A provider can query a configured local or remote reputation source using artifact SHA-256. This is useful because it is independent of local pattern matching.

Requirements:

- disabled by default if it sends hashes or metadata off-host;
- explicit privacy/operator policy;
- bounded caching;
- source and response provenance;
- no file upload without explicit separate opt-in;
- deterministic treatment of unavailable/rate-limited services.

### Runtime behavior provider

Falco is Apache-2.0 and useful as a source of behavioral-security concepts, but embedding the whole Falco stack is not recommended because NETA already owns an eBPF observation pipeline.

Prefer one of:

1. consume selected external Falco findings through an adapter; or
2. implement the small set of runtime signals NETA actually needs with its existing eBPF architecture.

These signals should be represented as runtime evidence, not disguised as YARA/antimalware matches.

## Provider categories

The normalized model should evolve toward explicit evidence categories:

```text
SIGNATURE_MATCH
STRUCTURAL_RULE_MATCH
REPUTATION_KNOWN_MALICIOUS
PLATFORM_AV_DETECTION
RUNTIME_BEHAVIOR_ANOMALY
MEMORY_RULE_MATCH
PROVIDER_ERROR
```

This gives the deterministic rule engine meaningful semantics while still retaining the original provider name, version, rule/database identity, and raw match metadata.

## Linux build sequence

### Slice 1 — provider foundation (this branch)

- portable provider API;
- multi-provider fan-out;
- optional YARA-X C API backend;
- normalized result states;
- bounded file scan;
- rule-set hash provenance;
- focused tests;
- no automatic connection verdict changes.

### Slice 2 — executable identity and manual validation

- stable artifact identity: path + device/inode + size + SHA-256;
- result cache keyed by `(artifact_sha256, provider, provider_version, ruleset_hash)`;
- a small CLI/debug path to scan one artifact and print normalized evidence;
- test rule set for deterministic integration tests.

### Slice 3 — eBPF exec trigger

- `sched_process_exec` observation;
- stable `PROC-*` process identity rather than PID-only state;
- asynchronous userspace scan request;
- `PROC-* -> artifact -> YARA-X evidence` linkage;
- correlation with existing `CONN-*` observations.

### Slice 4 — file provenance

- filtered write/close lifecycle tracking;
- race-safe artifact reopening/identity verification;
- writer process -> artifact -> later exec relation;
- scan newly materialized executable payloads.

### Slice 5 — memory triggers

- selected mmap/mprotect/LSM telemetry;
- RW->RX/RWX/anonymous executable memory signals;
- bounded userspace memory reads;
- YARA-X block scanning;
- no synchronous userspace scan on the LSM critical path.

### Slice 6 — additional providers and deterministic fusion rules

- second provider adapter;
- explicit evidence categories/confidence;
- rules combining independent provider evidence with exec/file/memory/network evidence;
- persistence/export/replay.

## Enforcement boundary

Detection comes first. BPF LSM can deny operations, but a fresh YARA-X userspace scan must not be inserted synchronously into an exec LSM decision path.

Possible later enforcement:

```text
artifact previously scanned/classified
      -> classification cached in policy map
      -> later exec LSM hook checks known classification
      -> allow or deny
```

This is separate, opt-in work after detection semantics are stable.

## Dependency review

### YARA-X

- Project: VirusTotal YARA-X
- Purpose: pattern/rule scanning for file and selected memory content
- License: BSD-3-Clause
- Maintenance: active; YARA-X is the forward-development direction of the YARA ecosystem
- Major concern: rules and hostile inputs must be resource-bounded; transitive dependencies and exact release artifacts require normal release review
- Why existing stack is insufficient: libbpf observes events but does not provide malware content matching; OpenSSL/SQLite are unrelated to malware rule scanning

Official integration API used: YARA-X C/C++ API (`yara_x_capi`).

### ClamAV

- Purpose: known-malware/signature coverage
- License: GPL-2.0
- Maintenance: active
- Major concern: incompatible with the current policy for embedding/linking GPL code
- Recommendation: do not link `libclamav`; consider only a separately installed daemon adapter after explicit license review

### Falco

- Purpose: runtime behavioral detections
- License: Apache-2.0
- Maintenance: active
- Major concern: architectural overlap and weight, not license incompatibility
- Recommendation: consume selected findings or reuse concepts rather than embedding the full stack initially

## Cross-platform future mapping

| Capability | Linux now | Windows later | macOS later |
|---|---|---|---|
| Provider API | Yes | Reusable | Reusable |
| YARA-X userspace file scanning | Yes | Technically reusable | Technically reusable |
| Exec trigger | eBPF `sched_process_exec` | Windows-native process telemetry required | EndpointSecurity/native telemetry required |
| File write provenance | eBPF/LSM/VFS | Windows-native file/minifilter telemetry required | EndpointSecurity/native telemetry required |
| Memory anomaly trigger | eBPF/LSM | Windows-native telemetry/driver path required | Platform-specific mechanisms required |
| YARA-X selected-memory scan | Linux process memory collection | Different memory-access implementation | Different memory-access implementation |
| LSM-style enforcement | BPF LSM | Different Windows enforcement architecture | Different Apple enforcement architecture |

The portable provider/evidence model should be reused. The event collectors and enforcement mechanisms should not be artificially abstracted as if the kernels expose equivalent primitives.

## Current non-goals

This branch does not yet:

- automatically scan every exec;
- persist antimalware evidence in SQLite;
- modify Trust verdicts;
- scan process memory;
- monitor file writes;
- embed ClamAV/Falco;
- download community YARA rules automatically;
- implement blocking/prevention;
- implement Windows or macOS collectors.

These omissions are deliberate so the first integration remains reviewable and does not destabilize the existing socket-assurance path.
