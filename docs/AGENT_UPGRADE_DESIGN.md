# NETA Agent Upgrade Design

## Goal

NETA agents must be remotely upgradeable by the coordinator without turning the coordinator/agent channel into arbitrary remote execution.

The coordinator selects an exact immutable target artifact. The agent downloads only that artifact, verifies it, stages it, activates it through a narrowly scoped privileged updater, performs a local health check, rolls back automatically on failure, reports bounded progress, and finally reconnects with exact build identity so the coordinator can confirm the upgrade.

This design applies to both Linux and Windows agents. The protocol, build identity, durable state, artifact validation, and progress reporting are shared. Only installation/service activation and rollback mechanics are platform-specific.

## End-to-end lifecycle

```text
operator
   |
   v
coordinator resolves exact version/commit/platform artifact
   |
   v
REQUESTED
   |
   v
agent heartbeat / AgentHello receives typed upgrade instruction
   |
   v
agent validates + persists instruction
   |
   v
DOWNLOADING
   |
   v
SHA-256 verified artifact
   |
   v
INSTALLING
   |
   v
platform updater activates staged version
   |
   v
local health check
   |\
   | \ failure
   |  -> rollback previous version -> ROLLED_BACK / FAILED
   v
LOCAL_HEALTHY
   |
   v
new process restarts and reports exact build identity
   |
   v
coordinator verifies exact expected version/build/commit/platform/artifact hash
   |
   v
CONFIRMED
```

Coordinator confirmation is intentionally separate from local health. A process that merely starts is not considered successfully upgraded until the restarted agent reports the exact immutable target expected by the coordinator.

## Coordinator instruction contract

The coordinator can include this optional object in successful `AgentHello` or `Heartbeat` responses:

```json
{
  "upgrade": {
    "upgrade_id": "uuid",
    "version": "1.4.0",
    "build_id": "20260905.1",
    "git_commit": "full-40-character-commit",
    "os": "linux",
    "arch": "arm64",
    "artifact_name": "neta-agent-1.4.0-linux-arm64.tar.gz",
    "download_url": "https://github.com/...",
    "sha256": "64-hex-digest"
  }
}
```

The same immutable instruction may be repeated while the coordinator considers the request delivered. Repetition must be idempotent. If the same `upgrade_id` is ever repeated with different immutable target fields, the agent must reject it.

## A1 - exact build identity

Every running agent reports a `payload.build` object on `AgentHello` and `Heartbeat`.

Required runtime identity:

```text
version
build_id
git_commit when available
build_timestamp
os
arch
protocol_version
schema_version
features
artifact_sha256 when installed from a release artifact
```

The executable receives version/build/commit/platform metadata at build time. The final package SHA cannot normally be embedded into the binary before packaging, so the installed version also has a small updater-owned metadata record containing the exact artifact SHA-256. The runtime combines compiled identity with that installed artifact metadata.

Canonical platform names used for upgrade matching are:

```text
linux/amd64
linux/arm64
windows/amd64
```

Windows ARM64 can be added later without changing the protocol.

## A2 - typed instruction parsing and policy validation

The agent parses the optional `upgrade` response object into a typed `UpgradeInstruction`.

Before any local state changes, validate:

- `upgrade_id` is a UUID;
- target version and build ID are non-empty;
- `git_commit` is a full 40-character hexadecimal commit;
- target OS and architecture exactly match the running agent;
- artifact name is a single safe file name;
- URL uses HTTPS;
- URL is hosted on approved GitHub/GitHubusercontent release infrastructure;
- SHA-256 is exactly 64 hexadecimal characters;
- the target is not already the running exact build.

The agent never resolves `latest`, a branch name, or a release tag itself. Mutable source references are resolved and pinned by the coordinator before the instruction reaches the endpoint.

## A3 - durable local upgrade state

Upgrade state must survive the service restart that is part of a successful upgrade.

Initial location:

```text
Linux:   /var/lib/neta/identity/upgrade/current.json
Windows: <agent state dir>\upgrade\current.json
```

The state record snapshots the immutable coordinator instruction plus local progress, download path, and a bounded last error.

Initial A1-A4 local states:

```text
RECEIVED
DOWNLOADING
VERIFIED
FAILED
```

Later activation work extends this model with staging/activation/health/rollback state as needed.

State writes use temp-file + rename semantics. A repeated instruction with the same ID and identical target is an idempotent no-op. A different active upgrade is rejected until the current local attempt reaches an appropriate terminal state.

## A4 - secure artifact download and verification

The agent downloads the exact coordinator-provided artifact; it does not run Git, compilers, package managers, or repository update commands.

Security requirements:

- HTTPS only;
- system CA validation;
- hostname verification and SNI;
- trusted GitHub/GitHubusercontent hosts only;
- HTTPS redirects only and every redirect host revalidated;
- redirect count bounded;
- download size bounded (default 256 MiB initially);
- artifact name cannot contain path separators or traversal components;
- partial download uses a temporary `.part` file;
- exact SHA-256 verified before the artifact becomes eligible for staging;
- pre-existing cached artifact is reused only after re-verifying its exact SHA-256.

A4 does not activate the downloaded artifact. Activation is intentionally blocked until the A5/A6 updater and rollback path exist.

## A5 - versioned installation and privileged updater

The running agent should not overwrite its own executable at the critical activation point. A small narrowly scoped privileged helper performs activation.

### Linux target layout

```text
/opt/neta-agent/
  versions/
    <build-id>/
      neta-agent
      build metadata
      supporting libraries
  current  -> versions/<active-build>
  previous -> versions/<previous-build>
```

`/usr/local/bin/neta-agent` should resolve to the active version rather than being destructively overwritten.

A Linux helper such as `/usr/local/libexec/neta-agent-updater` will:

1. validate a staged upgrade owned by NETA;
2. stop/allow the current service process to exit;
3. preserve the old active target as `previous`;
4. atomically switch `current`;
5. start `neta-agent.service`;
6. enforce a health timeout;
7. restore `previous` if health fails.

### Windows target layout

```text
C:\Program Files\NETA\
  versions\
    <build-id>\
      neta-agent.exe
      build metadata
      supporting DLLs
  current\
  previous\
```

The exact indirection mechanism may use directory junctions or another Windows-safe atomic layout, but the invariant is the same: never destroy the only known-good version.

A narrowly scoped `neta-agent-updater.exe` will stop the NETA Windows Service, switch the active version, start the service, enforce health, and rollback on failure. It must not expose arbitrary command execution.

## A6 - local health and automatic rollback

Upgrade health must be deterministic and machine-oriented. Existing human-readable Linux health scripts remain useful operationally, but the updater needs a stable programmatic health contract.

A future command/API such as:

```text
neta-agent health --upgrade
```

should validate at least:

- process starts correctly;
- configuration loads;
- SQLite database opens;
- fleet identity loads;
- required platform monitoring components initialize without fatal error;
- TLS/fleet reporting subsystem initializes;
- installed build metadata matches the executable identity expected for that staged version.

On success, the agent reports `LOCAL_HEALTHY`. On failure or timeout, the updater restores the previous version and restarts it.

## A7 - coordinator progress reporting

The agent sends the coordinator's typed `UpgradeProgress` message using the same authenticated fleet channel, sequence discipline, and mTLS identity as other agent messages.

Coordinator-facing progress states:

```text
DOWNLOADING
INSTALLING
LOCAL_HEALTHY
FAILED
ROLLED_BACK
```

Failure messages remain bounded and machine-readable through a stable failure code, for example:

```text
INVALID_INSTRUCTION
PLATFORM_MISMATCH
DOWNLOAD_FAILED
DOWNLOAD_TOO_LARGE
TLS_VERIFICATION_FAILED
SHA256_MISMATCH
STAGING_FAILED
ACTIVATION_FAILED
HEALTH_CHECK_FAILED
ROLLBACK_FAILED
```

Progress transmission must be retry-safe. The coordinator enforces ownership and legal state transitions.

## Shared architecture

The upgrade domain should remain portable and separated from platform activation:

```text
UpgradeManager
   |
   +-- BuildIdentity
   +-- UpgradeStateStore
   +-- ArtifactDownloader / verifier
   +-- UpgradeReporter
   |
   +-- PlatformUpgradeBackend
           |
           +-- LinuxUpgradeBackend
           +-- WindowsUpgradeBackend
```

Linux kernel headers, systemd details, Windows SCM APIs, junction handling, or other OS-specific behavior must not leak into the portable upgrade state/protocol layer.

## Packaging

Production coordinator-managed upgrades use prebuilt immutable artifacts, not local source builds.

Expected release asset family:

```text
neta-agent-<version>-linux-amd64.tar.gz
neta-agent-<version>-linux-arm64.tar.gz
neta-agent-<version>-windows-amd64.zip
release-manifest.json
release-manifest.sig   # planned hardening
```

The current manual `deploy/linux/install-or-update.sh` remains appropriate for developer/manual installation, but it is not the runtime self-upgrade mechanism because it performs Git/build/package-manager operations and overwrites the installed binary directly.

## Security boundaries

The upgrade path must preserve these invariants:

- no arbitrary remote shell or generic command execution;
- coordinator chooses one immutable target artifact;
- endpoint never follows mutable Git refs;
- endpoint never disables TLS certificate verification;
- endpoint verifies exact artifact SHA before staging;
- activation is only through the dedicated NETA updater helper;
- previous known-good version is retained until confirmation;
- local health is not equivalent to coordinator confirmation;
- coordinator confirms only exact restarted build identity;
- rollback must remain possible without coordinator connectivity.

Signed release-manifest verification is a planned hardening layer in addition to the exact SHA already distributed by the coordinator.

## Implementation sequence

### Current side branch scope: A1-A4

`feature/agent-upgrade-a1-a4` establishes:

1. generated cross-platform build identity;
2. typed C7 upgrade instruction parsing and validation;
3. durable local upgrade request state with retry-safe acceptance;
4. bounded HTTPS artifact download and exact SHA-256 verification;
5. tests on both Linux and Windows CI for the portable core.

Receiving an instruction may persist it, but this phase intentionally does **not** self-activate a downloaded executable.

### Next phase: A5-A7

1. package/versioned installation layout;
2. Linux updater helper and systemd integration;
3. Windows updater helper and Windows Service integration;
4. deterministic local health contract;
5. automatic rollback and watchdog timeout;
6. `UpgradeProgress` reporting;
7. full coordinator-to-agent integration testing.

## Acceptance tests

### Successful Linux upgrade

```text
request linux/arm64 release
-> instruction received
-> exact artifact downloaded and verified
-> new version staged
-> updater switches current
-> service starts
-> LOCAL_HEALTHY
-> restarted AgentHello reports exact new build
-> coordinator CONFIRMED
```

Repeat for linux/amd64.

### Successful Windows upgrade

```text
request windows/amd64 release
-> instruction received
-> exact ZIP downloaded and verified
-> new version staged
-> Windows updater switches active version
-> service starts
-> LOCAL_HEALTHY
-> restarted AgentHello reports exact new build
-> coordinator CONFIRMED
```

### Rollback test on both platforms

```text
request intentionally unhealthy target
-> artifact verifies and installs
-> local health fails or times out
-> updater restores previous version
-> previous agent restarts
-> ROLLED_BACK
-> coordinator must never mark the broken target CONFIRMED
```

### Security tests

Reject:

- wrong platform;
- malformed/full-commit mismatch metadata;
- non-HTTPS URL;
- non-GitHub redirect;
- oversized artifact;
- path-traversal artifact name;
- SHA mismatch;
- changed immutable fields for an already accepted `upgrade_id`;
- simultaneous second active upgrade.
