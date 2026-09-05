# NETA Agent Upgrade Design

## Goal

NETA agents are remotely upgradeable by the coordinator without turning the coordinator/agent channel into arbitrary remote execution.

The coordinator selects one exact immutable target artifact. The agent validates and persists that instruction, downloads only the pinned artifact, verifies its SHA-256, installs it into a versioned location, activates it through a narrowly scoped updater, performs deterministic local health checks, rolls back automatically on failure, and reports bounded progress. The restarted agent then reports exact build identity; only the coordinator may mark the upgrade `CONFIRMED`.

The protocol, build identity, durable state, artifact policy, health contract, and progress model are shared by Linux and Windows. Service control and activation mechanics are platform-specific.

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
AgentHello / Heartbeat response carries immutable upgrade instruction
   |
   v
agent validates + durably persists instruction
   |
   v
DOWNLOADING
   |
   v
HTTPS download + exact SHA-256 verification
   |
   v
INSTALLING
   |
   v
detached privileged updater installs versioned package
   |
   v
switch active version + restart service
   |
   v
local deterministic health check
   |\
   | \ failure/timeout
   |  -> restore previous version -> restart -> ROLLED_BACK / FAILED
   v
LOCAL_HEALTHY
   |
   v
restarted agent reports exact build identity
   |
   v
coordinator checks expected version/build/commit/platform/artifact SHA
   |
   v
CONFIRMED
```

Local health and coordinator confirmation are intentionally different. A process that starts is not a successful fleet upgrade until the coordinator sees the exact immutable target it requested.

## Security model

The upgrade path is deliberately narrower than remote administration.

The coordinator may provide only a typed upgrade target. It cannot provide a shell command, executable arguments, arbitrary filesystem path, mutable Git ref, package-manager command, or installation script.

Core invariants:

- no arbitrary remote command execution;
- coordinator sends one immutable target artifact;
- target OS/architecture must exactly match the running agent;
- endpoint accepts HTTPS only;
- endpoint accepts approved GitHub/GitHubusercontent artifact hosts only;
- every redirect is revalidated;
- exact SHA-256 is verified before installation;
- download size and redirect count are bounded;
- artifact filename cannot contain traversal/path components;
- activation is performed only by the dedicated NETA updater;
- a previous known-good installation is retained for rollback;
- rollback does not depend on coordinator connectivity;
- agent may report bounded progress but cannot report `CONFIRMED`;
- coordinator confirms only from a restarted agent's exact build identity.

Signed `release-manifest.sig` verification remains planned defense-in-depth. The implemented trust chain today is coordinator resolution + HTTPS + exact coordinator-supplied artifact SHA-256.

## Coordinator instruction contract

Successful `AgentHello` or `Heartbeat` responses may contain:

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

The coordinator may repeat exactly the same instruction while an upgrade remains deliverable. Repetition is idempotent. The same `upgrade_id` with changed immutable fields is rejected.

## A1 - exact build identity

Every running agent includes a `payload.build` object in `AgentHello` and `Heartbeat`.

Identity fields:

```text
version
build_id
git_commit
build_timestamp
os
arch
protocol_version
schema_version
features
artifact_sha256 when installed from an immutable artifact
```

CMake generates compile-time version/build/commit/platform metadata. The final package SHA cannot be embedded before packaging, so updater-owned `installed-build.conf` records the exact installed artifact SHA and target identifiers. Runtime identity combines the executable build metadata with that installation metadata.

Canonical upgrade platforms:

```text
linux/amd64
linux/arm64
windows/amd64
```

Windows ARM64 can be added without changing the protocol.

## A2 - typed instruction parsing and validation

`UpgradeInstruction` validates before any upgrade action:

- UUID upgrade ID;
- non-empty version/build ID;
- full 40-character hexadecimal Git commit;
- exact local OS/architecture match;
- single safe artifact filename;
- HTTPS URL;
- approved GitHub/GitHubusercontent host;
- exactly 64 hexadecimal SHA-256 characters;
- target is not already the exact running build.

The endpoint never resolves `latest`, branch names, tags, or other mutable source references. Mutable references are coordinator concerns and must already be pinned to an immutable commit/artifact before delivery.

## A3 - durable local state

The instruction and local download state survive service restarts.

```text
Linux:   /var/lib/neta/identity/upgrade/current.json
Windows: <fleet-state-dir>\upgrade\current.json
```

Download states:

```text
RECEIVED
DOWNLOADING
VERIFIED
FAILED
```

Activation state is recorded separately in:

```text
<state-dir>/upgrade/activation.json
```

Activation states:

```text
INSTALLING
LOCAL_HEALTHY
FAILED
ROLLED_BACK
```

Writes use temporary-file + rename replacement. Repeated identical instructions are idempotent. Conflicting immutable data for the same active request is rejected.

## A4 - secure download and verification

The endpoint downloads the exact coordinator-provided artifact. Runtime upgrade never runs Git, CMake, a compiler, apt, winget, or another package manager.

Implemented controls:

- HTTPS only;
- system CA verification;
- hostname verification and SNI;
- approved GitHub/GitHubusercontent hosts;
- redirect host/scheme revalidation;
- bounded redirect count;
- default 256 MiB download limit;
- safe artifact filename;
- `.part` temporary file;
- exact SHA-256 before `VERIFIED`;
- cached artifact reuse only after re-verification.

Manual diagnostics remain available:

```text
neta-agent fleet upgrade-status
neta-agent fleet upgrade-download
```

## A5 - versioned installation and dedicated updater

The running process never overwrites itself. `neta-agent-updater` is a separate fixed-purpose executable built from the same source tree.

It accepts only the durable NETA upgrade request plus fixed installation/service parameters; it does not expose a general command runner.

### Linux

Bootstrap/install layout:

```text
/opt/neta-agent/
  versions/
    <build-id>/
      neta-agent
      supporting package files
  current  -> versions/<active-build>
  previous -> versions/<previous-build>

/usr/local/bin/neta-agent -> /opt/neta-agent/current/neta-agent
/usr/local/libexec/neta-agent-updater
```

`neta-agent.service` executes `/opt/neta-agent/current/neta-agent`.

After an instruction is accepted, the service launches the updater as a detached transient systemd unit using `systemd-run`. The helper therefore survives stopping the old agent service.

The updater:

1. downloads/verifies if the artifact is not already `VERIFIED`;
2. extracts only the expected `.tar.gz`/`.tgz` package into a staging directory;
3. requires exactly one packaged `neta-agent` executable;
4. creates `versions/<build-id>`;
5. stops `neta-agent.service`;
6. preserves the old `current` target as `previous`;
7. atomically changes `current`;
8. records exact installed target metadata;
9. restarts the service;
10. waits for health or rolls back.

The manual `deploy/linux/install-or-update.sh` now bootstraps this versioned layout and installs the updater. It is still a developer/manual bootstrap path; self-upgrade never invokes that script.

### Windows

Target layout:

```text
C:\Program Files\NETA\
  versions\
    <build-id>\
      neta-agent.exe
      DLLs/support files
  current\
  previous\
  neta-agent-updater.exe
```

The current implementation uses version directories plus `current`/`previous` directory replacement. The updater runs in a detached process, stops `NETAAgent`, replaces the active directory from the immutable staged version, starts the service, and rolls back to `previous` on failed health.

Windows release packaging includes both `neta-agent.exe` and `neta-agent-updater.exe`.

A future implementation may replace directory copying with NTFS junction/reparse-point switching; that changes the activation mechanism but not the protocol or rollback invariant.

## A6 - deterministic health and rollback

Machine health command:

```text
neta-agent health --upgrade --state-dir <fleet-state-dir>
```

The current health contract is intentionally strict and deterministic. It requires:

- fleet identity/configuration files are readable;
- identity configuration parses successfully;
- running executable version equals expected target version;
- build ID equals expected build ID;
- Git commit equals expected target commit;
- OS and architecture exactly match;
- updater-owned installed artifact SHA equals expected artifact SHA.

The updater also requires the configured service to reach running state before health can succeed. Default timeout is 45 seconds; the helper accepts a bounded 5-300 second timeout for controlled testing/deployment.

On failure or timeout:

1. record `FAILED` with bounded failure information;
2. stop the failed service when necessary;
3. restore the previous active version;
4. restart the old service;
5. record/report `ROLLED_BACK` when rollback succeeds.

The updater snapshots `installed-build.conf` before activation and restores that metadata after successful rollback so subsequent old-agent build reports do not claim the failed target artifact SHA.

## A7 - bounded coordinator progress

The updater sends `UpgradeProgress` over the existing authenticated fleet transport using the same mTLS identity, Fleet CA, NAP/1 envelope, and durable sequence discipline.

Allowed agent-reported states:

```text
DOWNLOADING
INSTALLING
LOCAL_HEALTHY
FAILED
ROLLED_BACK
```

`CONFIRMED` is deliberately rejected by the agent reporter. Only the coordinator owns final confirmation.

Example payload:

```json
{
  "upgrade_id": "uuid",
  "status": "FAILED",
  "failure_code": "HEALTH_OR_ACTIVATION_FAILED",
  "failure_message": "new agent did not become locally healthy before timeout"
}
```

Bounds:

```text
failure_code:    64 characters maximum
failure_message: 1000 characters maximum
```

Progress transmission is best effort from the updater so loss of coordinator connectivity cannot prevent local rollback. Coordinator-side C8 owns request ownership checks, legal state transitions, idempotency, timestamps, and audit persistence.

Diagnostic command:

```text
neta-agent fleet upgrade-report --upgrade-id UUID --status STATUS
```

## Automatic service behavior

A normal service cycle is sufficient to start an upgrade:

```text
AgentHello/Heartbeat
  -> coordinator responds with upgrade
  -> FleetClient validates and persists instruction
  -> service calls launch_upgrade_worker_if_needed()
  -> detached updater performs A4/A5/A6/A7
```

A detached worker is not relaunched while the same upgrade is already `INSTALLING` or `LOCAL_HEALTHY`.

The service continues normal observation if instruction validation or updater launch fails.

## Packaging contract

Production upgrades require immutable prebuilt release assets:

```text
neta-agent-<version>-linux-amd64.tar.gz
neta-agent-<version>-linux-arm64.tar.gz
neta-agent-<version>-windows-amd64.zip
release-manifest.json
release-manifest.sig   # planned hardening
```

Each package must contain the agent executable and any runtime files needed by that platform. The Windows package also contains `neta-agent-updater.exe`. Linux deployment installs the fixed updater separately during bootstrap; release packaging may also carry it when updater replacement policy is introduced.

The coordinator resolves a platform-specific manifest entry to the exact release asset URL + SHA-256 before creating the upgrade request.

## Deployment prerequisites

A1-A7 complete the agent-side control flow, but production rollout depends on the rest of the system matching the contract:

1. coordinator C8 must ingest and persist `UpgradeProgress` with legal transitions;
2. coordinator C9 must mark `CONFIRMED` only after exact restarted build identity matches the stored target;
3. release automation must publish Linux amd64/arm64 and Windows amd64 immutable assets plus `release-manifest.json` in the format expected by the coordinator resolver;
4. existing agents must first be bootstrapped into the versioned installation layout with the dedicated updater present;
5. an intentionally broken canary package must prove automatic rollback before broad rollout.

## Acceptance tests

### Successful Linux upgrade

```text
bootstrap versioned Linux install
-> coordinator requests exact linux/amd64 or linux/arm64 artifact
-> AgentHello/Heartbeat receives instruction
-> detached systemd updater starts
-> artifact downloads and SHA verifies
-> version installs under versions/<build-id>
-> current switches
-> service restarts
-> LOCAL_HEALTHY reports
-> restarted build identity matches exact target
-> coordinator CONFIRMED
```

### Successful Windows upgrade

```text
bootstrap Windows versioned install
-> coordinator requests windows/amd64 artifact
-> instruction received
-> detached updater starts
-> ZIP downloads and SHA verifies
-> version installs
-> NETAAgent stops
-> current version switches
-> service starts
-> LOCAL_HEALTHY reports
-> restarted exact build identity reaches coordinator
-> coordinator CONFIRMED
```

### Rollback test

```text
start from known-good version
-> request intentionally unhealthy but correctly hashed target
-> target installs and becomes active
-> local health fails/times out
-> updater restores previous version
-> previous service restarts
-> ROLLED_BACK reported best-effort
-> old build identity reappears
-> broken target is never CONFIRMED
```

### Security tests

Reject or fail closed on:

- wrong platform;
- malformed commit/SHA/UUID;
- non-HTTPS URL;
- unapproved download/redirect host;
- oversized artifact;
- traversal artifact name;
- SHA mismatch;
- changed immutable fields for an already accepted upgrade ID;
- simultaneous conflicting active request;
- agent attempt to report `CONFIRMED`;
- package without exactly one expected agent executable;
- service health timeout.

## Current implementation status

Branch:

```text
feature/agent-upgrade-a1-a4
```

Despite the historical branch name, it now contains **A1-A7**:

- A1 exact build identity;
- A2 typed instruction validation;
- A3 durable state/idempotency;
- A4 bounded HTTPS + exact SHA verification;
- A5 Linux/Windows versioned activation through a separate updater;
- A6 deterministic health timeout + automatic rollback;
- A7 bounded `UpgradeProgress` over the fleet mTLS channel.

No new external dependency was introduced for A1-A7; the implementation uses the existing C++20/OpenSSL stack plus native/system service mechanisms already present on supported platforms.
