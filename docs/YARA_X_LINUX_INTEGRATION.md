# YARA-X Linux Integration

Status: side-branch implementation

Branch: `feature/process-artifact-assurance-yarax`

Last reviewed: 2026-09-04

## Goal

NETA treats YARA-X as an optional antimalware evidence provider, not as a required networking dependency and not as a final trust verdict. YARA-X findings are intended to correlate with process execution, file provenance, memory transitions, DNS/TLS/network activity, baseline state, and later cooperative/fleet evidence.

The endpoint design intentionally keeps `neta-agent` small and avoids Rust/Cargo/YARA-X source builds on deployed systems.

## Deployment architecture

```text
NETA core binary
    |
    +--> networking / eBPF / TLS / DNS / fleet
    |
    +--> YaraXProvider
            |
            +--> dlopen("/usr/local/lib/neta/yara-x/current/libyara_x_capi.so")
                    |
                    +--> available: compile configured rules and scan
                    +--> absent/incompatible: UNSUPPORTED evidence; NETA keeps running
```

The YARA-X C API is resolved at runtime with `dlopen`/`dlsym`. `neta-agent` does not require YARA-X headers, a `yara_x_capi.pc` file, Rust, Cargo, or the YARA-X source tree on the endpoint.

The runtime is deliberately kept loaded until process exit. YARA-X documents special global finalization requirements before unloading a dynamically loaded library, while NETA has no need for hot-unload semantics.

## Runtime layout

```text
/usr/local/lib/neta/yara-x/
    1.20.0/
        libyara_x_capi.so
        VERSION
        LICENSE.YARA-X
        MANIFEST
    current -> 1.20.0
```

The provider reads `current/VERSION` for evidence provenance. The library path can be overridden for development/testing with:

```bash
NETA_YARAX_LIBRARY=/path/to/libyara_x_capi.so
```

## Independent update lifecycles

NETA binary, YARA-X engine, and YARA rules are intentionally separate:

```text
neta-agent binary       relatively infrequent
YARA-X runtime          when upstream engine/security updates are approved
YARA ruleset            independently, potentially much more frequently
```

Evidence keeps provider version, ruleset ID, and ruleset SHA-256 so historical findings remain replayable and attributable.

## Prebuilt runtime production

`.github/workflows/yarax-runtime.yml` builds the YARA-X C API in GitHub Actions on native Linux x86_64 and ARM64 runners. Rust and `cargo-c` exist only in that controlled build job.

The workflow packages:

```text
neta-yarax-runtime-v<VERSION>-linux-x86_64.tar.gz
neta-yarax-runtime-v<VERSION>-linux-arm64.tar.gz
```

with matching `.sha256` files. When `publish=true`, the workflow publishes or updates the repository release tag:

```text
yarax-runtime-v<VERSION>
```

Each endpoint package contains only:

```text
libyara_x_capi.so
VERSION
LICENSE.YARA-X
MANIFEST
```

No Rust toolchain or YARA-X source is deployed.

GitHub currently provides native `ubuntu-24.04` x86_64 and `ubuntu-24.04-arm` ARM64 hosted runners, so both runtime artifacts are built natively rather than cross-compiled.

## Endpoint runtime install/update

Use:

```bash
sudo ./deploy/linux/install-yarax-runtime.sh 1.20.0
```

The installer:

1. selects x86_64 or ARM64 from the running kernel;
2. downloads the matching NETA runtime release asset and checksum;
3. verifies SHA-256 before extraction;
4. verifies the shared object's native architecture;
5. installs into a versioned directory;
6. atomically changes `current` to the new version;
7. restarts `neta-agent.service` if it is active.

The endpoint never compiles YARA-X.

Rollback is an atomic symlink change followed by an agent restart, for example:

```bash
sudo ln -sfn 1.20.0 /usr/local/lib/neta/yara-x/current.new
sudo mv -Tf /usr/local/lib/neta/yara-x/current.new /usr/local/lib/neta/yara-x/current
sudo systemctl restart neta-agent
```

## NETA build behavior

The Linux provider implementation is compiled into NETA but loads the YARA-X engine only at runtime.

`NETA_YARA_X=AUTO|ON|OFF` controls only whether the Linux runtime-loader provider is compiled/enabled:

```text
AUTO / ON   compile the runtime loader; no YARA-X headers or libraries are required
OFF         disable the YARA-X provider
```

There is no `pkg-config yara_x_capi` detection and no link-time YARA-X dependency. The supported Linux deployment installer explicitly uses:

```text
-DNETA_YARA_X=ON
```

so the runtime loader is available while the installed endpoint binary remains independent from `libyara_x_capi.so`. The installer checks `ldd` and fails if any hard YARA dependency appears.

## Missing or broken runtime semantics

A missing runtime must not prevent NETA from starting.

Examples:

```text
runtime absent       -> provider unavailable / UNSUPPORTED
missing ABI symbol   -> provider unavailable / UNSUPPORTED
rules unreadable     -> SCAN_ERROR
rules fail compile   -> SCAN_ERROR
scan timeout         -> INCONCLUSIVE
scan engine error    -> SCAN_ERROR
no rule matches      -> NO_MATCH
rule matches         -> MATCH
```

`NO_MATCH` never means that an artifact is safe.

## Current process-exec flow

```text
sched_process_exec
      |
      v
ProcessExecEvent
      |
      v
ExecAntimalwareMonitor
      |
      +--> executable path / size / SHA-256
      |
      +--> YaraXProvider
              |
              +--> runtime C API
              +--> configured rules
              +--> normalized AntimalwareEvidence
```

The deterministic integration harness executes `neta_yara_exec_trigger_target`, observes it through `sched_process_exec`, hashes the artifact, scans it with the runtime-loaded YARA-X engine, and requires the rule `neta_exec_trigger_marker` to match.

If the runtime is not installed, the normal CI test skips with return code 77. The AWS ARM64 validation host should run this test with a published runtime installed and must PASS rather than SKIP before merge to `main`.

## Provider model

The portable interface remains provider-oriented:

```text
Artifact / process
      |
      +--> YARA-X             pattern/rule evidence
      +--> Platform AV        future vendor/native verdict
      +--> Reputation         future hash/reputation evidence
      +--> Runtime detector   future behavior/anomaly evidence
      |
      v
normalized evidence set
      |
      v
NETA deterministic correlation rules
```

Do not use majority voting. A `NO_MATCH` from one provider must not cancel a high-confidence `MATCH` from another provider.

## Dependency policy

YARA-X is BSD-3-Clause and is the first concrete antimalware provider. Its engine is built outside the deployed endpoint and shipped as an optional runtime package.

ClamAV remains a possible external `clamd` provider later; NETA must not link `libclamav` without explicit GPL/distribution review.

## Current non-goals

This branch still does not:

- persist antimalware evidence in SQLite;
- modify Trust verdicts;
- scan process memory;
- monitor file writes;
- automatically download YARA community rules;
- block/prevent execution;
- implement Windows YARA-X process triggers.

The current merge gate is Linux runtime loading + deterministic exec-trigger validation on real x86_64/ARM64 systems without endpoint Rust/Cargo.
