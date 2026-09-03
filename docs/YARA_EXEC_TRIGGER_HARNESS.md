# YARA-X exec-trigger integration harness

Status: Linux side-branch validation harness

Branch: `feature/process-artifact-assurance-yarax`

## Purpose

This harness proves the complete first automatic antimalware trigger path:

```text
child exec
  -> sched_process_exec eBPF tracepoint
  -> ProcessExecEvent
  -> executable path
  -> SHA-256 artifact identity
  -> ExecAntimalwareMonitor
  -> YaraXProvider
  -> deterministic YARA-X MATCH
```

Ordinary socket, DNS, or TLS events do not trigger this test scan.

## Deterministic trigger

`neta_yara_exec_trigger_target` embeds this unique marker in its executable image:

```text
NETA_YARA_EXEC_TRIGGER_2026_09_03
```

`tests/data/yara_exec_trigger.yar` contains a purpose-built rule named:

```text
neta_exec_trigger_marker
```

The integration test succeeds only when the eBPF observer reports the exact child exec and YARA-X returns `MATCH` for that named rule.

No malware sample is required or used.

## Prerequisites

- Linux with BTF at `/sys/kernel/btf/vmlinux`;
- libbpf development/runtime support;
- clang BPF target;
- sufficient privilege/capabilities to load and attach the BPF tracepoint program;
- YARA-X C API installed and visible through pkg-config as `yara_x_capi`.

Configure with both required capabilities enabled when validating the real path:

```bash
cmake -S . -B build-yara-exec -G Ninja \
  -DCMAKE_BUILD_TYPE=Debug \
  -DNETA_EBPF=ON \
  -DNETA_YARA_X=ON
cmake --build build-yara-exec -j
```

## Run

Run the focused CTest target with sufficient privilege:

```bash
sudo ctest --test-dir build-yara-exec \
  -R neta_yara_exec_trigger_integration \
  --output-on-failure
```

Or invoke the harness directly:

```bash
sudo ./build-yara-exec/neta_yara_exec_trigger_integration \
  ./build-yara-exec/neta_yara_exec_trigger_target \
  ./tests/data/yara_exec_trigger.yar
```

Expected successful evidence includes output similar to:

```text
EXEC pid=<pid> path=<...>/neta_yara_exec_trigger_target sha256=<hash>
provider=yara-x state=MATCH matches=1
rule=neta_exec_trigger_marker
PASS: sched_process_exec triggered YARA-X match
```

## Skip behavior

The CTest target uses skip return code `77` when either:

- YARA-X is not compiled into the build; or
- the process-exec eBPF observer cannot attach in the current environment.

A skip is not evidence that the real path works. A release/merge decision for this slice should require at least one explicit Linux run with `NETA_EBPF=ON`, `NETA_YARA_X=ON`, and the focused harness returning success.

## What this slice does not prove

This harness does not yet prove:

- persistent scan caching across agent restarts;
- SQLite persistence/export/replay for artifact evidence;
- file-write/close triggered scanning;
- process-memory scanning;
- network-event escalation to memory scanning;
- verdict integration or blocking/enforcement.

Those remain later slices.
