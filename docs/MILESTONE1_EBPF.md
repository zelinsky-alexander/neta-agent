# Milestone 1: event-driven Linux lifecycle

Milestone 1 separates connection lifecycle discovery from detailed transport sampling:

```text
TCP connect/accept/close
         |
         v
   eBPF CO-RE
         |
         | lifecycle + PID + socket cookie
         v
  ConnectionTracker
         |
         +-------------------+
         |                   |
         v                   v
   HistoryStore         SOCK_DIAG
                           |
                           v
                       TCP_INFO
                           |
                           v
                   detailed evidence
```

eBPF answers **when** a socket begins/ends and **who** owned it at that time. It records connect, accepted-socket, and close observations with explicit optional fields. It does not produce a security or performance verdict. SOCK_DIAG remains the source of TCP state, RTT, RTT variance, retransmissions, congestion window, and queue evidence.

## Hooks and event delivery

- `fexit/tcp_v4_connect` and `fexit/tcp_v6_connect` emit successful outbound connects after the kernel has populated the socket endpoints.
- `kretprobe/inet_csk_accept` reads the returned accepted socket. A return probe avoids coupling the object to kernel-version-specific `inet_csk_accept` argument lists.
- `fentry/tcp_close` emits close at the kernel lifecycle operation rather than waiting for a missing snapshot.
- A BPF ring buffer delivers bounded fixed-version records. Userspace validates record size/version before decoding.

The BPF program uses CO-RE field relocations against runtime BTF. Its small local type declarations describe only accessed fields; they are not assumed to be an exact kernel layout. Connect/close use BTF trampolines. The accept return-value access uses libbpf's architecture-specific tracing ABI for the release target (`x86_64` or `arm64`).

## Identity and attribution

The preferred identity is a nonzero socket cookie:

```text
eBPF cookie -> ConnectionTracker -> same SOCK_DIAG idiag_cookie
```

This prevents eBPF-first admission and later TCP_INFO enrichment from creating two history rows. If a cookie is unavailable, the permanent fallback identity includes network namespace, process, endpoints, and lifecycle timestamp. A tuple-only index is used only to correlate one unambiguous currently-active fallback connection; the five-tuple is never treated as durable identity.

CONNECT and CLOSE are BPF tracing programs. For those hooks, the kernel resolves
`bpf_get_socket_cookie(sk)` to the socket-pointer helper that calls
`sock_gen_cookie()`, the same generator used by SOCK_DIAG. The ACCEPT kretprobe
is a kprobe program type, where that helper is not permitted. ACCEPT therefore
advertises the cookie as unavailable rather than reading the lazy internal
field or fabricating a value; its endpoints provide the temporary active-tuple
correlation until SOCK_DIAG supplies the canonical cookie.

At loader initialization, the agent obtains the device and inode of
`/proc/self/ns/pid` and writes them to a BPF configuration map before attaching
any hook. Each hook retains `bpf_get_current_pid_tgid()` as kernel/root-namespace
provenance, then uses `bpf_get_ns_current_pid_tgid()` to obtain the PID/TGID as
seen in the agent's PID namespace. Only that agent-visible TGID is eligible for
`/proc` attribution. The lifecycle model and persisted event keep the two PID
identities separate along with the agent PID-namespace device/inode.

If the namespace-aware helper fails, the event retains kernel PID provenance
but marks agent-visible PID/TGID unavailable. Userspace does not guess a
translation or use a socket cookie as process identity, so no misleading
process history is created. UID, command name, and task start time are captured
at event time when available; userspace converts the kernel start time to
`/proc` clock-tick units. The `/proc/<pid>/fd` inode resolver remains the polling
fallback and corroborating mechanism.

LISTEN sockets are not admitted. The accept event refers to the newly returned connected socket. The generic tracker supports accepted-socket admission for the Milestone 2 foundation, but the current `observe --target` product flow remains outbound-only and does not enable inbound assurance.

## Build and deployment

Build-time eBPF requirements are:

- clang with the BPF target;
- libbpf development headers/library;
- CMake and a C++20 compiler.

No generated `vmlinux.h` or `bpftool` command is required. CMake compiles `lifecycle.bpf.c`, deterministically converts the object to a C++ byte array, and links it into `neta-agent`. The build tree contains an intermediate `.bpf.o`; installed/runtime deployment does not.

Configure policy:

```bash
cmake -S . -B build -DNETA_EBPF=AUTO   # default; fallback build if tools are absent
cmake -S . -B build -DNETA_EBPF=ON     # require eBPF build support
cmake -S . -B build -DNETA_EBPF=OFF    # deliberate polling-only build
```

libbpf is used because it provides CO-RE relocation, BTF-aware loading, BPF-link lifetime management, and ring-buffer consumption without BCC or a runtime compiler. It is dual BSD-2-Clause/LGPL-2.1 licensed. A dynamically linked build needs the normal libbpf runtime library. A static/single-file release must link libbpf and its transitive static dependencies into the executable.

## Runtime requirements and capabilities

A practical runtime needs a modern native Linux kernel (5.11 or newer), `/sys/kernel/btf/vmlinux`, BPF ring buffers, BTF trampoline support, kprobe support, and permission to load/attach tracing BPF programs. Root normally has the needed authority; capability-based deployments typically require the kernel's applicable `CAP_BPF`, `CAP_PERFMON`, and resource-limit policy. Kernel lockdown or distribution policy may still deny tracing.

`neta-agent capabilities` performs a real open/load/attach probe. “Built in” only reports build-time inclusion. Connect, accept, and close are reported individually from successful attachments; full lifecycle reports `YES` only when every required hook attached and the ring buffer was created. BTF presence is reported separately. Outbound observation can use CONNECT+CLOSE if ACCEPT attachment is unavailable without claiming full lifecycle support.

WSL kernels vary. BTF may exist while trampoline, kprobe, capability, or host policy prevents the full program set from attaching. That state is reported as unavailable and does not mean “no lifecycle event occurred.” The observe command continues with polling discovery and SOCK_DIAG evidence.

With eBPF active, the default detailed transport interval is 1 second and a connect admission triggers an immediate SOCK_DIAG snapshot. `--poll-ms` can tune it. Without eBPF, the default remains the MS0 100 ms discovery poll.

## Tests

Deterministic userspace coverage runs without privileges:

```bash
ctest --test-dir build --output-on-failure
bash tests/ms0_acceptance.sh ./build/neta-agent
```

The native privileged integration executable creates loopback outbound and accepted TCP sockets, a short-lived connection, and closes them. It verifies real connect/accept/close events, event-time PID attribution, CONNECT/CLOSE cookie equality with SOCK_DIAG, explicit ACCEPT-cookie unavailability, and ACCEPT fallback correlation to later SOCK_DIAG state. It owns no pinned objects, qdisc state, background server, or temporary file; RAII closes sockets and libbpf links on every exit.

```bash
sudo bash tests/ms1_ebpf_integration.sh ./build/neta-agent
```

CTest marks return code 77 as an explicit skip when build/runtime eBPF capability is unavailable. A skip is not an integration pass.

## ARM64 runtime validation

Native ARM64 runtime validation is complete as of 2026-08-29. The strict Milestone 1 eBPF path was validated on Ubuntu Server 24.04 LTS running on an AWS Graviton2 `t4g.small` host (`aarch64` / `arm64`, kernel `6.17.0-1017-aws`).

The runtime capability probe reported BTF/CO-RE, full eBPF lifecycle, and TCP connect/accept/close support. The privileged integration test passed with short-lived process attribution, CONNECT/CLOSE socket-cookie correlation, ACCEPT fallback correlation, and no fabricated ACCEPT cookie. The Milestone 0 regression/acceptance suite also passed.

See [`ARM64_RUNTIME_VALIDATION.md`](ARM64_RUNTIME_VALIDATION.md) for the exact environment, commands, and observed acceptance results.
