# ARM64 Runtime Validation

## Status: COMPLETE

Milestone 1 ARM64 Linux runtime validation was completed successfully on 2026-08-29 on a native AWS Graviton ARM64 host.

Validated environment:

```text
OS:            Ubuntu Server 24.04 LTS
Architecture:  aarch64 / arm64
AWS instance:  t4g.small (Graviton2)
Region:        eu-north-1 (Stockholm)
Kernel:        6.17.0-1017-aws
BTF:           /sys/kernel/btf/vmlinux present
```

This complements the existing x86-64 Linux validation on WSL2 and Ubuntu 24.04 on AWS. The project may now describe the Milestone 1 Linux runtime path as validated on both x86-64 and ARM64 rather than only saying that an ARM64 build path exists.

## Validation procedure

The strict eBPF path was built and tested with:

```bash
cmake -S . -B build-ms1 \
  -DCMAKE_BUILD_TYPE=Debug \
  -DNETA_EBPF=ON
cmake --build build-ms1 -j"$(nproc)"
ctest --test-dir build-ms1 --output-on-failure
sudo ./build-ms1/neta-agent capabilities
sudo ./build-ms1/neta_ms1_ebpf_integration
bash tests/ms0_acceptance.sh ./build-ms1/neta-agent
```

The ordinary unprivileged CTest run passed all userspace tests and explicitly skipped the privileged eBPF integration test, as expected. The privileged integration executable was then run directly under `sudo`.

## Observed acceptance results

Runtime capability probing reported:

```text
Connection discovery       YES
Process attribution        YES
TCP RTT                    YES
TCP RTT variance           YES
TCP retransmissions        YES
TCP cwnd                   YES
Route observation          YES
eBPF lifecycle built in    YES
BTF/CO-RE runtime          YES
eBPF lifecycle             YES
TCP connect events         YES
TCP accept events          YES
TCP close events           YES
```

The native privileged eBPF integration test reported:

```text
client_connect_seen=1
accept_seen=1
client_close_seen=1
accepted_close_seen=1
short_connect_seen=1
short_accept_seen=1
short_client_close_seen=1
short_accepted_close_seen=1
short_lived_attributed=1
client_cookie_correlation=1
accept_fallback_correlation=1
accept_cookie_fabricated=0
MS1 eBPF integration PASS
```

The Milestone 0 regression/acceptance suite also completed successfully:

```text
MS0 acceptance PASS
```

The acceptance criteria are therefore satisfied:

- `BTF/CO-RE runtime YES`
- `eBPF lifecycle YES`
- TCP connect/accept/close events available
- `MS1 eBPF integration PASS`
- `short_lived_attributed=1`
- CONNECT/CLOSE socket-cookie correlation with SOCK_DIAG passes
- ACCEPT fallback correlation passes
- no fabricated ACCEPT cookie (`accept_cookie_fabricated=0`)
- `MS0 acceptance PASS`

## Portability conclusion

The ARM64 runtime check validates the same design used on x86-64:

```text
eBPF CO-RE lifecycle events
        +
SOCK_DIAG / TCP_INFO enrichment
        +
socket-cookie / fallback correlation
        +
deterministic persistence and replay
```

This is runtime portability evidence for the current Milestone 1 Linux implementation on native ARM64. It does not imply support for every ARM64 kernel/distribution configuration; runtime capability probing remains authoritative because BTF, tracing hooks, kernel policy, lockdown, and privileges can differ by host.
