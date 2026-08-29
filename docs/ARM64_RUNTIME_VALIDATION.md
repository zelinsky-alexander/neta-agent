# ARM64 Runtime Validation

Milestone 1 is validated on x86-64 Linux (WSL2 and Ubuntu 24.04 on AWS), but ARM64 runtime validation is still pending.

Before claiming ARM64 Linux support, validate the same strict eBPF path on a native ARM64 Ubuntu host:

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

Acceptance requires:

- `BTF/CO-RE runtime YES`
- `eBPF lifecycle YES`
- `TCP connect/accept/close events YES`
- `MS1 eBPF integration PASS`
- `short_lived_attributed=1`
- socket-cookie/SOCK_DIAG correlation passes
- ACCEPT fallback correlation passes without fabricated cookies
- `MS0 acceptance PASS`

This is a runtime portability check, not a prerequisite for the already validated x86-64 Linux MS1 implementation.
