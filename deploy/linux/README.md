# Linux install/update and enrollment

These scripts are the supported simple path for a Debian/Ubuntu Linux endpoint.

## Install or update

From an existing checkout of `neta-agent`:

```bash
sudo ./deploy/linux/install-or-update.sh
```

The installer is architecture-aware. It supports native Linux builds on:

- `x86_64` / Debian `amd64`;
- `aarch64` / Debian `arm64`.

It detects the running kernel/package architecture, rejects unsupported or mismatched architectures, reports kernel BTF availability, and uses architecture-specific build directories so a stale CMake cache from another CPU architecture is not reused. CMake then selects the matching eBPF target (`x86` for x86_64, `arm64` for aarch64/arm64). Before installation, the script verifies that the produced ELF binary matches the detected native architecture.

This means the same command is used on both the x86_64 WSL endpoint and an AWS ARM64 Ubuntu endpoint; no cross-compilation flag is needed.

The script:

- installs build prerequisites;
- fast-forwards the checkout to `origin/main` and refuses to overwrite local changes;
- detects and validates the native x86_64 or ARM64 platform;
- validates a Debug build with eBPF required by running the full test suite;
- builds a production Release binary with eBPF required for the detected architecture;
- verifies the generated executable architecture;
- installs `/usr/local/bin/neta-agent`;
- installs the optional OpenSSL TLS context shim at `/usr/local/lib/neta/libneta_tls_context.so`;
- creates `/var/lib/neta`, `/var/lib/neta/identity`, and `/etc/neta`;
- preserves an existing `/etc/neta/neta-agent.env`, otherwise creates the recommended MS4.2 environment;
- installs/enables/restarts `neta-agent.service`.

The system service observes all eligible directions, stores history in `/var/lib/neta/neta.db` with a 200 MB cap, and uses the shared TLS-context endpoint `@neta-agent-tls-service`.

### AWS ARM64 preflight

On the ARM instance, these should normally report `aarch64`, `arm64`, and a readable BTF file:

```bash
uname -m
dpkg --print-architecture
ls -lh /sys/kernel/btf/vmlinux
```

Then use the normal installer:

```bash
sudo ./deploy/linux/install-or-update.sh
```

A successful ARM install will print `NETA native build architecture: arm64` and `Installed arm64 build`.

## Enroll

Enrollment is a separate explicit operation. The token is prompted without echo, so it is not placed in shell history.

```bash
sudo ./deploy/linux/enroll.sh \
  https://COORDINATOR:8443 \
  /path/to/fleet-ca.crt \
  my-linux-agent \
  fleet-dev
```

The script creates the protected identity in `/var/lib/neta/identity`, verifies `fleet status`, sends one `AgentHello` and heartbeat, then restarts the always-on service.

It refuses to overwrite an existing `agent.key`. Re-enrollment therefore requires an intentional identity migration/removal rather than an accidental script rerun.

## Health check

Run the small read-only health check with:

```bash
sudo ./deploy/linux/health-check.sh
```

It reports the installed binary, systemd service state/PID/start time, boot enablement, fleet identity, local storage status, and recent AgentHello/heartbeat/live-reporting events. It does not send a heartbeat or mutate fleet sequence state.

## Verify manually

```bash
sudo systemctl status neta-agent --no-pager
sudo journalctl -u neta-agent -n 100 --no-pager
sudo /usr/local/bin/neta-agent fleet status --state-dir /var/lib/neta/identity
```

Expected service startup includes the shared TLS context endpoint and, for an enrolled endpoint, an accepted `AgentHello` followed by periodic heartbeats.
