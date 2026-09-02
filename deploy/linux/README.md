# Linux install/update and enrollment

These scripts are the supported simple path for a Debian/Ubuntu Linux endpoint.

## Install or update

From an existing checkout of `neta-agent`:

```bash
sudo ./deploy/linux/install-or-update.sh
```

The script:

- installs build prerequisites;
- fast-forwards the checkout to `origin/main` and refuses to overwrite local changes;
- validates a Debug build with eBPF required by running the full test suite;
- builds a production Release binary with eBPF required;
- installs `/usr/local/bin/neta-agent`;
- installs the optional OpenSSL TLS context shim at `/usr/local/lib/neta/libneta_tls_context.so`;
- creates `/var/lib/neta`, `/var/lib/neta/identity`, and `/etc/neta`;
- preserves an existing `/etc/neta/neta-agent.env`, otherwise creates the recommended MS4.2 environment;
- installs/enables/restarts `neta-agent.service`.

The system service observes all eligible directions, stores history in `/var/lib/neta/neta.db` with a 200 MB cap, and uses the shared TLS-context endpoint `@neta-agent-tls-service`.

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
