# MS4.2 — Always-On Agent Service Readiness

This milestone prepares `neta-agent run` for long-lived systemd operation and for controlled end-to-end incident validation against the coordinator.

## Runtime behavior

When `neta-agent run` is started in service mode with an enrolled fleet identity, it:

- sends `AgentHello` at service startup;
- sends periodic heartbeats using `NETA_FLEET_HEARTBEAT_SECONDS`;
- applies per-heartbeat jitter from `NETA_FLEET_HEARTBEAT_JITTER_PERCENT`;
- finalizes completed inbound connections during the live observation loop;
- applies the configured fleet reporting policy immediately;
- keeps observation alive if coordinator communication fails.

Service event messages are explicitly flushed so systemd/journald receives `AgentHello`, heartbeat, and live-reporting results without waiting for process shutdown or stdio buffer saturation.

## Recommended production fleet settings

```text
NETA_FLEET_STATE_DIR=/var/lib/neta/identity
NETA_FLEET_REPORTING_MODE=SIGNIFICANT_ONLY
NETA_FLEET_MIN_CONFIDENCE=0.80
NETA_FLEET_REPORTING_COOLDOWN_SECONDS=1800
NETA_FLEET_HEARTBEAT_SECONDS=300
NETA_FLEET_HEARTBEAT_JITTER_PERCENT=20
```

A short heartbeat interval such as 30 seconds should be used only for a bounded smoke test. Production uses 300 seconds by default with jitter to avoid synchronized fleet bursts.

## Shared TLS context endpoint for a privileged service

Exact TLS identity is collected from instrumented OpenSSL sessions through the local Unix datagram TLS-context endpoint.

If `NETA_TLS_CONTEXT_SOCKET` is not set, both the collector and the OpenSSL shim derive a per-UID endpoint:

```text
@neta-agent-tls-uid-<uid>
```

That default is convenient for a foreground agent and instrumented application running under the same user. It is not appropriate when the always-on agent runs as root while the observed application runs as an ordinary user: root would listen on `@neta-agent-tls-uid-0`, while a UID 1000 application would send to `@neta-agent-tls-uid-1000`.

For the system service, configure one explicit shared endpoint:

```text
NETA_TLS_CONTEXT_SOCKET=@neta-agent-tls-service
```

The root `neta-agent` service and every instrumented OpenSSL application that is expected to provide exact TLS-session evidence must receive the same environment value.

Example instrumented application launch:

```bash
NETA_TLS_CONTEXT_SOCKET=@neta-agent-tls-service \
LD_PRELOAD=/path/to/libneta_tls_context.so \
<application> <args...>
```

Changing to a shared endpoint does not remove sender attribution. The receiver enables `SO_PASSCRED` and validates kernel-provided `SCM_CREDENTIALS`, so PID/UID attribution is based on sender credentials supplied by the kernel rather than on fields supplied by the application.

The service logs its active TLS context endpoint at startup. This gives an immediate operational check in journald:

```text
NETA service TLS context endpoint: @neta-agent-tls-service
```

## Recommended systemd environment

A production `/etc/neta/neta-agent.env` should therefore contain:

```text
NETA_FLEET_STATE_DIR=/var/lib/neta/identity
NETA_FLEET_REPORTING_MODE=SIGNIFICANT_ONLY
NETA_FLEET_MIN_CONFIDENCE=0.80
NETA_FLEET_REPORTING_COOLDOWN_SECONDS=1800
NETA_FLEET_HEARTBEAT_SECONDS=300
NETA_FLEET_HEARTBEAT_JITTER_PERCENT=20
NETA_TLS_CONTEXT_SOCKET=@neta-agent-tls-service
```

Do not place enrollment tokens or private-key material in this environment file. Fleet identity remains in the protected state directory.

## Service validation

After updating and restarting the service, verify:

```bash
sudo systemctl status neta-agent --no-pager
sudo journalctl -u neta-agent -n 100 --no-pager
```

Expected startup evidence includes:

```text
NETA service TLS context endpoint: @neta-agent-tls-service
Fleet service: AgentHello accepted
```

A later line should show:

```text
Fleet service: heartbeat accepted
```

The first controlled incident acceptance test should not use `fleet announce-connection` manually. The intended path is:

```text
connection completes
  -> final evidence correlation
  -> live inbound verdict finalization
  -> SIGNIFICANT_ONLY policy
  -> FindingAnnouncement
  -> coordinator
```
