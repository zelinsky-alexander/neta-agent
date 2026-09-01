# MS4.1 — Fleet Reporting and Bounded Coordinator Storage

MS4.1 turns the first working NAP/1 E2E path into a continuously usable fleet-reporting path without sending every local observation to the coordinator or retaining every routine message forever.

## Agent reporting policy

Detailed evidence remains local in the agent SQLite database. When an observation run has finalized assurance verdicts, an enrolled agent evaluates each connection against the fleet reporting policy.

Default mode: `SIGNIFICANT_ONLY`.

A finding is significant when either:

- trust is `CHANGED` or `SUSPICIOUS`; or
- performance is `DEGRADED` or `FAILED` and `rule_confidence` is at least the configured minimum.

`STABLE`, `UNVERIFIED`, `NORMAL`, and `INSUFFICIENT_EVIDENCE` observations are not announced by the default policy.

Configuration is environment based so the same binary works in interactive and service deployments:

```text
NETA_FLEET_REPORTING_MODE=SIGNIFICANT_ONLY
NETA_FLEET_MIN_CONFIDENCE=0.80
NETA_FLEET_REPORTING_COOLDOWN_SECONDS=1800
NETA_FLEET_STATE_DIR=/var/lib/neta/identity
```

Modes:

- `OFF` — retain all findings locally only.
- `SIGNIFICANT_ONLY` — default operational mode.
- `ALL_FINDINGS` — lab/debug mode.

The reporting cooldown is keyed by a stable logical finding key derived from direction, service target and verdict/hypothesis. The state is persisted in `reporting.state` under the fleet identity directory and is updated only after a successful coordinator send. A send failure does not fail the observation run.

Manual `fleet announce-connection` remains available for testing, forensic publication and operator override.

## Coordinator bounded storage

Heartbeats are current-state messages by default, not permanent history. A valid heartbeat still performs all identity, sequence, freshness and mTLS validation, then updates the enrolled agent's `last_sequence`, `last_seen_at`, and `last_heartbeat_payload`. With the default configuration it does not create a `protocol_messages` row or a `MESSAGE_ACCEPTED` audit row.

Other NAP/1 protocol messages remain a bounded ingress/debug journal. Default retention is seven days. Routine accepted-message audit events default to thirty days. Enrollment/revocation and semantic finding data are not removed by this routine cleanup.

Coordinator storage settings:

```text
NETA_RETAIN_HEARTBEATS=false
NETA_AUDIT_HEARTBEATS=false
NETA_PROTOCOL_RETENTION=P7D
NETA_ACCEPTED_AUDIT_RETENTION=P30D
NETA_STORAGE_CLEANUP_INTERVAL=PT1H
```

## Finding deduplication

The V2 coordinator schema adds `finding_key`, `first_seen`, `last_seen`, `occurrence_count`, and `status` to findings. A repeated announcement of the same logical issue from the same agent updates the existing incident instead of creating another semantic finding row:

```text
first occurrence -> INSERT, occurrence_count=1
repeat           -> UPDATE last_seen/latest evidence, occurrence_count++
```

Raw NAP envelopes may still appear separately in the short-retention protocol journal, preserving near-term debugging without making duplicate semantic incidents permanent.

## Acceptance criteria

- Enrolled observation runs automatically evaluate finalized connections for fleet reporting.
- Default reporting does not announce stable/insufficient/unverified observations.
- Trust changes/suspicious identity evidence are announced.
- Performance degradation/failure is gated by configurable confidence.
- A successfully announced logical finding is locally cooled down.
- Heartbeats update current agent state without growing protocol/audit tables by default.
- Repeated logical findings increment `occurrence_count` rather than create unlimited semantic rows.
- Old protocol messages and routine accepted-message audit rows are removed by configurable scheduled retention.
- Existing enrollment, AgentHello, heartbeat and FindingAnnouncement mTLS/NAP behavior remains valid.
