# Large-Scale Simulator — Phase 1 Broker Foundation

Branch: `large-scale-simulator`

## Scope

Phase 1 adds the Linux sensor-broker foundation to `neta-agent` without changing the normal production execution path.

Implemented:

- `NETA_SENSOR_MODE=native|broker` selection for Linux lifecycle/process-exec/name-resolution observer factories;
- versioned host-local broker protocol over Unix `SOCK_SEQPACKET` sockets;
- broker-backed lifecycle and process-exec observers;
- a `neta-agent sensor-broker` host command;
- endpoint routing by existing lifecycle network-namespace inode and new process-exec cgroup ID;
- bounded per-endpoint/per-stream queues with drop accounting;
- explicit unroutable-event accounting;
- deterministic endpoint-isolation tests in the existing Linux test suite;
- process-exec eBPF wire version 4 with `bpf_get_current_cgroup_id()` attribution.

Not implemented in Phase 1:

- fleet orchestration / automatic namespace creation (`neta-lab` Phase 2);
- PID-namespace remapping. Phase-1 lab agents therefore share the simulator host PID namespace while being isolated by cgroup and network namespace;
- name-resolution stream multiplexing. Broker-mode name-resolution capability is reported unavailable instead of attaching one eBPF resolver probe per virtual agent;
- Windows ETW broker support;
- tenant/coordinator/portal changes.

## Host broker

The broker loads the current native Linux lifecycle and process-exec observers once and routes events to endpoint-specific queues.

```text
Linux kernel
   |
   +-- lifecycle eBPF -------- netns inode ----+
   |                                           |
   +-- process-exec eBPF ---- cgroup ID -------+--> sensor broker
                                                   |   |   |
                                                   v   v   v
                                                 agent agent agent
```

Example startup:

```bash
sudo ./build/neta-agent sensor-broker \
  --socket /run/neta/sensor-broker.sock \
  --queue-capacity 1024 \
  --map lnx-0001:4026533001:93828293 \
  --map lnx-0002:4026533002:93828411 \
  --map lnx-0003:4026533003:93828577
```

Each mapping is:

```text
SLOT:NETWORK_NAMESPACE_INODE:CGROUP_ID
```

The future `neta-lab` orchestrator will discover these kernel IDs automatically and construct the broker arguments.

## Broker-mode agent

Run each endpoint agent in its endpoint network namespace/cgroup and configure:

```bash
export NETA_SENSOR_MODE=broker
export NETA_ENDPOINT_SLOT=lnx-0002
export NETA_SENSOR_BROKER=/run/neta/sensor-broker.sock
```

The existing `make_lifecycle_observer()` and `make_process_exec_observer()` factories then return broker-backed observers. Downstream connection tracking, evidence generation, rules, findings, local SQLite state, fleet identity and NAP/mTLS remain the normal production implementation.

## Isolation invariant

An event is delivered only when its kernel attribution matches the endpoint mapping:

```text
network namespace 4026533002 -> lnx-0002 lifecycle queue
cgroup 93828411              -> lnx-0002 process queue
```

An event with an unknown namespace/cgroup is not guessed or broadcast; it increments the broker's unroutable counter.

The deterministic test suite checks that an event routed to `lnx-0002` cannot be consumed by `lnx-0001`, and vice versa.

## Queue semantics

Each endpoint/stream queue is bounded. When full, the oldest pending event is discarded and the queue drop counter increments. A slow endpoint therefore cannot block the host-wide sensor or other endpoints.

Phase 2 should expose these broker queue-loss counters as endpoint telemetry-degradation evidence.

## Security boundary

The broker socket is host-local. It is not a NAP network protocol and must not be exposed externally. The simulator deployment should restrict the socket path using filesystem permissions and run the broker with only the privileges required to load/consume the native Linux sensors.

## Next phase

`neta-lab` Phase 2 should create persistent Linux endpoint slots with:

- cgroup v2 subtree per endpoint;
- network namespace + veth per endpoint;
- IP lease/persona state;
- independent AgentId/certificate/state directory;
- real broker-mode `neta-agent` process;
- scenario processes placed in the same endpoint cgroup/network namespace;
- automatic discovery of netns inode and cgroup ID;
- 3 -> 10 -> 50 -> 100 -> 250 -> 500 endpoint scale progression.
