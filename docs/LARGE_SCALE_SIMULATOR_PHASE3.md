# Large-Scale Simulator — Phase 3 Windows Sensor Broker

Branch: `large-scale-simulator`

## Scope

Phase 3 adds the Windows host sensor-broker path used by the realistic Windows fleet in `neta-lab`.

The normal Windows agent remains unchanged when `NETA_SENSOR_MODE` is unset or `native`. Broker mode is explicit:

```text
NETA_SENSOR_MODE=broker
NETA_ENDPOINT_SLOT=win-0002
NETA_SENSOR_BROKER=neta-sensor-broker
```

## Architecture

One elevated host broker owns the native Windows ETW lifecycle and process collectors. Endpoint agents consume routed events over a host-local Windows named pipe.

```text
Windows ETW
   |-- TCP lifecycle ------+
   |-- process start/exit -+
                           v
                  WindowsSensorBroker
                       |
          process-tree ownership registry
                       |
          +------------+------------+
          v            v            v
      win-0001     win-0002     win-0003
      neta-agent   neta-agent   neta-agent
```

The broker is started with host-visible endpoint root PIDs:

```powershell
.\neta-agent.exe sensor-broker `
  --pipe neta-sensor-broker `
  --queue-capacity 1024 `
  --map win-0001:8120 `
  --map win-0002:9336 `
  --map win-0003:10444
```

Each mapping is `SLOT:ROOT_PID`.

## Attribution invariant

IP address is not an endpoint identity.

The broker seeds ownership with each process-isolated container's host-visible root/supervisor PID. New process events inherit endpoint ownership from their parent process. A bounded Toolhelp process-parent walk is used only when a PID has not yet been cached, for example during startup races.

Lifecycle events are routed by their ETW process PID through the same ownership registry.

Unknown ownership is never guessed or broadcast. The event is counted as unroutable.

## Named-pipe authentication

The broker pipe is host-local and created with `PIPE_REJECT_REMOTE_CLIENTS`.

A broker-mode endpoint sends its requested endpoint slot during registration. The server calls `GetNamedPipeClientProcessId` and verifies that the actual client process belongs to that endpoint's registered process tree. A client that asks for another endpoint's slot is rejected.

This prevents endpoint isolation from depending on a user-controlled slot string alone.

## Queueing

Each endpoint has a bounded combined lifecycle/process queue. When full, the oldest pending frame is discarded and the endpoint drop counter increases. One slow endpoint cannot block ETW collection for the rest of the host.

The broker reports total queue drops and unroutable events on shutdown.

## Production analysis path

Only host sensor collection is multiplexed. After delivery, the endpoint process uses the normal production NETA path:

```text
broker event
  -> lifecycle/process observer interface
  -> connection/process graph
  -> evidence
  -> production rules
  -> finding
  -> endpoint SQLite
  -> FleetClient / NAP / mTLS
```

The broker does not generate findings.

## Supplemental ETW streams

Phase 3 intentionally does not start one DNS Client ETW or Schannel ETW session per simulated endpoint. In broker mode those two observer factories report explicit `UNAVAILABLE` capability with a Phase-3 reason.

They remain fully native in normal Windows mode. A later broker protocol revision can multiplex DNS/Schannel while preserving the same endpoint ownership model.

## Code organization

The Phase-3 implementation is intentionally split by responsibility:

- `windows_sensor_broker.hpp` — public declarations only;
- `sensor_broker_protocol.*` — fixed versioned local wire format;
- `sensor_broker_process_registry.*` — PID/process-tree endpoint ownership;
- `sensor_broker_router.*` — bounded endpoint queues;
- `sensor_broker_pipe.*` — named-pipe transport helpers;
- `sensor_broker_client.cpp` — broker-backed lifecycle/process observers;
- `sensor_broker_supplemental.cpp` — explicit broker-mode capability gaps;
- `sensor_broker_factory.cpp` — native/broker factory selection;
- `sensor_broker_server.cpp` — broker command/server orchestration.

Headers contain declarations, type definitions, templates, or explicitly inline helpers only; implementation code remains in `.cpp` translation units.

## Validation

The deterministic Windows test validates:

- process-tree inheritance from endpoint root PID;
- endpoint ownership isolation;
- lifecycle/process protocol round trips;
- bounded queue oldest-drop behavior;
- unroutable accounting.

The full ten-endpoint process/network isolation acceptance lives in `neta-lab` and requires a Windows Server container host.

## Future memory collection

The process ownership registry is deliberately reusable by a future privileged process-memory collector. Before emitting process-memory evidence, the collector can resolve the target host PID to an endpoint slot through this same registry. Kernel-memory evidence remains host-scoped because process-isolated Windows containers share a kernel.
