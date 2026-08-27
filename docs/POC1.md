# POC1 design contract

POC1 proves one claim: for a real outbound Linux TCP connection, `neta-agent` can identify the process/socket, record immutable/sparse transport and trust evidence, compare it with an explicit baseline, and produce a replayable Performance + Trust verdict.

## Data path

```text
application ------------------------------> Internet
    |                                           
    | kernel owns actual TCP socket             
    v                                           
Linux networking stack                          
    ^                                           
    | SOCK_DIAG / INET_DIAG_INFO               
    |                                           
neta-agent                                      
    |-- /proc socket inode -> process           
    |-- rtnetlink -> selected local route       
    |-- independent TLS probe (SUPPORTING)      
    `-- bounded local SQLite history
```

No proxy, traffic redirection, packet capture, LD_PRELOAD, firewall interception, or remote cooperation is required.

## Evidence fidelity

- TCP socket and `tcp_info` fields from the actual observed socket: **EXACT**.
- Process attribution reconstructed via socket inode and `/proc/<pid>/fd`: **EXACT** for the matched kernel socket at observation time.
- Kernel-selected route queried near the connection observation: **STRONGLY_CORRELATED**.
- Separate TLS connection performed by `neta-agent`: **SUPPORTING**, relationship `contemporaneous_check_for`, never `certificate_used_by_connection`.

## Connection identity

POC1 stores the strongest available combination of socket cookie, socket inode, 5-tuple, process identity, network-namespace context, and observation time. Five-tuple alone is not considered a stable connection identity because tuples are reused.

## Polling limitation

POC1 uses `SOCK_DIAG` snapshots on a configurable interval (100 ms default). It can miss connections that begin and end between polls. Tests must use long-lived/repeated connections. Minimal eBPF lifecycle capture is the next planned evolution, not part of POC1.

## Storage invariant

The SQLite file is an endpoint-local longitudinal evidence store, not a telemetry warehouse. It is not network-exposed. Normal transport samples are persisted sparsely: state/retransmission changes, material RTT changes, or at most one unchanged sample per second. A configured database cap defaults to 200 MB; pruning removes the oldest normal history before anomalous connections.

SQLite access is encapsulated behind the C++ `HistoryStore` API. The supported user interface is the `neta-agent` CLI and JSON export, not raw SQL.

## Portability invariant

Portable core headers under `include/neta/` use C++20 semantic types (`TcpSnapshot`, `TlsObservation`, `Baseline`, `AssuranceVerdict`). Linux mechanisms such as `inet_diag`, `/proc`, and rtnetlink stay under `src/platform/linux/`. Future Windows/macOS backends should emit the same semantic evidence while honestly advertising unavailable metrics.

## Explicitly deferred

POC1 does not implement eBPF, HTTP inspection, packet capture, DNS interception, QUIC, STAMP, BGP/RPKI, RIPE Atlas, remote-agent correlation, web UI, AI explanation, central/fleet collection, Windows/macOS backends, Wi-Fi analysis, or generic network utility features.
