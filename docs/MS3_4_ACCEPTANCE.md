# MS3.4 Host/Network Environment Acceptance

MS3.4 adds privacy-conscious, capture-time host/network environment context to each observed connection without changing Trust or Performance verdict semantics.

## Captured evidence

Where available, the Linux collector records:

- domain-separated SHA-256 host identity derived from `/etc/machine-id` (raw machine ID is never persisted);
- hostname;
- boot ID;
- Linux kernel release and architecture;
- environment class (`WSL` when directly identified, otherwise `LINUX_HOST`);
- network namespace inode;
- selected interface index/name, MAC address, and MTU;
- connection local/source address;
- selected gateway and preferred source;
- route table and metric;
- deterministic `neta-env-v2` environment fingerprint over the complete captured context.

Unavailable values remain unavailable/empty; the collector does not invent replacements.

## Persistence model

Environment storage is normalized and deduplicated:

```text
host_identities
    -> host_boots
        -> network_environments
            <- connection_network_environments <- connections
```

Repeated connections in the same captured environment reuse the same `network_environments` row. Connections retain their original environment relation even if the host later observes a different namespace/interface/route context. Storage maintenance removes orphaned environment, boot, and host rows after connection pruning.

The environment observation is `STRONGLY_CORRELATED` context evidence. It is not a Trust verdict input in MS3.4.

## CLI and replay

`history show ID` and `evidence ID` expose the persisted environment and fingerprint.

Export schema version 6 includes the captured environment fields and a `HOST_NETWORK_ENVIRONMENT` evidence entry. Replay reconstructs the canonical environment fingerprint and reports `MATCH` or `MISMATCH`. Environment tampering does not change the verdict input hash or Trust/Performance verdict because MS3.4 environment context is deliberately non-verdict evidence.

Schemas 1-5 remain accepted by replay.

## Automated acceptance

Focused storage tests verify:

- complete environment round-trip;
- host and boot normalization;
- same-environment deduplication across connections;
- distinct environment creation for a changed network namespace/interface/path;
- optional route/interface fields;
- bounded-storage orphan cleanup integration.

Export/replay tests verify:

- schema version 6;
- environment-present and environment-absent bundles;
- canonical environment fingerprint integrity;
- environment tamper detection;
- unchanged verdict when only environment evidence is tampered;
- compatibility with resolver, TLS-session, and inbound mTLS replay behavior.

The repository CI continues to validate both the normal Linux build and `NETA_EBPF=OFF` build.

## Native WSL/Linux acceptance performed 2026-08-31

A controlled WSL2 acceptance used one database across two real Linux network environments on the same host and boot.

Environment 1 (normal WSL namespace):

```text
network namespace: 4026531833
interface:         eth0 (index 2)
MAC:               00:15:5d:a3:a5:8c
MTU:               1500
local/source:      172.22.122.91
gateway:           172.22.112.1
route table:       254
```

Fourteen observed connections reused one environment row:

```text
connections                     14
network_environments             1
connection_network_environments 14
```

Environment 2 was created with a temporary Linux network namespace and veth pair:

```text
network namespace: 4026532283
interface:         neta-veth-ns (index 5)
MAC:               aa:0f:cd:eb:64:2d
MTU:               1500
local/source:      10.200.1.2
gateway:           direct / none
route table:       254
```

After six connections in the second namespace:

```text
connections                     20
network_environments             2
connection_network_environments 20
```

Connections 1-14 remained linked to environment 1 and connections 15-20 linked to environment 2. The two environments had distinct deterministic fingerprints. Hostname, kernel, architecture, boot ID, namespace inode, interface metadata, address, gateway, and route selection were independently cross-checked against Linux (`hostname`, `uname`, `/proc`, `ip link`, `ip addr`, and `ip route get`).

This acceptance demonstrates capture-time historical preservation and deduplication across a real environment change rather than only synthetic unit data.

## MS3.4 completion criteria

MS3.4 is complete when the branch satisfies all of the following:

- host/network evidence is captured during observation;
- privacy-sensitive machine identity is hashed before persistence;
- environment identity changes when material captured environment context changes;
- same environment deduplicates across connections;
- historical connection-to-environment relations remain stable;
- environment evidence is visible through CLI history/evidence;
- schema-v6 export/replay integrity checks the captured environment;
- environment evidence does not independently modify Trust/Performance;
- bounded storage can remove orphan environment records;
- normal and no-eBPF regression suites pass.
