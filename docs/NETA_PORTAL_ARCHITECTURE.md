# NETA Portal Architecture

## Purpose

The NETA Portal is a future milestone to be implemented after the core `neta-agent`, Threat Emulation Lab, and Cooperative Network Assurance capabilities are mature.

Its purpose is to provide a human-facing fleet observability and analytics plane for an entire network of NETA agents. The portal should visualize the cooperative network, allow drill-down into individual agents and evidence on demand, explore incidents across multiple independent vantage points, and calculate cooperative fleet statistics when requested.

The portal must remain separate from the agent data-collection path and from the cooperative protocol itself. The browser must never communicate directly with agents.

## Product hierarchy

The long-term system should have three clearly separated responsibilities:

- **`neta-agent`** — local measurement, evidence capture, assurance, and bounded cooperative participation.
- **`neta-coordinator`** — fleet registry, cooperative assurance, incident correlation, distributed queries, corroboration, and central read models.
- **`neta-portal`** — visualization, exploration, operator workflows, and fleet analytics.

This preserves the existing evidence-first architecture and prevents UI requirements from coupling directly into kernel collectors or local evidence storage.

## High-level architecture

```text
                         USERS

              +-----------------------+
              |      NETA Portal      |
              |                       |
              | Network Visualization |
              | Node Drill-down       |
              | Incident Explorer     |
              | Fleet Analytics       |
              +-----------+-----------+
                          |
                   read/query API
                          |
              +-----------v-----------+
              |   NETA Coordinator    |
              |                       |
              | Registry              |
              | Query Planner         |
              | Corroboration         |
              | Incident Engine       |
              | Analytics Engine      |
              +-----+-----------+-----+
                    |           |
              +-----v----+  +---v---------+
              |PostgreSQL|  |Evidence/S3  |
              +----------+  +-------------+
                    ^
                    |
          signed selective evidence
                    |
     +--------------+--------------+
     |              |              |
 +---+----+     +---+----+     +---+----+
 | Agent A|     | Agent B|     | Agent C|
 |        |     |        |     |        |
 |SQLite  |     |SQLite  |     |SQLite  |
 |Evidence|     |Evidence|     |Evidence|
 +--------+     +--------+     +--------+
```

Agents communicate with `neta-coordinator`, not with `neta-portal`.

## Two portal data paths

The portal should deliberately separate a **cached fleet view** from **on-demand drill-down**.

### Cached fleet view

The normal network/dashboard view should be backed by a central read model containing compact fleet state such as:

- agent identity and registration;
- online/offline state and heartbeat;
- software version;
- platform and collector capabilities;
- site, region, cloud/provider, and ASN metadata where appropriate;
- current assurance summaries;
- important findings;
- current incident membership;
- corroboration state;
- aggregate counters and freshness metadata.

This allows the topology and status pages to render quickly even with large fleets.

### On-demand drill-down

Detailed local evidence should remain local by default. When an operator selects a node, incident, connection, or finding, the coordinator can issue a bounded live query to the relevant agent when fresher or more detailed data is required.

Typical on-demand data may include:

- active/recent connections;
- latest local assurance state;
- selected evidence records;
- collector capability status;
- recent threat-pattern results;
- connection evidence graphs;
- raw evidence/provenance for explicitly requested items.

The architecture should not continuously replicate every local SQLite database into the portal.

## Network visualization

The portal should visualize more than geography. The same fleet can be projected by different operational dimensions, for example:

- geography;
- site / VPC / LAN;
- source ASN / ISP;
- cloud provider;
- agent relationships;
- active corroboration relationships;
- incident topology;
- observed target topology.

Example incident projection:

```text
                        TARGET-X
                      api.example.com
                           |
               +-----------+-----------+
               |           |           |
           Agent-1      Agent-7     Agent-13
          SUSPICIOUS     STABLE       STABLE
               |           |           |
             ASN A       ASN B       ASN C
```

The visualization must preserve vantage independence. Host, site, ASN, provider, geography, and collector method should remain explicit rather than being hidden inside a single opaque confidence score.

## Node drill-down

A node page should expose a compact agent overview and allow progressive navigation into evidence.

Example fields:

```text
Agent-41

Status
  ONLINE
  last heartbeat: ...

Agent
  version
  architecture
  kernel
  collector mode
  capabilities

Assurance
  Performance
  Trust
  Behavior

Connections
  active
  observed today

Cooperative
  findings reported
  probes requested
  probes answered
  corroborations

Evidence
  locally retained
  centrally shared
  latest evidence root/hash
```

Recommended navigation hierarchy:

```text
Agent
  -> Process
      -> Connection
          -> Evidence Graph
              -> Raw Evidence / Provenance
```

## Incident explorer

A principal portal workflow should answer, visually and with evidence:

> Who observed this condition, who contradicted it, from which independent networks, what evidence supports each observation, and is the phenomenon host-local, site-local, regional, or global?

Incident views should correlate:

- originating findings;
- corroborating and contradicting observations;
- independent host/site/ASN/region counts;
- timestamps and ordering;
- collection capabilities;
- evidence quality and completeness;
- affected targets;
- scope classification.

Initial scope classifications should remain simple and deterministic, for example:

- `HOST_LOCAL`
- `SITE_LOCAL`
- `REGIONAL`
- `GLOBAL`
- `UNKNOWN`

## On-demand cooperative statistics

The portal should support deterministic fleet statistics without precomputing every possible question.

A `Fleet Query Engine` should answer ordinary questions from the cooperative store and perform bounded fan-out to agents only when current/local data is required.

Example requests:

- What percentage of agents currently see a specific TLS identity?
- What is the RTT distribution to a target by region?
- How many independent ASNs corroborate an incident?
- Which agents observed a target identity change?
- Which sites show retransmission degradation?
- How many registered threat-behavior patterns occurred during a time window?
- What percentage of agents support a particular collector capability?
- What is threat-emulation evidence completeness by agent version?

Conceptually:

```text
Portal request
      |
      v
Fleet Query Planner
      |
      +---- central-only query ----------> cooperative store
      |
      `---- bounded live distributed query
                    |
                    +--> Agent A
                    +--> Agent B
                    +--> Agent C
                    |
                    v
               result reducer
                    |
                    v
            traceable result
```

Every result should expose denominator and coverage metadata, not only a final percentage. Useful result metadata includes:

- eligible agents;
- queried agents;
- responding agents;
- missing/unavailable agents;
- unique hosts;
- sites represented;
- ASNs represented;
- regions represented;
- data freshness;
- query start/completion time;
- evidence quality distribution.

This prevents a value such as `91%` from being presented without explaining whether it represents 91 of 100 agents, 10 of 11 agents, or a biased subset of the fleet.

## Cooperative analytics engine

Cooperative statistics should be implemented as a deterministic library/service rather than as ad-hoc SQL distributed throughout portal code.

Initial first-class metrics should include:

- agreement / disagreement / unknown;
- independent corroboration count;
- host diversity;
- site diversity;
- ASN/provider diversity;
- geographic diversity;
- observation coverage;
- evidence quality;
- incident scope;
- temporal correlation;
- collector capability coverage;
- evidence completeness;
- fleet health.

The implementation should favor explainable inputs and outputs over opaque scoring.

## Threat Emulation Lab integration

The future portal should integrate the Threat Emulation Lab as a fleet validation view.

The lab separates performance, trust, and behavior-pattern evidence and provides known ground truth. The portal can therefore measure not only security observations but how trustworthy the fleet's measurement capability itself is.

Example fleet validation view:

```text
HTTPS_BEACON_V1

Agents tested             36
PASS                      28
PASS_WITH_GAP              6
FAIL                       2

Expected observations     3600
Captured                  3571
Coverage                  99.19%

By collector
  eBPF                     ...
  polling                  ...
```

Useful dimensions include:

- threat pattern;
- agent version;
- kernel/platform;
- architecture;
- collector implementation;
- region/site;
- expected versus captured evidence;
- PASS / PASS_WITH_GAP / FAIL.

## Storage architecture

### Agent-local storage

Continue using SQLite for local agent evidence and history where it remains appropriate.

### Fleet/coordinator storage

Use PostgreSQL as the initial central fleet database for:

- agent registry;
- heartbeats;
- capabilities;
- findings;
- corroboration requests/responses;
- incidents;
- topology metadata;
- time-indexed summaries;
- portal users and RBAC;
- query audit/history.

### Large evidence objects

Use object storage such as S3 only for exceptional larger objects, for example:

- exported incident bundles;
- large evidence bundles;
- Threat Emulation Lab ground-truth packages;
- long-lived signed artifacts.

The relational database should retain metadata such as hash, size, provenance, owner agent, schema version, timestamps, and object reference.

Avoid storing arbitrary large blobs directly in PostgreSQL unless a concrete use case justifies it.

## No early graph database requirement

The portal UI is graph-oriented, but the initial source model should remain relational.

Likely tables include:

```text
agents
sites
agent_capabilities

targets
findings
finding_evidence

incidents
incident_findings

corroboration_requests
corroboration_responses

agent_target_observations

evidence_objects
```

Graph projections can be generated dynamically from these relations. A graph database should be considered only if real production traversal workloads later demonstrate that the relational model is insufficient.

## Communication model

For the first production versions, a simple authenticated HTTPS protocol is sufficient.

### Agent -> coordinator

- registration;
- heartbeat;
- capability publication;
- selected finding announcement;
- corroboration response;
- bounded cooperative result publication.

### Coordinator -> agent

- bounded detail query;
- corroboration request;
- selected evidence request;
- capability-aware probe request.

Mutual TLS or equivalent strong agent identity should be used once the cooperative network reaches production maturity.

## Security boundary

The coordinator and portal must never turn NETA into a generic remote administration system.

The cooperative RPC surface must remain bounded, typed, authenticated, auditable, rate-limited, and policy-controlled.

Acceptable examples:

```text
GetAgentSummary
GetConnectionSummary
GetEvidence(id)
RunCorroboration(probeSpec)
RunFleetStatistic(statSpec)
```

Unacceptable design:

```text
Execute(command)
RunShell(...)
```

Agents must retain local authority over which cooperative requests are permitted.

## Portal/coordinator separation

The portal and coordinator should be separate logical services even if they initially run in the same deployment.

```text
                    +-----------------+
                    |   neta-portal   |
                    | UI + REST API   |
                    +--------+--------+
                             |
                    read/query contract
                             |
                 +-----------v-----------+
                 |   neta-coordinator    |
                 | fleet/control/query   |
                 +-----------+-----------+
                             |
                 +-----------v-----------+
                 |   cooperative store   |
                 +-----------------------+
```

This separation allows future consumers such as:

- private enterprise portal;
- public/demo portal;
- CLI clients;
- API consumers;
- research tooling;
- metrics/exporter integrations.

## Recommended milestone order

The real portal should remain a late milestone so that the UI is built on stable evidence and cooperative contracts.

Recommended order:

```text
complete local evidence architecture
        ->
eBPF / lifecycle fidelity
        ->
trust + performance assurance
        ->
inbound/outbound coverage
        ->
threat-emulation lab
        ->
agent cryptographic identity
        ->
private cooperative network
        ->
corroboration protocol
        ->
fleet evidence + incident model
        ->
site/fleet verdict engine
        ->
================================
        NETA PORTAL
================================
        ->
network visualization
        ->
node drill-down
        ->
incident visualization
        ->
cooperative analytics
        ->
on-demand distributed queries
        ->
optional federation/public views
```

## Initial portal milestone breakdown

### Portal P0 — contracts only

- Freeze coordinator/portal API boundary.
- Define agent summary, finding, incident, evidence reference, and statistics result schemas.
- Define freshness and coverage semantics.
- Define authorization/RBAC model.

### Portal P1 — fleet overview

- Agent registry view.
- Online/offline/freshness state.
- Capability/version summaries.
- Basic network/topology visualization.

### Portal P2 — node drill-down

- Agent summary.
- Local/current assurance state.
- Process/connection navigation.
- Bounded evidence retrieval.

### Portal P3 — incident explorer

- Multi-agent incident topology.
- Corroborating/contradicting observations.
- Independent vantage metadata.
- Evidence/provenance navigation.
- Scope classification.

### Portal P4 — cooperative analytics

- Fleet query planner.
- Central statistics.
- Bounded live fan-out.
- Coverage/freshness metadata.
- Deterministic reducers.

### Portal P5 — threat-emulation fleet validation

- Ground-truth versus observed coverage.
- PASS / PASS_WITH_GAP / FAIL fleet statistics.
- Comparison by agent version/platform/collector.
- Measurement-quality regressions.

## Non-goals for the first portal versions

Do not begin with:

- direct browser-to-agent communication;
- continuous replication of every local evidence row;
- arbitrary remote shell execution;
- Kubernetes unless deployment scale actually requires it;
- Kafka or another event bus without demonstrated throughput need;
- Elasticsearch without demonstrated search need;
- ClickHouse without demonstrated analytical-volume need;
- a graph database solely because the UI renders graphs;
- opaque AI-generated fleet verdicts replacing deterministic evidence logic.

## Architectural principle

The portal is not the source of truth for network behavior. NETA agents remain the measurement endpoints, and cooperative assurance remains evidence-first.

The portal's role is to make the fleet understandable:

> visualize who observed what, correlate independent vantage points, expose the evidence behind each conclusion, and calculate fleet-level statistics without sacrificing provenance, coverage, or local agent autonomy.
