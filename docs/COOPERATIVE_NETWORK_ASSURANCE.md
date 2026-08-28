# Cooperative Network Assurance

## Purpose

This milestone extends `neta-agent` from single-host connection assurance into a cooperative network of agents that can share critical findings, request independent corroboration, retain selected evidence centrally, and derive fleet-wide conclusions without abandoning the project's evidence-first design.

The key principle remains unchanged:

> Agents share observations and evidence. They do not blindly share conclusions as truth.

Every fleet-level conclusion should remain inspectable and reproducible from the evidence, provenance, baseline state, and rule set that produced it.

---

## 1. Architecture

```text
                         NETA COOPERATIVE NETWORK

       Host A                  Host B                  Host C
   +------------+          +------------+          +------------+
   | neta-agent |          | neta-agent |          | neta-agent |
   |            |          |            |          |            |
   | local      |          | local      |          | local      |
   | evidence   |          | evidence   |          | evidence   |
   | baseline   |          | baseline   |          | baseline   |
   | verdicts   |          | verdicts   |          | verdicts   |
   +-----+------+          +-----+------+          +-----+------+
         |                       |                       |
         +---------------+-------+---------------+-------+
                         |                       |
                         v                       v
                signed finding exchange    targeted probes
                         |                       |
                         +-----------+-----------+
                                     v
                         +---------------------+
                         | Cooperative Store   |
                         |                     |
                         | findings            |
                         | evidence summaries  |
                         | corroborations      |
                         | historical changes  |
                         +----------+----------+
                                    |
                                    v
                         fleet-wide hypotheses
```

The central component is optional. A small trusted deployment may use direct peer communication. Larger deployments will normally use a collector/store for retention, indexing, fan-out, policy enforcement, and fleet-level correlation.

---

## 2. What should be shared

Most raw observations should stay on the originating host.

The cooperative protocol should initially define a small set of exchange objects:

```text
FindingAnnouncement
CorroborationRequest
CorroborationResponse
EvidenceSummary
EvidenceBundle
```

A normal agent should not upload every TCP snapshot, every process observation, or every ordinary connection.

Instead, an agent that detects a meaningful change can publish a compact signed finding.

Example:

```text
FIND-8331

target:
    api.example.com:443

window:
    13:41:12-13:41:18 UTC

changes:
    origin_as_changed
    tls_spki_changed
    rpki_invalid

agent:
    AGENT-A

evidence_root:
    SHA256: ...

confidence:
    0.86
```

The announcement is a claim backed by evidence, not a globally accepted fact.

---

## 3. Independent corroboration

The main value of multiple agents is independent verification.

Suppose one endpoint observes:

```text
api.example.com

previous ASN: AS13335
current ASN:  AS64530

previous SPKI: 91ab...
current SPKI:  c712...

RPKI: INVALID

Trust: SUSPICIOUS
```

The reporting agent can request contemporaneous checks from selected peers:

```text
AGENT-A
  |
  | "I observe origin AS64530 / RPKI INVALID"
  |
  +--------------> AGENT-B
  +--------------> AGENT-C
  +--------------> AGENT-D

AGENT-B: AS13335 / VALID
AGENT-C: AS64530 / INVALID
AGENT-D: AS13335 / VALID
```

This provides information that a single endpoint cannot obtain.

Possible interpretations include:

- geographically localized routing change;
- ISP-specific route leak;
- partial route hijack or misannouncement;
- localized DNS manipulation;
- CDN or infrastructure migration affecting only some vantage points;
- local-network effects at the reporting endpoint.

The fleet engine should retain the differing observations instead of collapsing them into one value.

---

## 4. Host, site, and fleet scopes

Cooperative evidence introduces three useful reasoning scopes.

```text
HOST
    What changed for this endpoint?

SITE
    What changed for this office, VPC, subnet, or network?

FLEET
    What changed across independent agents?
```

Example: if a certificate changes for 113 of 200 globally distributed agents at approximately the same time, the event is likely a broad service-side change.

If only four machines in one office observe simultaneous changes to gateway identity, DNS server, and TLS issuer, the incident is much more likely to be local to that site's network path.

This scope classification should become an explicit part of fleet-level incident state.

---

## 5. Cooperative probing

Agents can also act as distributed diagnostic vantage points.

A corroboration request should be tightly constrained to known diagnostic operations such as:

```text
TLS handshake
DNS resolution
TCP connect latency
route/path probe
destination ASN lookup
RPKI validation
```

For example:

```text
                    api.example.com
                          ^
             +------------+------------+
             |            |            |
         London         Tel Aviv      Virginia
         Agent-12       Agent-41      Agent-77

RTT        28 ms          67 ms         19 ms
TLS        SPKI A         SPKI B        SPKI A
ASN        AS13335        AS64501       AS13335
RPKI       VALID          INVALID       VALID
```

This immediately suggests that the Tel Aviv observation is localized rather than global.

The long-term capability resembles a private measurement network focused on actual endpoint connection assurance rather than generic active network measurement.

---

## 6. Local and cooperative storage tiers

The distributed design should deliberately avoid centralizing all telemetry.

### Local agent database

Keep detailed data such as:

```text
connections
TCP snapshots
process identity
detailed route evidence
local baselines
full evidence bundles
full verdict inputs
```

### Cooperative store

Retain selected fleet-relevant information such as:

```text
important findings
target identity changes
anomaly fingerprints
agent corroborations
evidence hashes
selected evidence bundles
fleet baseline summaries
incident scope state
```

This creates a useful storage invariant:

> Normal network history is local by default; significant shared findings are centralized selectively.

A production target might result in only a small fraction of connections ever being represented in the cooperative store.

---

## 7. Shared finding model

A conceptual data structure is:

```cpp
struct SharedFinding {
    FindingId id;

    AgentId reporter;

    TargetIdentity target;
    TimeWindow observed;

    FindingKind kind;

    Severity severity;
    double rule_confidence;

    std::vector<EvidenceDigest> evidence;

    RuleSetId rule_set;
    Hash rule_set_hash;

    Hash local_evidence_root;

    Signature signature;
};
```

The cooperative system should exchange semantic evidence types rather than platform-native details whenever possible.

---

## 8. Agent identity and signed findings

Single-host SHA-256 evidence hashes provide replay and integrity checking, but distributed evidence needs stronger provenance.

Each agent installation should eventually have a cryptographic identity:

```text
AGENT-41
    private key
       |
       +-- stored locally

    public key
       |
       +-- registered with fleet
```

Shared findings and evidence manifests should be signed.

This allows a collector or another peer to verify that a claimed observation really originated from a particular registered agent.

For private enterprise deployments, the preferred direction is:

```text
mTLS
+
agent certificates
+
signed evidence manifests
```

rather than inventing a custom transport or cryptographic protocol.

The signature covers authorship and tamper detection. It does not by itself prove that an honest agent observed the real-world event correctly; evidence fidelity and independent corroboration remain necessary.

---

## 9. Vantage independence

Ten identical alerts do not necessarily equal ten independent confirmations.

The system should retain metadata describing the independence of corroborating agents.

Useful dimensions include:

```text
host identity
site / LAN
public source ASN
provider
region / country
cloud / residential / enterprise network
collection method
```

Conceptually:

```text
same host             weak additional corroboration
same LAN              limited independence
same ISP/ASN          partial independence
different ASN         stronger independence
different geography   stronger independence
independent source    strongest independence
```

The initial implementation should avoid hiding this behind a single opaque reputation score. Instead, report explicit agreement and diversity.

Example:

```text
ROUTE_OR_ENDPOINT_ANOMALY

Evidence:
  4 exact endpoint observations
  7 supporting TLS observations
  3 independent route observations

Agreement:
  12 / 14 agents

Geographies:
  5

Networks:
  4 source ASNs
```

This is substantially stronger than merely reporting that 12 devices raised the same alert.

---

## 10. Fleet-level evidence graph

The single-host evidence graph naturally extends into a fleet graph.

```text
AGENT-12 ----reported----> FIND-91
                               |
                               +----about----> TARGET-A
                               |
AGENT-41 --corroborates--------+
                               |
AGENT-77 --contradicts---------+
                               |
                               +----supported_by----> EV-SUMMARY-1
                               +----supported_by----> EV-SUMMARY-2
                               |
                               +----classified_as---> INCIDENT-17
```

The shared graph should preserve contradictions.

If one vantage sees a changed TLS identity and another does not, both observations remain first-class evidence.

---

## 11. Fleet-level incident reasoning

The cooperative service should correlate findings by target and time window.

For example:

```text
10:31:04 Agent-12 path identity changed
10:31:05 Agent-12 RTT increased
10:31:08 Agent-12 RPKI INVALID
10:31:10 Agent-41 reports same origin ASN
10:31:12 Agent-77 reports original origin ASN
10:31:18 Agent-88 reports original TLS SPKI
```

These should become one distributed incident rather than unrelated alerts.

A fleet verdict might then say:

```text
INCIDENT-77

Target:
    api.example.com:443

Trust:
    SUSPICIOUS

Scope:
    PARTIAL / LOCALIZED

Hypothesis:
    ROUTE_OR_ENDPOINT_IDENTITY_ANOMALY

Corroboration:
    2 anomalous
    2 normal
    3 source ASNs represented

Causality:
    not established
```

As with single-agent verdicts, this result should reference a versioned rule set and exact input findings.

---

## 12. Privacy and sharing policy

A distributed endpoint product can easily over-collect sensitive data if privacy is not built into the protocol.

Agents should not indiscriminately upload:

```text
all domains visited
all destination IPs
process names
user identities
internal hostnames
raw DNS traffic
complete application histories
```

Sharing policy should be explicit and configurable.

Example:

```text
share.normal_connections = false
share.internal_targets = false
share.process_identity = fleet_only
share.raw_dns = false
share.critical_findings = true
share.corroboration = true
```

Deployment modes may eventually include:

```text
LOCAL
    nothing leaves host

PRIVATE_FLEET
    selected evidence shared within organization

FEDERATED
    selected redacted findings exchanged across trusted fleets

PUBLIC
    explicitly published findings only
```

The first implementation should stop at `PRIVATE_FLEET`.

Public federation creates significantly harder questions around privacy, abuse, authentication, trust, rate limiting, poisoning, and disclosure policy.

---

## 13. Security boundaries

Cooperative probing must not become an arbitrary distributed scanner.

Requests should therefore be constrained by policy and protocol design:

- bounded probe types;
- bounded destinations;
- rate limits;
- authenticated requesters;
- target allow/deny policy;
- audit history;
- no arbitrary shell execution;
- no remotely supplied executable probe code;
- no general-purpose port scanning command;
- no automatic propagation of untrusted instructions between agents.

The responding agent decides whether a request is permitted locally.

A central collector must never obtain an implicit ability to execute arbitrary commands on endpoints merely because the endpoints participate in cooperative assurance.

---

## 14. Failure and adversarial cases

The distributed design must expect conflicting or malicious data.

Examples include:

```text
compromised agent publishes false findings
collector receives duplicate findings
agent clock is incorrect
agent is temporarily offline
multiple agents share the same NAT/ISP path
an attacker attempts finding floods
an old valid finding is replayed
rule versions differ between agents
baseline versions differ
probe target changes during corroboration
```

Required metadata should therefore include at least:

```text
agent identity
observation timestamp
monotonic ordering where locally meaningful
message ID
finding ID
evidence digest
rule-set ID/hash
baseline snapshot reference
signature
schema version
expiry / freshness policy where appropriate
```

Central conclusions should not silently discard evidence produced under a different rule or schema version.

---

## 15. Cooperative protocol flow

A typical incident can follow this sequence:

```text
1. Agent A observes an anomaly.

2. Agent A produces local immutable evidence.

3. Local deterministic rules produce a finding.

4. Agent A signs and publishes a compact FindingAnnouncement.

5. Fleet service determines whether independent corroboration is useful.

6. Selected agents receive bounded CorroborationRequest messages.

7. Each selected agent independently measures the target.

8. Agents sign CorroborationResponse objects.

9. Fleet service groups all related observations into an incident.

10. Fleet deterministic rules classify scope and hypothesis.

11. Selected full evidence bundles are requested only if needed.

12. The complete incident remains replayable from retained inputs.
```

---

## 16. Example distributed incident

A useful target demo is three geographically separated agents:

```text
WSL / Israel
AWS Virginia
AWS Europe
```

Deliberately create a TLS, DNS, route, or endpoint identity anomaly visible to only one vantage point.

Expected output:

```text
INCIDENT-91
api.lab.example:443

Reporter
  Tel Aviv / Agent-1

Observed
  TLS SPKI changed
  route identity changed

Independent corroboration
  Virginia / Agent-2       NOT OBSERVED
  Frankfurt / Agent-3      NOT OBSERVED

Scope assessment
  LOCALIZED

Likely scope
  reporter network / route

Performance
  normal globally

Trust
  suspicious at one vantage

Evidence
  3 independently signed responses
```

This demonstrates a capability that neither ordinary single-host network diagnostics nor generic endpoint alerts provide well: evidence-backed determination of whether a network or trust anomaly is local, regional, or global.

---

## 17. Implementation phases

This work should not disrupt the current single-agent POC.

### Phase 1 — Single-agent foundation

```text
exact local evidence
baseline engine
replayable verdict
local SQLite history
```

This remains the prerequisite.

### Phase 2 — Agent identity

Add:

```text
agent key pair
stable agent ID
signed finding manifests
verification API
```

### Phase 3 — Private fleet collector

Add:

```text
finding ingestion
agent registry
fleet history
indexed target findings
retention policy
```

Do not upload ordinary connection telemetry by default.

### Phase 4 — Corroboration protocol

Add:

```text
CorroborationRequest
CorroborationResponse
request policy
rate limits
result signing
```

### Phase 5 — Distributed probing

Support selected vantage checks for:

```text
DNS
TCP connect
TLS
route/path
ASN
RPKI
```

### Phase 6 — Site/fleet verdict engine

Add deterministic rules capable of distinguishing:

```text
HOST_LOCAL
SITE_LOCAL
REGIONAL
GLOBAL
INSUFFICIENT_EVIDENCE
```

and of retaining contradictory observations.

### Phase 7 — Optional federation

Only after the private-fleet model is mature should the project consider evidence exchange between independently administered organizations.

Federation requires separate design work for privacy, abuse resistance, trust roots, disclosure policy, identity, poisoning resistance, reputation, and revocation.

---

## 18. Architectural evolution

The project can evolve without replacing its original data model:

```text
Connection Evidence Graph
        |
        v
Host Assurance
        |
        v
Fleet Evidence Graph
        |
        v
Cooperative Network Assurance
```

The distributed system is therefore not a separate product architecture. It is a higher-level projection of the same immutable, provenance-aware observations already produced by individual agents.

The essential invariant remains:

> Local collectors produce evidence. Deterministic engines interpret it. Cooperative agents independently corroborate it. Shared infrastructure stores and correlates evidence, but does not turn another agent's conclusion into truth merely because it was received over the network.
