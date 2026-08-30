# NETA Agent Communication Protocol (NAP/1)

## Status

Design summary for the planned NETA cooperative/fleet milestone.

This protocol builds on the existing `COOPERATIVE_NETWORK_ASSURANCE.md` design. It keeps the project's evidence-first model:

> Agents share observations and evidence. They do not blindly share conclusions as truth.

The existing cooperative design defines the fleet concepts, signed findings, corroboration flow, and preferred use of mTLS and agent certificates. The coordinator bootstrap and enrollment procedure below is the proposed NAP/1 mechanism for making that design operational.

---

## 1. Goals

NAP/1 allows multiple `neta-agent` installations to:

- identify themselves cryptographically;
- connect securely to a fleet coordinator;
- publish significant signed findings;
- request independent measurements from selected agents;
- return signed corroboration results;
- exchange compact evidence summaries;
- request full evidence only when necessary;
- retain provenance sufficient for deterministic replay;
- avoid uploading ordinary connection telemetry by default.

The protocol is not intended to turn NETA agents into generic remote-execution or scanning nodes.

---

## 2. Initial topology

NAP/1 should use a coordinator-based topology:

```text
                    Fleet Coordinator
                    /       |       \
                   /        |        \
               Agent A   Agent B   Agent C
```

Agents establish outbound authenticated connections to the coordinator.

Advantages:

- agents do not require public inbound exposure;
- centralized agent registration;
- policy enforcement;
- request fan-out;
- rate limiting;
- deduplication;
- replay protection;
- incident grouping;
- retention and audit;
- easier coordinator redundancy later.

The broader NETA architecture may eventually support direct peer communication, but it is not required for NAP/1.

---

## 3. Transport and cryptographic trust

Do not invent a custom transport or cryptographic protocol.

Preferred transport:

```text
HTTPS / TLS 1.3
+
mutual TLS (mTLS)
+
agent certificates
+
signed finding/evidence manifests
```

Two security layers have different purposes:

### Transport identity

mTLS authenticates the two endpoints participating in the current connection.

### Object provenance

Important protocol objects are signed so that retained findings and evidence remain independently verifiable after the network connection has ended.

A valid signature proves provenance and detects modification. It does not prove that the observation itself was correct; independent corroboration remains necessary.

---

## 4. Coordinator bootstrap

Every agent must initially know:

1. where the fleet coordinator is; and
2. which coordinator identity it is allowed to trust.

Coordinator discovery and coordinator trust are separate concerns:

```text
Coordinator discovery = configuration
Coordinator trust     = cryptographic verification
```

Example bootstrap configuration:

```yaml
fleet:
  coordinator: https://fleet.neta.example:443
  fleet_id: fleet-prod-eu

  trust:
    ca_file: /etc/neta/fleet-ca.pem

  enrollment:
    token_file: /etc/neta/enrollment-token
```

The hostname or address tells the agent where to connect.

The fleet CA tells the agent whether the endpoint it reached is an authorized coordinator.

The agent must not trust a coordinator merely because DNS resolved its hostname.

---

## 5. Fleet trust root

Prefer a fleet CA rather than pinning one coordinator server certificate.

```text
NETA Fleet CA
   |
   +---- coordinator-01 certificate
   +---- coordinator-02 certificate
   +---- coordinator-03 certificate
```

This allows coordinator replacement, failover, and load balancing without reprovisioning trust material on every agent.

A future production deployment can therefore expose:

```text
agents
   |
   v
fleet.neta.example
   |
   v
Load Balancer
  /    |     \
 C1    C2    C3
```

All coordinator instances must present identities valid under the configured fleet trust root.

---

## 6. Agent enrollment

Initial enrollment should be explicit.

Conceptual command:

```bash
sudo neta-agent enroll \
    --coordinator https://fleet.neta.example \
    --fleet-ca ./neta-fleet-ca.pem \
    --token <one-time-enrollment-token>
```

Enrollment flow:

```text
Agent installation
     |
     v
Bootstrap configuration
     |
     +-- coordinator endpoint
     +-- fleet ID
     +-- fleet CA
     +-- one-time enrollment token
     |
     v
TLS connection
     |
     v
Agent verifies coordinator
     |
     v
Agent submits enrollment credential
     |
     v
Coordinator authorizes enrollment
     |
     +-- assigns stable AgentId
     +-- registers agent public identity
     +-- issues/authorizes agent certificate
     +-- provides applicable fleet policy
```

The enrollment token should not remain part of normal authentication after enrollment.

---

## 7. Persistent agent identity

Each enrolled installation eventually has:

```text
AgentId
private key
agent certificate
fleet CA
coordinator endpoint(s)
```

Conceptual local layout:

```text
/etc/neta/
    fleet.conf
    fleet-ca.pem

/var/lib/neta/identity/
    agent-id
    agent.crt
    agent.key
```

The private key remains local.

The authoritative security identity should be bound to the enrolled certificate. A hostname or user-selected label may be useful metadata but must not substitute for authenticated agent identity.

---

## 8. Normal connection

After enrollment:

```text
              mutual TLS
Agent  <--------------------> Coordinator

agent verifies coordinator certificate
coordinator verifies agent certificate
```

The agent establishes the connection outbound.

A persistent authenticated stream, reconnecting HTTPS session, or equivalent bounded transport may later be selected as an implementation detail.

---

## 9. Initial protocol objects

The cooperative design defines these primary exchange objects:

```text
FindingAnnouncement
CorroborationRequest
CorroborationResponse
EvidenceSummary
EvidenceBundle
```

NAP/1 additionally needs small lifecycle/control objects such as:

```text
AgentHello
Heartbeat
EvidenceRequest
Ack
Error
```

These lifecycle objects support operation of the cooperative exchange and should not carry arbitrary commands.

---

## 10. Common message envelope

A message should carry enough information for identity, ordering, expiry, correlation, integrity, and schema evolution.

Conceptual envelope:

```json
{
  "protocol": "neta-agent/1",
  "schema_version": 1,

  "message_id": "0193...",
  "message_type": "CorroborationResponse",

  "agent_id": "AGENT-41",

  "created_at": "2026-08-30T18:07:31.421Z",
  "expires_at": "2026-08-30T18:12:31.421Z",

  "sequence": 18832,
  "correlation_id": "REQ-91281",

  "payload_hash": "sha256:...",
  "payload": {},

  "signature": {
    "algorithm": "...",
    "key_id": "...",
    "value": "..."
  }
}
```

Exact serialization is not fixed by this design summary.

Before signing objects, NAP must define an unambiguous canonical representation.

---

## 11. Finding publication

An agent normally retains detailed evidence locally.

When deterministic local rules detect a meaningful event, it publishes a compact signed `FindingAnnouncement`.

Example:

```json
{
  "finding_id": "FIND-8331",

  "target": {
    "host": "api.example.com",
    "port": 443,
    "transport": "tcp"
  },

  "observation_window": {
    "from": "...",
    "to": "..."
  },

  "changes": [
    "TLS_SPKI_CHANGED",
    "ORIGIN_AS_CHANGED",
    "RPKI_INVALID"
  ],

  "performance_verdict": "NORMAL",
  "trust_verdict": "SUSPICIOUS",

  "rule_set": {
    "id": "trust-rules",
    "version": 7,
    "hash": "sha256:..."
  },

  "evidence_root": "sha256:..."
}
```

The announcement is a claim backed by evidence, not a fleet-wide fact.

Ordinary TCP snapshots, process observations, and routine connection history should not be continuously uploaded.

---

## 12. Independent corroboration

When one finding merits verification, the coordinator may select other agents with useful independent vantage points.

Flow:

```text
1. Agent A observes an anomaly.
2. Agent A creates immutable local evidence.
3. Deterministic local rules create a finding.
4. Agent A signs and sends FindingAnnouncement.
5. Coordinator decides whether corroboration is useful.
6. Selected agents receive bounded CorroborationRequest objects.
7. Those agents independently measure the target.
8. They sign CorroborationResponse objects.
9. Coordinator groups related observations into an incident.
10. Fleet rules classify scope/hypothesis.
11. Full evidence is requested only when required.
12. Retained inputs permit incident replay.
```

Example bounded request:

```json
{
  "request_id": "REQ-91281",

  "target": {
    "host": "api.example.com",
    "port": 443
  },

  "probes": [
    "DNS",
    "TCP_CONNECT",
    "TLS_IDENTITY",
    "ROUTE",
    "ASN",
    "RPKI"
  ],

  "deadline": "...",

  "limits": {
    "max_duration_ms": 10000,
    "max_dns_queries": 3,
    "max_tcp_connections": 3
  }
}
```

---

## 13. Corroboration response

A selected agent performs the requested measurements independently and returns observed values.

Example:

```json
{
  "request_id": "REQ-91281",

  "status": "COMPLETED",

  "observations": {
    "dns": {
      "addresses": ["203.0.113.20"]
    },

    "tcp": {
      "connect_rtt_us": 18341
    },

    "tls": {
      "spki_sha256": "91ab..."
    },

    "network": {
      "origin_asn": 13335,
      "rpki": "VALID"
    }
  },

  "evidence_root": "sha256:..."
}
```

Contradictory observations must be preserved rather than collapsed into one value.

---

## 14. Vantage independence

Multiple identical responses are useful only to the degree that their measurements are independent.

Fleet correlation should retain metadata such as:

```text
host identity
site / LAN
public source ASN
provider
region / country
cloud / residential / enterprise network
collection method
```

Fleet logic may later use this metadata to distinguish:

```text
HOST_LOCAL
SITE_LOCAL
REGIONAL
GLOBAL
INSUFFICIENT_EVIDENCE
```

---

## 15. Evidence exchange

Default behavior:

```text
detailed evidence -> remains endpoint-local
significant finding -> may be shared
evidence summary   -> shared when useful
full bundle        -> requested exceptionally
```

`EvidenceSummary` should contain enough semantic information for fleet correlation without requiring continuous raw telemetry transfer.

`EvidenceBundle` is reserved for cases where deeper investigation, retention, or replay requires the selected underlying evidence.

The cooperative store may retain:

```text
findings
evidence summaries
corroborations
historical changes
fleet baseline summaries
selected full evidence
```

Retention policy should remain bounded.

---

## 16. Security boundaries

NAP/1 must not contain a generic remote command facility.

Forbidden concepts include:

```text
command = "..."
shell = "..."
script = "..."
binary = "..."
```

A `CorroborationRequest` instead selects from explicitly supported probe types.

Initial bounded probes may include:

```text
DNS
TCP connect
TLS identity
route/path
ASN
RPKI
```

Every request must remain subject to:

- agent authentication;
- coordinator authorization;
- local agent policy;
- target restrictions;
- probe allowlists;
- duration/quantity bounds;
- request expiry;
- rate limits;
- replay detection;
- audit history.

An agent must be allowed to reject a request that violates local policy even if the request was authenticated.

---

## 17. Replay and freshness protection

Shared objects should include at least:

```text
message ID
agent identity
creation timestamp
expiry/deadline
sequence or locally meaningful ordering
correlation/request ID
schema version
payload/evidence digest
signature
```

The receiving side should reject or quarantine messages that are:

- expired;
- duplicated;
- improperly signed;
- from revoked/unregistered identities;
- outside permitted protocol/schema policy;
- inconsistent with expected correlation state.

---

## 18. Rule and schema provenance

Fleet conclusions must not silently combine incompatible interpretation contexts.

Shared findings should retain relevant provenance such as:

```text
schema version
collector/probe type
rule-set identity
rule-set version
rule-set hash
baseline reference
evidence root/digest
```

If different agents used different rules or schemas, the fleet system should preserve that fact.

---

## 19. NAP/1 exclusions

The first protocol version should explicitly exclude:

```text
generic remote execution
arbitrary Internet scanning
remotely supplied executable probe code
continuous raw connection upload
continuous PCAP exchange
automatic public peer discovery
automatic trust of coordinator advertisements
Internet federation
unbounded evidence transfer
AI-generated authoritative fleet verdicts
```

These exclusions preserve the NETA evidence-first and deterministic-assurance model.

---

## 20. Coordinator discovery policy

NAP/1 should not automatically discover whom to trust through:

```text
public DNS SRV discovery alone
multicast advertisements
peer advertisements
unauthenticated coordinator broadcasts
Internet-wide discovery
```

DNS may locate an already configured coordinator service name, but it does not establish trust.

The core rule is:

> Coordinator discovery is configuration; coordinator trust is cryptographic. Agent identity is established through authenticated enrollment.

---

## 21. Expected initial deployment

A useful early deployment is:

```text
WSL / Israel agent
AWS Lightsail agent
AWS ARM64 agent
          |
          | outbound mTLS
          v
    Fleet Coordinator
          |
          v
   Cooperative Store
```

This provides multiple vantage points while keeping endpoint databases and detailed evidence local.

---

## 22. Future evolution

After the private fleet model is mature, later work may add:

- redundant coordinators;
- more sophisticated fleet policy;
- stronger certificate lifecycle and revocation;
- site-aware request selection;
- fleet baseline summaries;
- richer evidence manifests;
- direct trusted peer communication where justified;
- federation between independently administered fleets.

Federation requires separate design for:

```text
privacy
abuse resistance
trust roots
identity
revocation
disclosure policy
poisoning resistance
reputation
```

It should not be part of NAP/1.

---

## 23. NAP/1 summary

```text
Transport
    HTTPS + TLS 1.3 + mTLS

Bootstrap
    explicit coordinator endpoint
    fleet ID
    trusted fleet CA
    one-time enrollment credential

Identity
    stable coordinator-issued/registered AgentId
    local private key
    agent certificate

Topology
    outbound agent -> coordinator connection

Primary objects
    FindingAnnouncement
    CorroborationRequest
    CorroborationResponse
    EvidenceSummary
    EvidenceBundle

Operational objects
    AgentHello
    Heartbeat
    EvidenceRequest
    Ack
    Error

Evidence policy
    ordinary telemetry stays local
    significant findings are shared
    full evidence is exceptional

Security
    signed important objects
    bounded probe enum
    local authorization
    expiry
    replay protection
    rate limits
    auditability

Core principle
    observations and evidence are shared;
    conclusions are independently reproducible.
```
