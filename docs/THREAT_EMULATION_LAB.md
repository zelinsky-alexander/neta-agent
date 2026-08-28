# neta-agent Threat Emulation Lab — Milestone Plan

_Last updated: 2026-08-28_

This milestone extends `neta-agent` from controlled performance/trust validation into a **threat-emulation evidence lab**. The purpose is not to run real malware or to turn the agent into an IDS/NDR product. The purpose is to reproduce well-defined network behaviors associated with known threat techniques in a controlled environment and verify that `neta-agent` records the expected evidence patterns correctly.

The design follows the existing architectural invariants in [`DESIGN_AND_ROADMAP.md`](DESIGN_AND_ROADMAP.md): collectors record observations, evidence retains provenance and fidelity, and deterministic interpretation happens later.

## 1. Milestone objective

The central claim to validate is:

> `neta-agent` can observe controlled threat-like network behavior on real endpoint connections, preserve the relevant evidence, compare that evidence with known ground truth, and identify reproducible behavioral patterns without claiming malicious intent that the evidence cannot establish.

This milestone therefore adds a new validation dimension alongside the existing performance and trust dimensions:

```text
                   REAL CONTROLLED CONNECTIONS
                              |
                              v
                         neta-agent
                              |
          +-------------------+-------------------+
          |                   |                   |
          v                   v                   v
     connection          transport            identity
     + process           evidence             evidence
          |                   |                   |
          +-------------------+-------------------+
                              |
                              v
                       Evidence Graph
                              |
                 +------------+------------+
                 |                         |
                 v                         v
           Assurance rules          Threat-pattern rules
                 |                         |
                 v                         v
        Performance + Trust       Behavior classification
```

The two result paths are intentionally independent.

A connection may remain:

```text
Performance: NORMAL
Trust:       STABLE
```

while separately matching:

```text
Pattern: PERIODIC_OUTBOUND_HTTPS
ATT&CK mapping: T1071.001-compatible behavior
```

That must **not** automatically become:

```text
MALWARE
CONFIRMED C2
COMPROMISED HOST
```

because those conclusions require evidence beyond the observed network pattern.

## 2. Safety and scope boundary

The lab should emulate **observable behavior**, not deploy operational malware.

Allowed milestone scenarios use:

- benign local emulator processes;
- generated non-sensitive payloads;
- controlled local or remote endpoints;
- controlled TLS certificates;
- controlled proxy services;
- network impairment tools such as `tc netem` in lab-owned environments;
- deterministic timing and transfer patterns.

The milestone does **not** require:

- malware samples;
- exploit delivery;
- credential theft;
- persistence mechanisms;
- destructive payloads;
- uncontrolled scanning;
- probing unrelated third-party infrastructure;
- real data exfiltration;
- public C2 infrastructure.

The emulator should make ground truth easy to know exactly.

## 3. Why threat emulation belongs in neta-agent

The project's differentiator is not simply collecting TCP statistics. It is building an inspectable evidence record for real endpoint connections.

Threat emulation gives us a disciplined way to answer several important questions:

1. Can the agent reliably observe repeated short-lived connections?
2. Can it attribute those connections to the correct process?
3. Can it detect temporal patterns across multiple connections?
4. Can it distinguish transport degradation from security-relevant behavioral changes?
5. Can it represent endpoint and TLS identity changes without overstating causality?
6. Can evidence completeness be measured against known ground truth?
7. At what point does polling become insufficient and lifecycle event capture, such as eBPF, become necessary?
8. Can an exported evidence bundle replay to the same pattern result later?

The lab therefore becomes both a **security validation environment** and a **measurement-quality test harness** for the core agent.

## 4. Proposed architecture

```text
                      NETA THREAT EMULATION LAB

 +-----------------------+           +------------------------+
 | local emulator        |           | controlled remote lab  |
 |                       |           |                        |
 | beacon                |           | HTTPS endpoint         |
 | downloader            |           | redirector/proxy       |
 | upload client         |---------->| file endpoint          |
 | DNS simulator         |           | TLS variants           |
 | proxy client          |           | slow/lossy endpoint    |
 +-----------+-----------+           +------------+-----------+
             |                                    |
             +------------- REAL TCP -------------+
                              |
                              v
                         neta-agent
                              |
             +----------------+------------------+
             v                v                  v
        connection         TCP evidence       identity
        + process          RTT/retrans        route/TLS
             |                |                  |
             +----------------+------------------+
                              |
                              v
                        Evidence Graph
                              |
                              v
                   Threat Pattern Matcher
                              |
               +--------------+-------------+
               v                            v
          raw assurance                emulation result

     Performance: NORMAL             Scenario:
     Trust: STABLE                   HTTPS_BEACON

                                     ATT&CK:
                                     T1071.001

                                     Expected evidence:
                                     8/9 present
```

## 5. Threat Pattern Matcher

The threat-pattern matcher should remain separate from the normal assurance verdict engine.

The assurance engine answers questions such as:

```text
Is the connection performing normally?
Did endpoint identity change?
Did local route behavior change?
Is supporting TLS validation stable?
```

The threat-pattern matcher answers a different question:

```text
Does this observed sequence of connections resemble a defined behavioral pattern?
```

A result should therefore look like:

```text
Assurance verdict
  Performance: NORMAL
  Trust:       STABLE

Threat pattern
  HTTPS_PERIODIC_BEACON_PATTERN
  confidence: 0.83

Interpretation
  Behavior is compatible with periodic HTTPS command-and-control traffic.
  Malicious intent is NOT established.
```

The final sentence should effectively be an invariant unless stronger non-emulated evidence exists in some future product capability.

## 6. ATT&CK mapping

ATT&CK identifiers are useful as a vocabulary for known behavior, but they should be treated as **behavior mappings**, not proof of compromise.

Initial mappings:

| Scenario | ATT&CK relation | Emulated behavior | Primary expected evidence |
|---|---|---|---|
| HTTPS periodic beacon | T1071.001 | Short HTTPS connections at a deterministic interval | process, repeated destination, timestamps, TCP metrics, TLS identity |
| Ingress transfer | T1105 | Controlled download of a benign generated blob | outbound connection, destination, received bytes, process, TLS |
| Outbound/exfil-like transfer | T1041-like | Controlled upload of generated non-sensitive data | connection, destination, sent/received byte asymmetry, process, TLS |
| Proxy/pivot behavior | T1090-like | Client talks to controlled proxy which reaches another controlled target | process to proxy endpoint, repeated proxy identity, route/endpoint evidence |
| TLS identity substitution | trust validation scenario | Same target hostname, controlled certificate A -> B | SPKI/issuer change, validation state, otherwise stable transport |
| Combined degradation + identity change | compound validation | `netem` impairment plus controlled certificate change | Performance DEGRADED + Trust CHANGED |

The `-like` suffix is intentional where the network behavior alone cannot establish the complete ATT&CK technique semantics.

## 7. Scenario 1 — periodic HTTPS beacon

### Goal

Validate repeated short outbound TLS connections with stable process attribution and measurable temporal regularity.

### Controlled behavior

```text
neta-emulator
      |
      | HTTPS every 5 seconds
      v
controlled-lab.example:443
```

The request body can contain only harmless scenario metadata:

```json
{
  "scenario": "beacon",
  "sequence": 42
}
```

No remote commands are required.

### Expected evidence

```text
PROCESS
  executable = neta-emulator

CONNECTION FAMILY
  destination = LAB_IP:443
  TLS identity = LAB-C2-A
  repeated outbound connections
  interval approximately 5 seconds

TEMPORAL PATTERN
  median interval approximately 5 seconds
  bounded jitter

TRANSPORT
  RTT samples
  retransmission counters
  route information where available
```

### Expected pattern output

```text
Pattern
  HTTPS_PERIODIC_BEACON

ATT&CK mapping
  T1071.001-compatible

Evidence quality
  process attribution       EXACT
  connection timing         EXACT
  TCP statistics            EXACT
  TLS active probe          SUPPORTING
  HTTP semantics            UNAVAILABLE unless explicitly instrumented

Malicious intent
  NOT ESTABLISHED
```

This scenario is particularly important for testing whether the current polling implementation misses short-lived sockets.

## 8. Scenario 2 — ingress transfer

### Goal

Validate evidence associated with a controlled inbound data transfer to a local process.

### Controlled behavior

Serve a generated benign file from the lab endpoint, for example:

```text
4 MiB generated test blob
```

Then perform:

```text
curl
  |
  v
https://controlled-lab.example/file/test.bin
```

### Expected evidence

```text
PROC curl
    |
    +-- opened --> CONN-X

CONN-X
    |- remote controlled-lab:443
    |- received bytes approximately 4 MiB
    |- connection duration
    |- TCP snapshots
    |- route evidence
    `- supporting TLS evidence
```

If exact per-connection byte counters are not yet implemented, this scenario becomes an explicit reason to add them.

### Future extension

When filesystem/process-event evidence exists, the chain can become:

```text
PROCESS
   |
   +---- network connection
   |
   v
DOWNLOAD
   |
   v
FILE CREATED
```

Until then, the agent should state only:

```text
Network transfer observed.
File creation attribution unavailable.
```

Missing evidence is `UNKNOWN`/`UNAVAILABLE`, never silently treated as false or zero.

## 9. Scenario 3 — outbound/exfiltration-like transfer

### Goal

Validate directional byte asymmetry and sustained outbound transfer evidence.

### Controlled behavior

Generate non-sensitive test data locally:

```text
/tmp/neta-lab-generated.bin
```

Upload it to a lab-owned endpoint.

Example expected values:

```text
connection duration       12.8 s
bytes sent                20.1 MiB
bytes received            11 KiB
outbound ratio            99.95%
destination               controlled lab endpoint
TLS                       valid
transport                 normal
```

### Expected output

```text
Performance
  NORMAL

Trust
  STABLE

Threat pattern
  HIGH_OUTBOUND_ASYMMETRY

ATT&CK mapping
  T1041-like network behavior

Malicious intent
  NOT ESTABLISHED
```

This scenario makes per-connection byte accounting a high-value capability for both diagnostics and security evidence.

## 10. Scenario 4 — proxy/pivot behavior

### Goal

Validate that the agent records what the endpoint can actually prove when an application reaches the network through a proxy.

### Controlled topology

```text
emulator
   |
   v
controlled proxy
   |
   v
controlled target
```

From the endpoint's direct socket evidence, the observable peer is the proxy.

The evidence graph should therefore represent:

```text
PROCESS
   |
   +-- opened --> CONNECTION
                      |
                      +-- connected_to --> PROXY
```

It must not assert a direct kernel socket to the ultimate target unless another evidence source establishes that relationship.

This scenario validates evidence-fidelity discipline as much as threat-pattern recognition.

## 11. Scenario 5 — TLS identity substitution

This scenario extends the existing trust tests.

### Controlled behavior

```text
same hostname
same port
same or similar transport behavior
certificate/SPKI A -> certificate/SPKI B
```

### Expected assurance

```text
Performance: NORMAL
Trust:       CHANGED
```

### Expected evidence

```text
baseline SPKI          A
observed supporting SPKI B
certificate validation valid
hostname validation    valid
```

### Expected interpretation

```text
TLS_IDENTITY_CHANGE
```

The active TLS probe is supporting evidence for the real application connection unless exact application-session TLS evidence is available.

## 12. Scenario 6 — combined degradation and identity change

### Goal

Validate independent verdict dimensions under a compound scenario.

Controlled changes:

```text
tc netem delay/loss
+
certificate A -> B
```

Expected result:

```text
Performance: DEGRADED
Trust:       CHANGED
```

The agent must not automatically assert that the TLS identity change caused the transport degradation.

```text
Causal relation between the two:
NOT ESTABLISHED
```

This preserves one of the project's main design principles: correlation and causality are different claims.

## 13. Ground truth is a first-class object

Every lab run should persist its expected behavior independently of what the observer later reports.

Conceptual model:

```text
LabGroundTruth
{
    run_id
    scenario_id
    scenario_version

    emulator_pid
    start_time
    stop_time

    expected_endpoints[]
    expected_connection_count
    expected_timing
    expected_transfer_bytes
    expected_tls_identity

    generated_payload_hashes[]
}
```

Example:

```text
LAB-RUN-104

scenario
  https_beacon_v1

emulator PID
  21842

expected destination
  10.20.0.4:443

expected connection count
  10

expected interval
  5 s

expected TLS identity
  LAB-SPKI-A
```

Ground truth is then compared with observed evidence:

```text
GROUND TRUTH
       |
       | compare
       v
OBSERVED EVIDENCE
       |
       v
coverage / mismatch report
```

Example:

```text
Ground truth connections: 10
Observed connections:       9

Process attribution:        9/9
TCP RTT:                    9/9
Route evidence:             9/9
TLS evidence:               supporting probe present

Missed:
  expected connection at 12:31:25.130

Possible collector limitation:
  connection lifetime 34 ms < polling interval 50 ms
```

This is essential. Without ground truth, the lab can show that the agent produced evidence but cannot quantify what it missed.

## 14. Evidence-pattern definition

Each scenario should eventually have a machine-readable deterministic definition.

Conceptual structure:

```text
ScenarioDefinition
{
    id
    version

    name
    attack_mapping[]

    setup

    expected_evidence[]
    optional_evidence[]
    forbidden_evidence[]

    expected_assurance

    timing_constraints
    timeout

    notes
}
```

A periodic HTTPS scenario might conceptually define:

```text
HTTPS_BEACON_V1

ATT&CK
  T1071.001

EXPECT
  process attribution
  >= 5 outbound connections
  same destination
  periodic timing
  TCP RTT evidence
  supporting TLS observation

OPTIONAL
  exact DNS attribution

EXPECT ASSURANCE
  Performance != FAILED

DO NOT ASSERT
  malware
  command_and_control_confirmed
  compromised_host
```

The first implementation does not require a YAML/JSON DSL. Scenario definitions may initially be compiled into the test/lab code as long as the canonical values are exportable and versioned for replay.

## 15. Pattern matching semantics

Pattern rules should be deterministic and inspectable.

Example:

```text
PERIODIC_OUTBOUND_CONNECTIONS_V1

REQUIRES
  >= 5 connections
  same process identity
  same destination identity

SUPPORT
  median interval within configured range
  low interval variance
  stable destination TLS identity

UNKNOWN
  exact application protocol when not instrumented
```

The matcher should use three-valued semantics:

```text
TRUE
FALSE
UNKNOWN
```

An unavailable signal must not be equivalent to a negative signal.

Example:

```text
exact HTTP request semantics = UNKNOWN
```

not:

```text
exact HTTP request semantics = FALSE
```

## 16. Evidence completeness score

A lab run should report evidence coverage directly rather than hiding missing evidence inside a confidence score.

Example:

```text
Expected evidence
  [x] process attribution
  [x] repeated destination
  [x] five TCP connections
  [x] periodic timing
  [x] TCP RTT evidence
  [x] supporting TLS observation
  [?] DNS-process correlation unavailable

Evidence completeness
  6 / 7 expected categories observed

Scenario
  PASS WITH CAPABILITY GAP
```

Possible statuses:

```text
PASS
PASS_WITH_CAPABILITY_GAP
FAIL_OBSERVATION_MISMATCH
FAIL_SCENARIO_EXECUTION
INCONCLUSIVE
```

These are lab-validation results, not security verdicts.

## 17. Longitudinal threat patterns

The lab should explicitly test behavior across multiple related connections rather than treating every socket independently.

Example:

```text
connection 1 -> known endpoint
connection 2 -> known endpoint
connection 3 -> new lab endpoint
connection 4 -> same new endpoint
connection 5 -> same new endpoint
```

Graph view:

```text
PROCESS-X
  |
  +-- CONN-1 -> known endpoint
  +-- CONN-2 -> known endpoint
  +-- CONN-3 -> NEW endpoint
  +-- CONN-4 -> NEW endpoint
  `-- CONN-5 -> NEW endpoint
```

The pattern matcher can then reason over:

```text
endpoint novelty
+
new TLS identity
+
periodic recurrence
+
stable process attribution
```

without labeling the process as malware.

This is where the connection evidence graph becomes substantially more valuable than a collection of isolated socket records.

## 18. Local and remote lab modes

Both modes are useful.

### Local mode

```text
neta-agent lab run https-beacon --mode local
```

Useful for:

- deterministic CI tests;
- process attribution;
- lifecycle testing;
- storage/replay testing;
- fast development loops.

Localhost alone is insufficient for all routing/trust scenarios.

### Controlled remote mode

```text
neta-agent lab run https-beacon \
    --endpoint https://controlled-lab.example
```

A controlled remote VM can expose, for example:

```text
443   HTTPS normal/beacon/download/upload
8443  alternate TLS identity
8080  plain HTTP test endpoint
```

Optional controlled components:

- proxy endpoint;
- alternate certificate endpoint;
- network impairment via `tc netem`;
- multiple controlled destination addresses.

No scenario should require interaction with unrelated Internet systems.

## 19. Performance/trust behavior matrix

The lab should retain the existing independent assurance dimensions.

```text
                    Trust
                 stable changed
              +--------+--------+
Performance   |        |        |
normal        | normal | TLS-ID |
              +--------+--------+
degraded      | loss   | loss + |
              |        | TLS-ID |
              +--------+--------+
```

Threat-like behavior is then a third orthogonal dimension:

```text
Behavior patterns

periodic HTTPS
large ingress transfer
large outbound transfer
proxy endpoint
endpoint novelty
```

The milestone validates that these dimensions can coexist without one being incorrectly collapsed into another.

## 20. Proposed CLI

The initial user-facing surface can stay compact.

List scenarios:

```bash
neta-agent lab scenarios
```

Run locally:

```bash
sudo neta-agent lab run https-beacon --mode local
```

Run against a controlled remote endpoint:

```bash
sudo neta-agent lab run https-beacon \
  --endpoint https://controlled-lab.example
```

Inspect run:

```bash
neta-agent lab show LAB-RUN-104
```

Compare ground truth with evidence:

```bash
neta-agent lab verify LAB-RUN-104
```

Inspect related connection evidence:

```bash
neta-agent evidence --lab-run LAB-RUN-104
```

Export/replay:

```bash
neta-agent lab export LAB-RUN-104 > lab-run-104.json
neta-agent lab replay lab-run-104.json
```

Exact command names may change as the existing CLI evolves; the required capabilities are more important than this syntax.

## 21. Example report

```text
Threat Emulation
--------------------------------------------------

Scenario
  HTTPS periodic beacon

Scenario version
  https-beacon/1

ATT&CK mapping
  T1071.001-compatible behavior

Ground truth
  expected connections    10
  expected interval       5.0 s
  emulator PID            21842
  destination             10.20.0.4:443

Observed connections
  CONN-81
  CONN-82
  CONN-83
  CONN-84
  CONN-85
  ...

Expected evidence
  [x] process attribution
  [x] repeated destination
  [x] connection recurrence
  [x] periodic timing
  [x] TCP RTT evidence
  [x] supporting TLS observation
  [?] exact DNS attribution unavailable

Pattern result
  HTTPS_PERIODIC_BEACON

Evidence completeness
  6 / 7

Assurance
  Performance: NORMAL
  Trust:       STABLE

Scenario result
  PASS_WITH_CAPABILITY_GAP

Security interpretation
  Network behavior is compatible with periodic
  HTTPS command-and-control traffic.

  Malicious intent is not established.
```

## 22. Storage additions

The existing SQLite evidence model should remain the primary persistence layer.

Likely additions:

```text
lab_scenarios
lab_runs
lab_ground_truth
lab_expected_evidence
lab_pattern_results
lab_observation_matches
```

Relationships should still be expressible through graph edges where useful:

```text
LAB-RUN-104      generated              PROC-12
LAB-RUN-104      expected_connection    GT-CONN-1
PROC-12          opened                 CONN-81
LAB-RUN-104      observed_connection    CONN-81
PATTERN-22       supported_by           EV-91
PATTERN-22       evaluated_for          LAB-RUN-104
```

The lab must not require a separate database service.

## 23. New evidence capabilities this milestone may expose as necessary

Threat-emulation tests are expected to reveal gaps in current observation fidelity.

High-value candidates include:

### 23.1 Per-connection byte counters

```text
bytes_sent
bytes_received
```

Needed for transfer asymmetry and useful for ordinary diagnostics as well.

### 23.2 Stronger lifecycle observation

Current polling may miss very short-lived beacon/download connections.

Ground-truth mismatch should determine whether and when eBPF lifecycle capture becomes necessary rather than adding eBPF merely because it is available.

### 23.3 Exact DNS attribution

Today destination IP and configured target correlation may be available without proving which DNS answer a process used.

Future DNS evidence should distinguish:

```text
configured/correlated target
```

from:

```text
exact process DNS observation
```

### 23.4 Exact application TLS identity

An active TLS probe remains supporting evidence for an application connection.

Future library/application instrumentation may provide exact session identity, but the lab must not upgrade supporting evidence to exact evidence implicitly.

## 24. Implementation phases

### Phase A — lab framework and ground truth

Implement:

- lab run identity;
- scenario registry;
- emulator process launcher;
- deterministic local endpoint;
- ground-truth persistence;
- evidence-to-ground-truth matching;
- `lab show` / `lab verify` reporting.

First scenario:

```text
periodic HTTPS beacon
```

Primary goal: determine how many known connections current polling actually observes.

### Phase B — transfer evidence

Add:

- benign ingress transfer scenario;
- benign outbound transfer scenario;
- per-connection sent/received byte evidence if not already available;
- transfer asymmetry pattern rules.

### Phase C — trust variation

Add:

- alternate certificate/SPKI endpoint;
- trust baseline A -> B scenario;
- compound trust + periodic behavior scenario;
- compound trust + transport degradation scenario.

### Phase D — proxy topology

Add:

- controlled proxy endpoint;
- proxy scenario;
- evidence relationships that distinguish direct socket peer from inferred/known upstream target.

### Phase E — stronger lifecycle capture if justified

Use the accumulated ground-truth mismatch data to decide whether polling is insufficient.

If necessary, add an event-driven Linux lifecycle backend, likely eBPF, while retaining the same normalized evidence model.

The acceptance condition is an actual measurable improvement in ground-truth coverage, not simply successful eBPF integration.

### Phase F — portable threat-emulation validation

Once another OS backend exists, reuse the same scenario and ground-truth model to compare evidence capabilities across platforms.

The pattern definitions remain semantic and must not depend on Linux-specific fields.

## 25. Initial implementation order

Recommended sequence:

1. **Periodic HTTPS beacon — T1071.001-compatible**
2. **Benign remote download — T1105-compatible**
3. **Large controlled outbound upload — T1041-like**
4. **TLS identity replacement + periodic traffic**
5. **Proxy/pivot behavior — T1090-like**
6. **Compound loss/delay + TLS identity change**

This sequence maximizes what can be learned from the current architecture before adding broader instrumentation.

## 26. Acceptance criteria

The milestone is complete when the following are demonstrated reproducibly.

### 26.1 Ground truth

Every lab run records an independent ground-truth definition containing at least:

- scenario/version;
- emulator process identity;
- expected destination(s);
- expected connection count where deterministic;
- expected timing where deterministic;
- expected TLS identity where relevant;
- generated test payload identity/hash where relevant.

### 26.2 Observation coverage

For every deterministic scenario, the report shows:

```text
expected connections
observed connections
matched connections
missed connections
unexpected matching connections
```

### 26.3 Evidence fidelity

Every matched expected observation identifies its fidelity and collection method.

Supporting TLS probes remain explicitly supporting evidence.

Unavailable evidence is reported as unavailable/unknown rather than zero/false.

### 26.4 Pattern reproducibility

Exporting and replaying a lab run using the same evidence and pattern-rule version produces the same pattern result.

### 26.5 Assurance independence

The following combinations can be produced and explained independently:

```text
Performance NORMAL   + Trust STABLE  + beacon-like behavior
Performance NORMAL   + Trust CHANGED + identity-change behavior
Performance DEGRADED + Trust STABLE  + network impairment
Performance DEGRADED + Trust CHANGED + compound scenario
```

### 26.6 No unsupported malicious-intent assertion

Pattern output may say:

```text
compatible with
resembles
matches defined behavioral pattern
```

It must not automatically say:

```text
malware confirmed
C2 confirmed
compromised host
attack confirmed
```

without future evidence specifically capable of supporting such claims.

## 27. Testing strategy

Three layers are needed.

### Unit tests

Test deterministic components without networking:

- scenario definition validation;
- temporal interval matcher;
- byte-asymmetry matcher;
- three-valued evidence handling;
- ground-truth matching;
- evidence completeness calculation;
- replay determinism.

### Local integration tests

Run local client/server pairs to validate:

- process attribution;
- connection discovery;
- repeated connection tracking;
- ground-truth correlation;
- SQLite persistence;
- report generation.

### Controlled remote tests

Exercise:

- real routing;
- remote TLS identity;
- `tc netem` degradation;
- remote download/upload;
- proxy topology.

CI should prefer deterministic local scenarios; remote scenarios can be explicit integration/lab jobs rather than making normal CI depend on external infrastructure.

## 28. Licensing and dependencies

The milestone should prefer the project's existing dependencies and platform APIs.

No threat-emulation framework dependency is required initially. The emulator and matcher can be implemented as original project code using standard C++ and documented platform/library APIs.

If a third-party emulation framework is considered later, its license, maintenance status, security implications, and compatibility with the project's Apache-2.0 license must be reviewed before adoption. GPL, AGPL, SSPL, source-available, or similarly restrictive dependencies should not be introduced without explicit approval.

ATT&CK identifiers and technique names are references/mappings, not source-code dependencies.

Any release intended for publication or commercial use should still receive normal manual license, similarity, security, and legal review.

## 29. Non-goals for this milestone

Do not expand this milestone into:

- a general endpoint detection and response platform;
- signature-based malware detection;
- packet payload inspection;
- full IDS/NDR functionality;
- a SIEM;
- malware detonation infrastructure;
- exploit research infrastructure;
- autonomous threat hunting;
- Internet-wide threat scanning;
- automatic remediation or blocking.

The milestone remains focused on **connection evidence quality and reproducible behavioral validation**.

## 30. Definition of success

The strongest demonstration is not:

```text
neta-agent detected malware
```

It is:

```text
This exact controlled behavior occurred.

This is the independent ground truth.

These are the connections and observations neta-agent captured.

These expected observations were present.
These expected observations were missed.
These capabilities were unavailable.

These deterministic behavioral patterns matched.

These patterns correspond to known ATT&CK-style network behavior.

The Performance and Trust verdicts were evaluated independently.

The exported evidence reproduced the same result offline.

This is what the evidence supports, and this is what it does not support.
```

That demonstrates the core product thesis much more convincingly than adding another collection mechanism or opaque security score.
