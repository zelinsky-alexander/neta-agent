# RM3 — Adaptive Rule Tuning and Endpoint Baselines

## Goal

Reduce false positives without turning NETA into an arbitrary remote-code rule engine or globally weakening useful detections.

RM3 builds on RM1/RM2 declarative rules with three layers:

1. conservative built-in defaults,
2. endpoint/group scoped overrides and approved baselines,
3. retained analyst false-positive feedback.

The invariant remains:

> The portal/coordinator control declarative policy, while agents execute only trusted compiled evaluators.

## RM3 phases

### RM3.1 — Canonical finding identity

All findings must eventually report the active canonical rule identity and exact active rule-set metadata:

- `NETA-PROC-*`, `NETA-BEH-*`, `NETA-NET-*`, etc.
- active rule-set id/version/revision,
- exact published SHA-256.

Legacy process finding names such as `PROCESS_SHELL_FROM_UNEXPECTED_PARENT` may be accepted during transition but must map to `NETA-PROC-002` in control-plane tuning data.

### RM3.2 — Clear disposition semantics

Keep three concepts separate:

- **exact suppression** — do not recreate the same agent + finding key,
- **false-positive feedback** — retain analyst judgement for tuning,
- **rule/baseline tuning** — a separate staged policy object requiring approval/publish.

A false-positive action must never silently weaken fleet policy.

### RM3.3 — Scoped overrides

Effective policy is layered:

```text
published rule catalog
    + group overrides
    + endpoint overrides
    + approved baseline
    = effective endpoint policy
```

Scopes:

- `GLOBAL`
- `GROUP`
- `ENDPOINT`

Per-endpoint policy should be represented as small deltas, not cloned copies of all rules.

### RM3.4 — Learning mode

Endpoint learning lifecycle:

```text
OFF -> LEARNING -> REVIEW -> OFF
```

Learning records bounded candidate observations. It does not automatically trust them.

Candidate examples:

- process parent -> child relationships,
- recurring executables,
- common destinations/ports,
- DNS patterns,
- TLS peer identities,
- route/gateway/interface patterns.

### RM3.5 — Analyst-approved baseline promotion

Candidate behavior may become an approved baseline or scoped exclusion only after explicit review. Malware or unwanted software present during learning must not become trusted automatically.

### RM3.6 — Platform profiles

Support safer starting profiles such as:

- Linux server,
- Linux workstation,
- WSL,
- Windows workstation,
- Windows server.

Profiles adjust declarative defaults/exclusions only; evaluator code remains compiled and trusted.

### RM3.7 — Confidence and corroboration

Single weak behavioral signals should not automatically become medium/high-confidence findings. Future evaluators should support corroboration across process/network/DNS/TLS/route evidence and expose confidence independently from severity.

## First acceptance case

Known benign WSL example:

```text
/usr/libexec/wsl-pro-service -> /usr/bin/bash
```

Expected RM3 workflow:

1. finding appears under `NETA-PROC-002`,
2. analyst marks it false positive,
3. false-positive feedback is retained separately from exact suppression,
4. analyst can stage an endpoint-scoped parent-process exclusion or baseline candidate,
5. staged policy is not active until approved/published,
6. after approval/update the behavior no longer alerts on that endpoint,
7. the rule remains active elsewhere.

## Initial implementation slice — 2026-09-09

Coordinator RM3 foundation is being introduced on `feature/rm1-central-rule-management` with:

- retained `finding_feedback`,
- staged `rule_overrides`,
- `endpoint_learning_state`,
- `baseline_candidates`,
- transitional legacy-process-rule -> canonical `NETA-PROC-*` mapping for tuning records.

Portal work on the same feature branch separates the explanation of exact suppression from false-positive feedback.

Next agent work is RM3.1: remove hard-coded draft rule-set metadata from emitted findings and report the exact active centrally managed rule set/version/hash.
