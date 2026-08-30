# AGENTS.md

## Purpose

This file gives coding agents the minimum persistent instructions needed to work efficiently and safely in `neta-agent`.

Keep this file short. Detailed product and architecture requirements live in `docs/` and should be read only when relevant to the current task.

## Work efficiently

- Start from the user's task. Do not perform a broad repository audit unless explicitly requested.
- Inspect only the files and symbols needed for the task. Prefer `rg`, targeted `git diff`, and focused file reads over recursively reading the repository.
- Do not repeatedly reread unchanged documentation or source files in the same session.
- Do not repeatedly run the full test suite while iterating. Use the smallest relevant build/test first; run broader regression tests once the focused work is stable.
- Do not repeatedly reconfigure CMake unless configuration inputs changed.
- Avoid speculative refactors, cleanup, formatting churn, and unrelated documentation edits.
- Do not search the web or external repositories unless the task actually requires external/current information.
- When a command fails, diagnose that failure directly before launching unrelated investigation.
- Prefer one coherent implementation pass followed by focused tests over many tiny exploratory edits.
- Keep progress narration concise. Spend context on code, failures, and decisions.
- Stop when the requested task is complete and validated. Do not invent additional work.

## Repository safety

Before editing, run:

```bash
git status --short
```

If the tree is dirty:

- preserve all existing modifications and untracked files;
- assume they may be valuable user or previous-agent work;
- do not run `git reset`, `git clean`, destructive checkout/restore, or similar commands;
- do not stash existing work unless the user explicitly asks;
- do not run `git pull`, rebase, or branch switching when it could overwrite or complicate a dirty worktree;
- distinguish pre-existing changes from changes made in the current task.

Never discard another agent's unfinished work merely because it is incomplete or does not compile.

## Sources of truth

Read only the documents relevant to the task:

- `docs/DESIGN_AND_ROADMAP.md` — authoritative product scope and milestone roadmap.
- `docs/DESIGN_ARCHITECTURE_MS1_AND_NEXT.md` — architecture, MS1 constraints, and nearest evolution.
- `docs/MILESTONE2.md` — MS2 implementation details when present.
- `docs/COOPERATIVE_NETWORK_ASSURANCE.md` — later cooperative/fleet work only.
- `docs/THREAT_EMULATION_LAB.md` — threat-emulation milestone only.

For an MS2 recovery session, if the repository copy of the handoff is unavailable and
`/home/alex/MS2_CHAT_SUMMARY_AND_CODEX_HANDOFF.md` exists, read that file once at the beginning of the session. Do not `git pull` merely to obtain another copy.

Do not load cooperative-assurance or threat-emulation documents for ordinary MS2 work.

## Architecture invariants

Preserve these boundaries:

```text
LifecycleObserver
        |
        v
ConnectionAdmissionPolicy
        |
        v
ConnectionTracker
        |
        v
EvidenceScheduler
        |
        v
HistoryStore
```

- `ConnectionTracker`: identity, correlation, lifecycle tracking, deduplication.
- `ConnectionAdmissionPolicy`: whether a candidate connection is observed.
- `EvidenceScheduler`: timing of enrichment and transport evidence collection.
- `HistoryStore`: SQLite persistence/history.
- CLI code: parsing and orchestration, not domain logic.

Substantial new responsibilities belong in dedicated `.hpp` / `.cpp` files.

Avoid turning these into monoliths:

```text
src/main.cpp
src/core/connection_tracker.cpp
src/core/observation_session.cpp
src/core/history_store.cpp
```

Portable core code must not depend on Linux kernel/UAPI headers or Linux TCP numeric constants. Map platform-specific values to portable semantics under `src/platform/linux/`.

## Current MS2 invariants

When working on MS2:

- direction is explicit: `OUTBOUND`, `INBOUND`, or `UNKNOWN`;
- local `CONNECT` lifecycle evidence means outbound;
- local `ACCEPT` lifecycle evidence means inbound;
- never infer direction from conventional port numbers;
- a listening socket is service/listener metadata, not an ordinary connection-history object;
- an accepted connected socket is an inbound assurance object;
- fallback connection identity may be promoted to a canonical socket-cookie identity only after unambiguous correlation;
- identity promotion must preserve the logical/history connection and must not create a duplicate;
- ambiguous correlation must remain unresolved rather than guessed;
- missing process start identity stays unavailable; do not convert absence into a meaningful `0`;
- lifecycle event loss/backpressure must be observable rather than silently treated as no event;
- inbound route evidence means the current host response route toward the remote peer;
- the outbound active TLS probe must not be presented as evidence for the actual inbound application's TLS session;
- unavailable evidence must remain unavailable/unknown rather than becoming zero/false.

Do not expand MS2 into DNS/application-TLS instrumentation, packet interception, HTTP inspection, QUIC, cooperative assurance, threat emulation, BGP/RPKI, AI verdicts, or general IDS/NDR functionality.

## Build and test discipline

Use incremental validation.

1. Build the smallest affected target or normal current build.
2. Run the focused test(s) covering the changed behavior.
3. Fix failures before broadening scope.
4. When focused tests pass, run applicable MS0/MS1 regression tests.
5. Before declaring a substantial MS2 change complete, run the applicable broader test suite.
6. Run `NETA_EBPF=OFF` validation for changes that affect portable/non-eBPF behavior.
7. Run BPF-enabled and privileged lifecycle/integration tests only when the environment supports them and the task requires them.
8. Report tests that could not be run; do not imply they passed.

Do not run expensive privileged, high-churn, remote, or full-suite tests after every small edit.

For networking integration tests, prefer deterministic local client/server scenarios. Remote tests should be explicit and purposeful.

## Correctness rules

- Preserve deterministic verdict and replay behavior.
- Keep Performance and Trust evidence/semantics independent.
- Persist actual observed values, not invented substitutes.
- Preserve bounded local storage and bounded long-lived in-memory state.
- If observation stops while a socket still exists, do not falsely record that the socket disappeared.
- Never silently broaden evidence claims beyond what the collector actually proves.

## Dependencies and licensing

The project is Apache-2.0.

Prefer the existing dependency set and documented platform APIs:

- C++20 / standard library
- libbpf
- SQLite
- OpenSSL
- Linux native APIs

Do not add a third-party dependency unless genuinely necessary.

Before proposing any new dependency, report:

- package/project name;
- purpose;
- license;
- maintenance status;
- material security concern;
- why the existing stack is insufficient.

Do not introduce GPL, AGPL, SSPL, source-available, or similarly restrictive dependencies without explicit user approval.

Generate original implementation code from requirements and public/documented APIs. Do not copy substantial code, distinctive structure, comments, or naming from external repositories/tutorials. If third-party code is ever needed, verify license compatibility and required attribution first.

Do not claim generated code is legally cleared or plagiarism-free. Code intended for publication should still receive normal manual license/similarity/security review.

## Editing rules

- Keep diffs narrow and task-related.
- Follow existing naming and formatting in neighboring code.
- Avoid unrelated renames and mass formatting.
- Do not change public semantics merely to make a test pass.
- Add focused tests for meaningful behavior changes.
- Prefer explicit types and three-valued/optional semantics where evidence can be unavailable.
- Comments should explain non-obvious intent or invariants, not restate code.

## Completion checklist

Before saying a coding task is done:

```bash
git diff --check
git status --short
```

Also:

- inspect the final diff for accidental unrelated changes;
- verify focused tests pass;
- run the appropriate regression level for the scope;
- ensure generated/build artifacts are not included;
- make documentation claims match implemented behavior.

Do not commit unless the user requested a commit or the task explicitly authorizes committing.

## Final response

Keep the completion report concise:

- what changed;
- important design choice, if any;
- tests/build commands and outcomes;
- anything not tested and why;
- remaining known issue, if relevant.

Do not dump long command transcripts unless requested.
