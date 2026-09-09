# RM3.1 — Active Rule-Set Metadata in Findings

## Goal

Ensure every emitted `FindingAnnouncement` carries the metadata of the rule set that was actually active on the endpoint when the finding was produced.

## Required fields

The finding payload `rule_set` object must contain:

- `id`
- `version`
- `revision`
- `hash`

The values must be derived from the endpoint's active rule bundle, not hard-coded placeholders.

## Compatibility

The canonical rule identifiers remain unchanged (`NETA-*`). This work does not alter rule evaluation semantics or coordinator schema compatibility beyond adding the optional/available `revision` field to the emitted JSON object.

## Acceptance

After a centrally managed bundle is installed, a process finding must report the same rule-set ID, version, revision, and SHA-256 shown by `neta-agent fleet rules-status`.

For built-in rules, findings must report built-in rule-set metadata rather than `draft` / `sha256:pending` placeholders.
