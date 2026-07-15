# Compatibility

`agent-guard` is still in `0.x`, but its public evidence contract is treated as
a compatibility surface. The project can add new optional fields, new optional
artifacts, and new schema versions, but the promise is explicit: v1 consumers
keep working across 0.x releases.

This page documents the current emitted artifacts, the schema version each one
uses, volatile fields consumers must ignore, and the compatibility promise for
downstream wrappers.

## Packaged Evidence Schemas

Installed wheels package these JSON Schema resources under
`agent_guard.schemas`.

| Artifact | Schema version | Schema file | Volatile fields | Stable consumer surface |
| --- | --- | --- | --- | --- |
| Shared result envelope | `agent-guard.result.v1` | `agent-guard.result.v1.schema.json` | none | `schema_version`, `tool`, `scanner`, `status`, `exit_code`, `policy`, `summary`, `finding_count`, `findings`, and optional `error`. |
| Context inventory | `agent-guard.context_inventory.v1` | `agent-guard.context_inventory.v1.schema.json` | none | Repository-relative context file metadata and permission-boundary status. |
| Context lock coverage | `agent-guard.context_lock_coverage.v1` | `agent-guard.context_lock_coverage.v1.schema.json` | none | Hash-free coverage counts, covered context files, and digest coverage findings. |
| Sanitized report evidence | `agent-guard.report_evidence.v1` | `agent-guard.report_evidence.v1.schema.json` | none | Public-safe report JSON, including the embedded `report.schema_version` contract marker. |
| Conformance evidence | `agent-guard.conformance.v1` | `agent-guard.conformance.v1.schema.json` | none | Profile, status, required gates/surfaces, counts, and conformance findings. |
| Evidence pack manifest | `agent-guard.evidence_pack_manifest.v1` | `agent-guard.evidence_pack_manifest.v1.schema.json` | none | Sanitized artifact manifest, gate summary, and optional conformance summary. |
| Surface delta evidence | `agent-guard.surface_delta.v1` | `agent-guard.surface_delta.v1.schema.json` | none | Sanitized PR base/head agent-surface delta: added/removed/modified surface entries with controlled-vocabulary `changed_fields` names and risk labels; no raw diffs, base ref names, or instruction/description bodies. |

These schema file names and `$id` values are frozen by tests. A schema version
will not change without a new schema identifier and a documented compatibility
decision.

## Other Emitted Evidence Versions

Some public evidence subdocuments are currently emitted through CLI payloads but
do not yet have standalone packaged schema files. Consumers may use their
`schema_version` as a version marker, but should validate them through the
surrounding packaged report schema until a standalone schema is added.

| Artifact | Schema version | Emitted by | Volatile fields | Notes |
| --- | --- | --- | --- | --- |
| Evidence coverage summary | `agent-guard.evidence_coverage.v1` | `agent-guard report` | none | Records enabled, missing, clean, and failing gates inside report evidence. |
| Agent surface inventory | `agent-guard.agent_surface_inventory.v1` | `agent-guard surface inventory`, report evidence | none | v1 surface metadata used by minimal inventories. |
| Agent surface inventory | `agent-guard.agent_surface_inventory.v2` | `agent-guard surface inventory --schema-version v2`, recommended report evidence | none | v2 adds static MCP, skills, profiles, commands, hooks, and evidence-artifact metadata. |
| Policy/spec drift | `agent-guard.policy_spec_drift.v1` | `agent-guard drift check`, report evidence | none | Repository policy/spec alignment findings. |
| Policy/spec drift | `agent-guard.policy_spec_drift.v2` | `agent-guard drift check --schema-version v2`, recommended report evidence | none | v2 can include baseline-sensitive change evidence when `--base-ref` is supplied. |
| Init plan | `agent-guard.init_plan.v1` | `agent-guard init --json` | none | Starter-file plan output; consumers should treat embedded file content as local setup data, not public review evidence. |

## Benchmark Result Schemas

The stabilization benchmark suite writes local JSON result artifacts under
`bench/results/`. These are deterministic measurement artifacts, not packaged
runtime schemas. Current AGB benchmark metrics, known gaps, and scope caveats
are reported in [Benchmark Results](benchmark-results.md).

| Artifact | Schema version | Runner | Volatile fields | Stable consumer surface |
| --- | --- | --- | --- | --- |
| Agent-Guard Bench result | `agent-guard.agb_results.v1` | `bench/agb/run.py` | `generated_at` | Case count, overall metrics, per-guard metrics, and per-case false positive/negative details. |
| Evidence integrity result | `agent-guard.evidence_results.v1` | `bench/evidence/run.py` | `generated_at` | Overall status, passed/failed counts, and named integrity checks. |
| Taxonomy alignment result | `agent-guard.alignment.v1` | `bench/alignment/run.py` | `generated_at` | Alignment status, emitted/missing counts, and named taxonomy checks. |
| TTFE replay result | `agent-guard.ttfe_results.v1` | `bench/ttfe/run.sh` and `bench/ttfe/run.py` | `generated_at`, `elapsed_ms`, per-command timing fields | Quickstart command count, first nonzero command, failure point, setup metadata, and command records. |

## Volatile Fields

Consumers must ignore these fields for equality, golden-file, and backward
compatibility comparisons:

- `generated_at` in benchmark result artifacts.
- `elapsed_ms` in TTFE result artifacts.
- Per-command timing fields in TTFE command records.
- Tool version fields when comparing one release to another.

The absence of a volatile field in the tables means the project currently
expects byte-stable values for the same repository input and package version.

## Compatibility Promise

For existing v1 artifacts, downstream consumers can rely on these rules across
future `0.x` releases:

- Existing packaged schema files, `$id` values, and top-level `schema_version`
  constants remain available.
- Required fields already present in v1 schemas keep their type and meaning.
- Enum values already emitted by a released version are not repurposed.
- Public evidence continues to omit raw context text, snippets, raw hashes,
  raw workflow bodies, secret values, and absolute local paths.
- New optional fields may be added when they are sanitized and documented.
- New schema versions may be added beside v1. They must not silently replace v1
  output in a way that breaks a v1 consumer.
- Removing a v1 schema, changing its `$id`, or changing a required field's type
  requires a new schema identifier and an explicit release-note compatibility
  decision.

Consumers should fail closed on unknown top-level schema versions, but they
should tolerate additional optional properties allowed by the schema. The
packaged `agent_guard.consumer` module demonstrates that policy for sanitized
report evidence.
