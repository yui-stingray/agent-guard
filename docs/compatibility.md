# Compatibility

`agent-guard` is still in `0.x`, but its public evidence contract is treated as
a compatibility surface. The project can add new optional fields, new optional
artifacts, and new schema versions, but the promise is explicit: v1 consumers
keep working across 0.x releases.

This page documents the current emitted artifacts, the schema version each one
uses, volatile fields consumers must ignore, and the compatibility promise for
downstream wrappers.

## Execution Platforms

The Python CLI supports the Windows and POSIX process-containment behavior
described below. The packaged composite GitHub Action currently requires a
Linux runner; it fails before evidence mutation on other runner operating
systems. The copyable `examples/evidence_contracts_ci.sh` consumer requires a
POSIX host. These wrapper limits do not restrict the language or operating
system represented by the repository files being scanned, and they do not
reduce the Python CLI's Windows support.

Isolated scanner workers use `forkserver` on POSIX hosts where it is available
and otherwise use `spawn`; they do not automatically select `fork` because the
parent process may contain Python or native threads whose locks must not be
inherited. Programmatic entry points must therefore use the normal
`if __name__ == "__main__":` guard. The packaged CLI and Action entry points
already provide that guard.

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

Public-safe is a bounded sanitization contract over declared controlled fields
and controlled patterns. It is not a generic guarantee that an artifact contains
no secrets or PII, and it does not replace dedicated secret scanners.

API, content, and path policies also have fail-closed resource ceilings. The
current implementation accepts policy files up to 256 KiB and at most 64
policy-controlled regular expressions per scanner, bounds include lists and
filesystem walks, rejects repository-scoped include targets that resolve
outside the repository root, and limits each isolated matching run to five
seconds after worker startup. Registered and preregistration content target
walks also share a monotonic five-second enumeration deadline and charge
directory entries plus pattern/path glob-state work against the fixed traversal
budget. Isolated result messages are capped at 16 MiB;
scanner-specific budgets stop oversized finding sets before materialization,
and supported POSIX workers lower their address-space ceiling to 512 MiB. API
directory walks charge `scandir` entries incrementally and prune lexical
exclusions before resolving selected paths. API and content reads are
additionally bounded to 1 MiB per file. Exceeding a
ceiling is a sanitized configuration/runtime error
with exit `2`; raw patterns, paths, or file contents are not included in the
error. These ceilings are implementation safety limits, not evidence-schema
fields or a promise of generic content/credential scanning.

Workflow inputs use the same fail-closed approach. Workflow policies are capped
at 256 KiB, individual policy strings at 4 KiB, and workflow files at 1 MiB.
Distinct workflow input is capped in aggregate, while duplicate normalized paths
share one descriptor-bound read and parse without merging their independent
check identities. YAML aliases, nodes, depth, and the constructed object graph
are bounded; YAML merge-key expansion is rejected. Jobs, steps, active shell
commands, traversal, comparison work, findings, and serialized finding size also
have fixed ceilings checked before result construction. The command recognizer
tracks supported quoting,
substitutions, arrays, continuations, comments, and here-documents across lines;
unsupported or unterminated shell structure is a sanitized exit `2`. This is a
bounded lexical contract, not a complete Bash interpreter or proof of workflow
exit behavior.

Git metadata and content-diff commands use bounded output and deadlines in an
environment that ignores inherited Git routing and global/system configuration,
disables lazy fetch, replace refs, and fsmonitor helpers, and rejects Git
subcommands or diff modes outside the helper-disabled query shapes used by the
static scanners. Windows execution is assigned to a Job Object. POSIX execution
starts a separate session and terminates that process group on completion or
failure; a descendant that deliberately starts another session with `setsid()`
is outside portable process-group containment. Content worktree diffs enumerate
only bounded, validated filter-driver key names, override each discovered
clean/process driver with a non-required empty transform, and disable external
diffs and text conversion. Rename detection is also disabled so configured
rename policy cannot remove added paths from content selection. A supplied
content `--since-ref` is validated and resolved to a commit object id before it
is used in a diff. These controls do not make an attacker-selected executable
earlier on the caller's `PATH` trusted; the Python and Git executables and
installed package environment remain part of the runner trust boundary.

Repository walks are bounded static observations, not filesystem snapshots.
Descriptor-bound API and content reads keep the bytes actually read beneath the
validated repository root, but a concurrent checkout writer can still add or
replace a path after enumeration. Run evidence generation against a quiescent
checkout. Content `new` mode consumes NUL-delimited Git path lists and reads
current working-tree bytes. Every returned Git entry is count-bounded; lexical
policy exclusion and matching happen before selected paths are resolved for
containment. Without `--since-ref`, a selected staged path marked
skip-worktree, assume-unchanged, or fsmonitor-valid is a sanitized exit `2`
error, as is a selected staged path that differs between the index and working
tree after repository-configured external filters and text conversion have been
disabled. Built-in Git text normalization remains part of that comparison.

Packaged bundle validation accepts at most the seven allowlisted public artifact
names and enumerates only through the first excess entry. Report, standalone
envelope, Markdown, and annotation inputs are capped at 1 MiB each; SARIF is
capped at 4 MiB. Bundle-mode CLI failures use one fixed
sanitized message without echoing an artifact name, file body, or local path.
The public shell examples run that bounded bundle check before report-only
validation or digest inspection. Report-only consumer behavior remains
compatible with earlier releases.

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
| Init plan | `agent-guard.init_plan.v1` | `agent-guard init --json` | none | Starter-file plan output for automation/API use; consumers should treat embedded file content as local setup data, not public review evidence. |

`agent-guard.init_plan.v1` may add optional fields to make write behavior easier
to audit. The opt-in missing-only write mode uses per-file `written` and
`skipped_existing` statuses, `written_count` and `skipped_count`, and
`bundle_state: mixed_unverified` when existing files are preserved. Those
fields are additive local setup metadata. They do not make `init` output public
evidence and do not replace the recommended report, conformance, or
evidence-pack review surfaces.

## Benchmark Result Schemas

The stabilization benchmark suite writes local JSON result artifacts under
`bench/results/`. These are deterministic measurement artifacts, not packaged
runtime schemas. Current AGB benchmark metrics, known gaps, and scope caveats
are reported in [Benchmark Results](benchmark-results.md).

| Artifact | Schema version | Runner | Volatile fields | Stable consumer surface |
| --- | --- | --- | --- | --- |
| Agent-Guard Bench result | `agent-guard.agb_results.v1` | `bench/agb/run.py` | `generated_at` | Case count, overall metrics, per-guard metrics, per-case false positive/negative details, and optional sanitized diagnostics in top-level `benchmark_error` or per-case `errors`. |
| Evidence integrity result | `agent-guard.evidence_results.v1` | `bench/evidence/run.py` | `generated_at` | Overall status, passed/failed counts, and named integrity checks. |
| Taxonomy alignment result | `agent-guard.alignment.v1` | `bench/alignment/run.py` | `generated_at` | Alignment status, emitted/missing counts, and named taxonomy checks. |
| TTFE replay result | `agent-guard.ttfe_results.v1` | `bench/ttfe/run.sh` and `bench/ttfe/run.py` | `generated_at`, `elapsed_ms`, per-command timing fields | Quickstart command count, first nonzero command, failure point, setup metadata, and command records. |

An AGB payload containing top-level `benchmark_error`, or a case with non-empty
or malformed `errors`, is a diagnostic result rather than a measurement result.
Consumers must fail closed before reading its counts or metrics. The bundled
`bench.agb.reporting` helper returns exit `2` and does not render a table for
these payloads. Diagnostic values are sanitized labels and must not be treated
as scanner output, benchmark findings, or valid zero-case scores.

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
