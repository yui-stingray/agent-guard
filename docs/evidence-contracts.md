# Evidence Contracts

`agent-guard` is a deterministic static evidence gate for repositories touched
by coding agents. Its report, render-report, standalone surface inventory,
conformance, and evidence-pack commands emit small, sanitized evidence payloads
that maintainers can read in pull requests, store as CI artifacts, or validate
in downstream wrappers without sending repository contents to a model.

> **Version gate:** package `0.3.5` contains the v1 and v2 report/manifest
> contracts, including the guard-owned `agent-guard.public_agent_policy_audit_event.v1`
> profile. Copyable Action examples use the immutable `0.3.5` release commit.
> The Action does not expose audit-event inputs; its generated report and manifest remain v1.
> Unreleased source `0.3.6.dev0` additionally requires consumer `--repo-root`
> for bound v2 evidence; public install examples remain pinned to `0.3.5`.

## Contracts

Installed wheels package these JSON Schema resources under
`agent_guard.schemas`:

- `agent-guard.result.v1.schema.json`: the shared result envelope used by
  scanner JSON output. This envelope is stable, but individual raw scanner
  payloads are not public-safe artifacts by default.
- `agent-guard.context_inventory.v1.schema.json`: redacted metadata for
  discovered agent context files.
- `agent-guard.context_lock_coverage.v1.schema.json`: hash-free evidence that
  discovered agent context files are pinned by digest policy.
- `agent-guard.report_evidence.v1.schema.json` (event-free) and
  `agent-guard.report_evidence.v2.schema.json` (bound audit event): sanitized
  report payloads with agent surface inventory and evidence coverage.
- `agent-guard.conformance.v1.schema.json`: profile evidence for `minimal`,
  `recommended`, and `strict` adoption levels. The `recommended` profile
  requires the first-class `mcp_config` gate; the `strict` profile can also fail
  on deterministic malformed MCP config or risk metadata emitted by the v2
  surface inventory.
- `agent-guard.evidence_pack_manifest.v1.schema.json` (legacy unbound) and
  `agent-guard.evidence_pack_manifest.v2.schema.json` (bound): sanitized manifests.

Installed wheels also include `agent-guard.surface_delta.v1.schema.json`. The
schema covers sanitized PR base/head agent surface delta evidence emitted by
`agent-guard surface delta` and by `agent-guard report --surface-delta-base-ref`.
It is review evidence, not a gate:
added/removed/modified counts and per-surface entries with controlled-vocabulary
`changed_fields` names (never values) and risk labels.

The `v1` schemas are intended to remain stable for downstream consumers.
Compatible tightening may add enum constraints for values already emitted by
`agent-guard`, but raw repository content, hash values, local paths, secrets,
and workflow bodies remain outside the contract.

The sample report in
[`docs/evidence-samples/agent-guard-report.json`](evidence-samples/agent-guard-report.json)
is intentionally public-safe, generated from the latest published package
version, and
validated by the test suite against the packaged schema.
[`examples/evidence_consumer.py`](../examples/evidence_consumer.py) shows a
small downstream wrapper pattern that loads the packaged report schema and
fails closed on incompatible, internally inconsistent, or unsanitized evidence,
including top-level `status` values that are not explained by findings, failing
evidence gates, or conformance findings.
[`docs/evidence-consumer-contracts.md`](evidence-consumer-contracts.md) adds
copyable CI examples for missing/invalid/stale report checks, public-artifact
linting, and strict release gates using the same packaged consumer path.

## Public Artifact Boundary

Public-safe means sanitized under the declared controlled-field/controlled-pattern contract,
not a generic secret/PII absence guarantee or replacement for dedicated secret scanners. It applies to
`agent-guard report`, `agent-guard render-report`, standalone `agent-guard surface inventory`,
GitHub annotations, SARIF rendered from a report, conformance output, and evidence-pack manifests.
Standalone surface inventory output is recursively sanitized before Action upload so secret-shaped repository-relative metadata is not published raw.

Raw per-scanner JSON, including `api`, `content`, `context`, `mcp`, or `workflow` checks with `--json`, is for
local automation and CI internals; depending on the scanner and policy, it may include scanner metadata, policy details, server metadata, or other diagnostics.
Do not upload raw scanner JSON as a public artifact unless a maintainer has reviewed that exact output.

The current MCP 2026-07-28 protocol/runtime/OAuth changes do not expand this static boundary.
No changelog item directly invalidates the current committed-config labels, so they do not require
runtime execution, live OAuth validation, or taxonomy/code changes.

OWASP Agentic Top 10 labels, MCP risk labels, and other public crosswalks are static
risk-theme metadata attached to deterministic repository findings. They are not vulnerability proofs,
runtime prompt/tool poisoning detection, runtime MCP security validation, live OAuth validation,
generic secret scanning, SLSA/provenance verification, or compliance attestation.

See [`docs/threat-model.md`](threat-model.md) for the static evidence boundary:
what `agent-guard` can catch in repository files and sanitized artifacts, what
it cannot prove about runtime agent behavior, and how downstream evidence
consumers should fail closed without treating the report as a merge decision.

## Adoption Path: Minimal First, Then Recommended

Choose the smallest profile that matches the review decision you need:

| Profile | Use when | Requires |
| --- | --- | --- |
| `minimal` | You are introducing `agent-guard` and want a low-friction inventory gate before committing every starter policy. | Context policy, workflow policy, and surface inventory evidence. |
| `recommended` | You want the reviewed static evidence baseline for CI or release review. | Repo-local `.agent-guard/mcp-policy.yaml`, recommended evidence gates, and conformance. |
| `strict` | You want publication evidence to include repository-specific context-lock, digest, and evidence-pack expectations. | Reviewed recommended evidence plus strict-only digest/context-lock/evidence-pack coverage. |

Minimal first pass:

1. Run `agent-guard init --root . --print` and review the proposed starter
   `.agent-guard` policies and evidence workflow before writing them.
2. Add repo-local policies under `.agent-guard/`, starting with
   `context-policy.yaml`.
3. Run the context and surface inventories locally and review only
   repository-relative paths, agent context kinds, workflow references, policy
   files, counts, and permission-boundary status.
4. Store only sanitized report or rendered report output as a build artifact.

Move to recommended evidence after the starter files are reviewed:

1. Commit a repo-local `.agent-guard/mcp-policy.yaml` with the default static MCP
   risk-label set.
2. Enable `--evidence-preset recommended`, surface inventory v2, recommended
   conformance, and an evidence-pack manifest.
3. Add digest/context-lock evidence only after generating and reviewing a digest
   policy for safety-critical context files. Recommended conformance does not
   require those repository-specific gates unless supplied.
4. Pair the static report with a runtime admission event from `agent-policy`
   when the repository uses an agent hook or wrapper before side effects. Pass
   that event only as an artifact reference; `agent-guard` reads and
   canonicalizes it locally, but does not embed or publish the event body.
5. Review the evidence as a maintainer aid, not as a model-generated verdict.

Example commands for a new repository. Review the `init --print` plan before
writing starter files, and generate the digest policy before checking context
lock coverage:

```bash
agent-guard init --root . --print
agent-guard init --root . --write
agent-guard context inventory --root . --policy .agent-guard/context-policy.yaml --json
agent-guard surface inventory --root . --context-policy .agent-guard/context-policy.yaml --schema-version v2 --json
agent-guard context lock --root . --policy .agent-guard/context-policy.yaml > .agent-guard/context-digest-policy.yaml
agent-guard context lock --root . --policy .agent-guard/context-policy.yaml --check --digest-policy .agent-guard/context-digest-policy.yaml --json
agent-guard mcp check --root . --policy .agent-guard/mcp-policy.yaml --json
agent-guard drift check --root . --profile recommended --schema-version v2 --json
agent-guard report --root . --context-policy .agent-guard/context-policy.yaml --evidence-preset recommended --mcp-policy .agent-guard/mcp-policy.yaml --digest-policy .agent-guard/context-digest-policy.yaml --format json --output .agent-guard/evidence/agent-guard-report.json
agent-guard render-report --root . --input .agent-guard/evidence/agent-guard-report.json --format markdown --output .agent-guard/evidence/agent-guard-report.md
agent-guard render-report --root . --input .agent-guard/evidence/agent-guard-report.json --format sarif --output .agent-guard/evidence/agent-guard-results.sarif
agent-guard conformance check --root . --evidence .agent-guard/evidence/agent-guard-report.json --profile recommended --json
agent-guard evidence-pack manifest --root . --report .agent-guard/evidence/agent-guard-report.json --artifact .agent-guard/evidence/agent-guard-report.json --json
python examples/evidence_consumer.py .agent-guard/evidence/agent-guard-report.json
```

If a reviewed `agent-policy` admission event already exists, optionally attach
its repository-relative path outside `.agent-guard/evidence`:

```bash
agent-guard report --root . \
  --context-policy .agent-guard/context-policy.yaml \
  --evidence-preset recommended \
  --mcp-policy .agent-guard/mcp-policy.yaml \
  --digest-policy .agent-guard/context-digest-policy.yaml \
  --agent-policy-audit-event path/to/reviewed-policy-admission-event.json \
  --agent-policy-audit-event-profile agent-guard.public_agent_policy_audit_event.v1 \
  --format json \
  --output .agent-guard/evidence/agent-guard-report.json
agent-guard evidence-pack manifest --root . \
  --report .agent-guard/evidence/agent-guard-report.json \
  --artifact .agent-guard/evidence/agent-guard-report.json \
  --agent-policy-audit-event path/to/reviewed-policy-admission-event.json \
  --agent-policy-audit-event-profile agent-guard.public_agent_policy_audit_event.v1 \
  --json
python examples/evidence_consumer.py \
  .agent-guard/evidence/agent-guard-report.json \
  --evidence-dir .agent-guard/evidence \
  --repo-root . \
  --agent-policy-audit-event path/to/reviewed-policy-admission-event.json \
  --agent-policy-audit-event-profile agent-guard.public_agent_policy_audit_event.v1
```

The referenced event must already be produced, reviewed, and stored as a
repo-local regular JSON file. Pass the identical path and explicit expected
profile to both producers. Events select v2; event-free reports stay v1. The
manifest records a sanitized repository-relative
path and a profile-bound digest. `agent-guard` reads and canonicalizes the
bounded event JSON locally to compute that binding, but never embeds the event
body. The only recognized profile is
`agent-guard.public_agent_policy_audit_event.v1`. It validates a public-safe
subset of the underlying published
[agent-policy v0.1.11 event shape](https://github.com/yui-stingray/agent-policy/blob/v0.1.11/src/agent_policy/schemas/agent-policy.audit_event.v1.1.schema.json):
required fields, exact top-level and decision fields, decision enums, bounded
optional strings, and a sanitized repository-relative optional path. That
guard-owned path grammar permits non-whitespace printable ASCII only and
rejects absolute paths, colons, backslashes, dot segments, controlled
secret-shaped values, and every embedded raw 64-hex hash. It is a
public-artifact contract, not a generic secret scanner or a claim that the
producer-owned `agent-policy` JSON Schema uses the same narrower grammar.
Canonicalization also rejects strings that cannot be encoded as valid UTF-8,
including escaped lone surrogates, before computing a digest.
The source `0.3.6.dev0` consumer requires the event separately and an explicit
repository root. Each positional event must be a canonical relative path or a
canonical absolute in-root path, and its derived repository-relative path must
exactly equal the same-position manifest artifact path before profile and
digest verification. It fails closed when the root is missing, a path uses dot
or parent aliases, a path escapes through location or symlink, events are
reordered, or an event is malformed, outside that profile schema, supplied
under a different expected profile, changed, or replaced during the bounded
descriptor read. CLI parsing retains the raw path spelling. Programmatic v2
callers must pass the same unmodified spelling as a `str`; `Path` objects are
rejected because dot or parent aliases may already have been normalized away.
Event-free v1 consumption is unchanged. The event itself is not part of the
fixed seven-file public bundle.
The binding does not protect an attacker who can replace both the evidence
manifest and the event; use a signature, attestation, or immutable trusted
storage for that threat model.

When CI uploads evidence, pin third-party actions to versions or commit SHAs
according to the repository's normal supply-chain policy, and keep generated
evidence out of source control unless it is a deliberately sanitized sample.

## How To Read The Report

The JSON report is a compact statement of what `agent-guard` checked:

- `tool`, `scanner`, `command`, and `status` identify the producing tool and
  whether the enabled checks passed.
- `summary`, `finding_count`, and `findings` give stable counts and rule
  anchors for failed checks.
- `inventory` lists discovered agent context files by repository-relative path
  and records whether approval, permission, network, destructive-action,
  local-verification, and sensitive-material handling boundaries are present.
- `surface_inventory` lists agent context files, `.agent-guard` policy files,
  workflow files, agent-guard workflow references, documented guard commands,
  evidence artifact references, agent skills/profiles/commands/hooks, and MCP
  configuration metadata when v2 is requested. MCP entries omit raw args and
  env values; they keep only server names, transports, command basenames,
  package-manager pin status, remote hosts, env var names, filesystem-root
  presence, and deterministic risk labels for static authorization, scope,
  URL-scheme, package, path, and inline-value review.
- Findings and surface risk labels can include `owasp_agentic_risk_themes` to
  show which OWASP Agentic Top 10 risk themes the static evidence is relevant
  to.
- `evidence_coverage` records which gates were enabled, missing, clean, or
  failing without treating every missing optional gate as a failure.
- `report.scope` is a compatibility-preserved, coarse scanner summary. It uses
  the released shorthand names `mcp` and `drift`, always includes `context`,
  and does not enumerate the implicit `surface_inventory` or `context_lock`
  sections. Consumers that need canonical gate names or complete enabled,
  missing, and failing coverage must use `evidence_coverage.gates`, including
  `mcp_config`, `policy_spec_drift`, `surface_inventory`, and `context_lock`.
- `mcp_config` records whether committed MCP configuration metadata had
  parse errors or deterministic risk labels. It omits raw args, env values,
  authorization values, scope strings, URLs, secrets, instruction bodies, and
  local absolute paths. Static authorization, scope, and URL-scheme labels are
  review evidence over committed configuration only; they do not prove that a
  live OAuth flow is correctly implemented or that an MCP server is safe to run.
  Recommended and strict evidence require the reviewed repo-local policy at
  `.agent-guard/mcp-policy.yaml`. External MCP policy files can drive scanner
  experiments, but conformance reports display them as `<external-policy>` and
  do not treat them as reviewed repository evidence.
  `version_pinned` is emitted only for recognized package-execution forms. For
  JavaScript launchers (`npx`, `npm exec`/`npm x`, `pnpm dlx`, `yarn dlx`,
  `bun x`, and direct `bunx`), every eligible package operand or selector must
  use an npm-compatible full SemVer: its total version text is at most 256
  characters and each numeric core identifier is no greater than
  `Number.MAX_SAFE_INTEGER`. Synthetic package-attached `sha256` selectors are
  not supported by these launcher grammars and are not treated as pins.
  `version_pinned` and `latest_package` consume only explicit recognized
  launcher option and alias arities; unsupported or ambiguous layouts do not
  inspect arbitrary arguments as package operands. For `uvx`,
  every selected requirement must use an exact `name[extras]==version` form; a
  positional command must use uv's exact-only `name@version` syntax and is also
  required unless `--from` selects it.
  For `bun x` and direct `bunx`, only the actual package operand is eligible;
  `--bun` may precede it, while Bun global `--cwd` and `--shell` are recognized
  only before `x` on the `bun x` form.
  Version-dependent post-`x` selectors such as `--package` do not supply a pin,
  because static configuration evidence does not establish the Bun version
  that will interpret them.
  Once a package or tool operand is selected, its trailing command arguments
  are excluded from pin inference. Classification recognizes package-manager
  launcher names case-insensitively and removes one known Windows launcher
  suffix (`.cmd`, `.exe`, `.bat`, or `.ps1`) while preserving the original
  public `command_basename`.
  Ranges, tags such as `latest`, npm-style major/minor-only versions, digest
  selectors, editable or requirements-file inputs, and ambiguous or unsupported
  option layouts are conservatively not treated as pinned. This is static command
  metadata classification; it does not resolve registries, lock files, or live
  package identity.
- Optional `conformance` records whether enabled evidence satisfies the chosen
  `minimal`, `recommended`, or `strict` profile. Recommended and strict
  conformance also fail when the reviewed MCP policy omits the default static
  MCP risk-label set; broader semantic policy weakening remains out of scope.
  Recommended is the reviewed static evidence baseline. It does not require
  repository-specific digest or context-lock gates unless those checks are
  supplied; `strict` is the profile that makes digest/context-lock and
  evidence-pack expectations part of conformance.
- Optional `evidence_pack_manifest` records the sanitized artifact manifest for
  reviewer handoff. Artifact roles are limited to `report` and
  `agent-policy-audit-event`. V2 entries include a controlled binding profile
  and public-safe canonical-content digest for the separately supplied event;
  legacy v1 references remain readable but cannot satisfy content verification.
- `context_lock` records whether discovered context files are covered by digest
  policy, without emitting hash values.
- Optional `path`, `content`, `api`, `digest`, and `workflow` sections summarize
  additional static gates when those policies are supplied.
- Optional `policy_spec_drift` summarizes README, workflow-policy, and
  `.agent-guard` policy alignment when `--drift-check` is enabled. When
  `--base-ref` or `--drift-base-ref` is supplied, it can also flag
  baseline-sensitive guard policy, digest policy, workflow, action metadata, or
  hook metadata changes as review-required evidence.
- Optional `surface_delta` is emitted when `--surface-delta-base-ref` is
  supplied. It reports which agent surfaces (context files, skills, MCP
  servers, workflows, policies, hooks) were added, removed, or modified
  relative to `git merge-base <base-ref> HEAD`, computed from the same surface
  inventory v2 used elsewhere in the report. The working tree remains the head
  side, so uncommitted changes are included without misclassifying additions on
  an advanced base branch as PR removals. It is deterministic review evidence,
  not a gate: it never changes the report's exit code and is never emitted to
  SARIF.
  Policy is always read from the current working tree, never from the base
  ref; the base tree is materialized read-only from raw Git tree/blob objects
  and never executed as instructions. This does not apply release-archive
  `export-ignore` / `export-subst` attributes, and configured
  clean/process/smudge filters are not executed. Git tree metadata is filtered
  against the requested repository root and inventory patterns, including
  context `scan.exclude`, before any blob is read, so unrelated tracked blobs
  are not materialized. Selected repository-internal symlink targets and chains
  are added with bounded expansion so target-only changes remain comparable.
  Repository-external symlink targets are not followed; external, `.git`,
  cyclic, and otherwise unsafe targets fail closed. Context `scan.exclude` is
  applied to both repository-relative alias paths and resolved in-repo target
  paths before expansion through context-selected symlinks. Target values are
  never published. Tracked submodules are opaque boundaries in the parent
  repository delta: initialized checkout contents and dirty/untracked
  submodule files are excluded, while a superproject gitlink pin change is
  represented only by the controlled `content` field name. Object ids and
  submodule contents are never published, and opaque paths are pruned before
  collector file reads. A boundary without an existing skill, profile, or
  command surface is represented by the controlled `git_submodule` kind;
  submodule-internal surfaces require a separate scan rooted in that repository.
  Raw blobs are streamed into a temporary synthetic tar rather than buffering
  a repository archive in memory. Base-tree extraction requires the
  security-backported stdlib tar extraction filter available from Python
  3.11.4 and fails closed if that filter is unavailable; there is no
  unfiltered fallback. `changed_fields`
  lists schema-enumerated field *names* only, never before/after values. Repeated same-file
  records retain their multiplicity, while
  line-number and workflow-step-position-only moves remain unchanged. The
  delta marks content-only changes to existing file-backed context, policy,
  workflow, evidence artifact, skill, profile, command, hook, and MCP
  configuration surfaces with the controlled field name `content`; it never
  emits the instruction body or an internal content fingerprint value. The
  section omits base ref names, raw diffs, MCP args/env values, and
  instruction/description text.

For failure reading, a missing implicit MCP policy in recommended evidence is a
sanitized violation report: `mcp_config` records `mcp_policy_missing`, and
conformance can also report missing required policy evidence. A repo-external MCP
policy is displayed as `<external-policy>` and does not satisfy reviewed-policy
conformance. A reviewed policy that omits any default risk label fails as
`mcp_policy_weakened`. These failure surfaces identify controlled rule ids and
reasons; they do not dump raw YAML content, token-shaped filenames, URLs, scope
strings, or absolute local paths.

Report output omits raw context text, snippets, matched text, raw regex
patterns, repository-controlled raw URLs, raw workflow commands, workflow run
bodies, hash values, sensitive material, base ref names, and absolute local
paths. Baseline findings are not approval decisions or tamper-proof
authorization. This guarantee applies to the sanitized
report/render-report/evidence artifact surfaces, not to raw scanner JSON.

For copied metadata, a string containing a recognized HTTP(S)- or file-scheme
value or absolute local path is replaced as a whole rather than preserving an
ambiguous suffix. If two mapping keys become identical after sanitization,
emission fails closed with a generic error instead of silently overwriting
evidence.

## SARIF Thin Adapter

`agent-guard report --format sarif` renders SARIF 2.1.0 from the same sanitized
report evidence used by JSON, Markdown, and GitHub annotations. It is a thin
adapter, not a separate scanner: rule ids, severity, repository-relative
locations, messages, and fingerprints come from the existing deterministic
payload.

SARIF output intentionally omits snippets, raw context text, matched text, raw
regex patterns, repository-controlled raw URLs, raw workflow commands, workflow
run bodies, raw repository/content/digest hash values, sensitive material, and
absolute local paths. The fixed SARIF 2.1.0 `$schema` URI and agent-guard tool
`informationUri` are format/tool metadata, not copied repository evidence. Its
`partialFingerprints` are deterministic hashes of sanitized
rule/location/message fields for code-scanning deduplication. Uploading the
SARIF file to GitHub code scanning is a consumer workflow choice because it
requires additional repository permissions.

## Non-Goals

`agent-guard` should stay narrow. It should not become:

- a general LLM reviewer or issue triage bot;
- a model router, MoA orchestrator, or model-quality scorer;
- a broad replacement for dedicated secret or credential scanners;
- an agent execution log UI;
- a runtime prompt-injection, MCP tool-poisoning, or memory-poisoning detector;
- a live OAuth validator;
- an MCP server security validator or compliance attestation tool;
- a large governance framework or semantic proof system.

Those layers can consume `agent-guard` evidence, but they should not move into
this package.
