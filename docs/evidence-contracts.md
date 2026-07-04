# Evidence Contracts

`agent-guard` is a deterministic static evidence gate for repositories touched
by coding agents. Its report, render-report, conformance, and evidence-pack
commands emit small, sanitized evidence payloads that maintainers can read in
pull requests, store as CI artifacts, or validate in downstream wrappers
without sending repository contents to a model.

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
- `agent-guard.report_evidence.v1.schema.json`: the sanitized report payload
  used by Markdown, JSON, and GitHub annotation output. Successful and
  violation reports include agent surface inventory and evidence coverage.
- `agent-guard.conformance.v1.schema.json`: profile evidence for `minimal`,
  `recommended`, and `strict` adoption levels. The `recommended` profile
  requires the first-class `mcp_config` gate; the `strict` profile can also fail
  on deterministic malformed MCP config or risk metadata emitted by the v2
  surface inventory.
- `agent-guard.evidence_pack_manifest.v1.schema.json`: a sanitized manifest of
  report artifacts and evidence counts for pull request review.

The `v1` schemas are intended to remain stable for downstream consumers.
Compatible tightening may add enum constraints for values already emitted by
`agent-guard`, but raw repository content, hash values, local paths, secrets,
and workflow bodies remain outside the contract.

The sample report in
[`docs/evidence-samples/agent-guard-report.json`](evidence-samples/agent-guard-report.json)
is intentionally public-safe, generated from the current package version, and
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

Public-safe claims apply to `agent-guard report`, `agent-guard render-report`,
GitHub annotations, SARIF rendered from a report, conformance output, and
evidence-pack manifests. Raw per-scanner JSON from commands such as
`agent-guard api check --json`, `content check --json`, `context check --json`,
`mcp check --json`, or `workflow check --json` is intended for local automation
and CI internals. Depending on the scanner and policy, raw JSON may include
scanner-specific metadata, policy details, server metadata, or other
diagnostics. Do not upload raw scanner JSON as a public artifact unless a
maintainer has reviewed that exact output.

OWASP Agentic Top 10 labels, MCP risk labels, and other public crosswalks are
static risk-theme metadata attached to deterministic repository findings. They
are not vulnerability proofs, runtime prompt/tool poisoning detection, runtime
MCP security validation, live OAuth validation, generic secret scanning,
SLSA/provenance verification, or compliance attestation.

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

1. Run `agent-guard init --root . --json` and review the proposed starter
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
   that event only as an artifact reference; `agent-guard` does not read or
   embed the event body.
5. Review the evidence as a maintainer aid, not as a model-generated verdict.

Example commands for a new repository. Review the `init --json` plan before
writing starter files, and generate the digest policy before checking context
lock coverage:

```bash
agent-guard init --root . --json
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
agent-guard evidence-pack manifest --root . --report .agent-guard/evidence/agent-guard-report.json --artifact .agent-guard/evidence/agent-guard-report.json --agent-policy-audit-event .agent-guard/evidence/policy-admission-event.json --json
python examples/evidence_consumer.py .agent-guard/evidence/agent-guard-report.json
```

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
  `agent-policy-audit-event`.
- `context_lock` records whether discovered context files are covered by digest
  policy, without emitting hash values.
- Optional `path`, `content`, `api`, `digest`, and `workflow` sections summarize
  additional static gates when those policies are supplied.
- Optional `policy_spec_drift` summarizes README, workflow-policy, and
  `.agent-guard` policy alignment when `--drift-check` is enabled. When
  `--base-ref` or `--drift-base-ref` is supplied, it can also flag
  baseline-sensitive guard policy, digest policy, workflow, action metadata, or
  hook metadata changes as review-required evidence.

For failure reading, a missing implicit MCP policy in recommended evidence is a
sanitized violation report: `mcp_config` records `mcp_policy_missing`, and
conformance can also report missing required policy evidence. A repo-external MCP
policy is displayed as `<external-policy>` and does not satisfy reviewed-policy
conformance. A reviewed policy that omits any default risk label fails as
`mcp_policy_weakened`. These failure surfaces identify controlled rule ids and
reasons; they do not dump raw YAML content, token-shaped filenames, URLs, scope
strings, or absolute local paths.

Report output omits raw context text, snippets, matched text, raw regex
patterns, raw URLs, raw workflow commands, workflow run bodies, hash values,
sensitive material, base ref names, and absolute local paths. Baseline findings
are not approval decisions or tamper-proof authorization. This guarantee
applies to the sanitized report/render-report/evidence artifact surfaces, not
to raw scanner JSON.

## SARIF Thin Adapter

`agent-guard report --format sarif` renders SARIF 2.1.0 from the same sanitized
report evidence used by JSON, Markdown, and GitHub annotations. It is a thin
adapter, not a separate scanner: rule ids, severity, repository-relative
locations, messages, and fingerprints come from the existing deterministic
payload.

SARIF output intentionally omits snippets, raw context text, matched text, raw
regex patterns, raw URLs, raw workflow commands, workflow run bodies, raw
repository/content/digest hash values, sensitive material, and absolute local
paths. Its `partialFingerprints` are deterministic hashes of sanitized
rule/location/message fields for code-scanning deduplication. Uploading the
SARIF file to GitHub code scanning is a consumer workflow choice because it
requires additional repository permissions.

## Non-Goals

`agent-guard` should stay narrow. It should not become:

- a general LLM reviewer or issue triage bot;
- a model router, MoA orchestrator, or model-quality scorer;
- a broad replacement for dedicated credential scanners;
- an agent execution log UI;
- a runtime prompt-injection, MCP tool-poisoning, or memory-poisoning detector;
- a live OAuth validator;
- an MCP server security validator or compliance attestation tool;
- a large governance framework or semantic proof system.

Those layers can consume `agent-guard` evidence, but they should not move into
this package.
