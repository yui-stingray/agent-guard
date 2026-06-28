# Evidence Contracts

`agent-guard` is a deterministic static evidence gate for repositories touched
by coding agents. It emits small, sanitized evidence payloads that maintainers
can read in pull requests, store as CI artifacts, or validate in downstream
wrappers without sending repository contents to a model.

## Contracts

Installed wheels package these JSON Schema resources under
`agent_guard.schemas`:

- `agent-guard.result.v1.schema.json`: the shared result envelope used by
  scanner JSON output.
- `agent-guard.context_inventory.v1.schema.json`: redacted metadata for
  discovered agent context files.
- `agent-guard.context_lock_coverage.v1.schema.json`: hash-free evidence that
  discovered agent context files are pinned by digest policy.
- `agent-guard.report_evidence.v1.schema.json`: the sanitized report payload
  used by Markdown, JSON, and GitHub annotation output. Successful and
  violation reports include agent surface inventory and evidence coverage.
- `agent-guard.conformance.v1.schema.json`: profile evidence for `minimal`,
  `recommended`, and `strict` adoption levels.
- `agent-guard.evidence_pack_manifest.v1.schema.json`: a sanitized manifest of
  report artifacts and evidence counts for pull request review.

The sample report in
[`docs/evidence-samples/agent-guard-report.json`](evidence-samples/agent-guard-report.json)
is intentionally public-safe and is validated by the test suite against the
packaged schema.
[`examples/evidence_consumer.py`](../examples/evidence_consumer.py) shows a
small downstream wrapper pattern that loads the packaged report schema and
fails closed on incompatible or unsanitized evidence.

## Minimal Adoption Path

1. Run `agent-guard init --root . --json` and review the proposed starter
   `.agent-guard` policies and evidence workflow before writing them.
2. Add repo-local policies under `.agent-guard/`, starting with
   `context-policy.yaml` and a digest policy for safety-critical context files.
3. Run the context and surface inventories locally and review only
   repository-relative paths, agent context kinds, workflow references, policy
   files, counts, and permission-boundary status.
4. Add `agent-guard report` to CI and store the JSON or Markdown output as a
   build artifact.
5. Pair the static report with a runtime admission event from `agent-policy`
   when the repository uses an agent hook or wrapper before side effects.
6. Review the evidence as a maintainer aid, not as a model-generated verdict.

Example commands:

```bash
agent-guard init --root . --json
agent-guard context inventory --root . --policy .agent-guard/context-policy.yaml --json
agent-guard surface inventory --root . --context-policy .agent-guard/context-policy.yaml --schema-version v2 --json
agent-guard context lock --root . --policy .agent-guard/context-policy.yaml --check --digest-policy .agent-guard/context-digest-policy.yaml --json
agent-guard drift check --root . --profile recommended --schema-version v2 --json
agent-guard report --root . --context-policy .agent-guard/context-policy.yaml --digest-policy .agent-guard/context-digest-policy.yaml --workflow-policy .agent-guard/workflow-policy.yaml --drift-check --drift-schema-version v2 --surface-inventory-version v2 --conformance-profile recommended --evidence-pack-manifest --format json --output .agent-guard/evidence/agent-guard-report.json
agent-guard conformance check --root . --evidence .agent-guard/evidence/agent-guard-report.json --profile recommended --json
agent-guard evidence-pack manifest --root . --report .agent-guard/evidence/agent-guard-report.json --artifact .agent-guard/evidence/agent-guard-report.json --json
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
  and evidence artifact references as metadata only when v2 is requested.
- `evidence_coverage` records which gates were enabled, missing, clean, or
  failing without treating every missing optional gate as a failure.
- Optional `conformance` records whether enabled evidence satisfies the chosen
  `minimal`, `recommended`, or `strict` profile.
- Optional `evidence_pack_manifest` records the sanitized artifact manifest for
  reviewer handoff.
- `context_lock` records whether discovered context files are covered by digest
  policy, without emitting hash values.
- Optional `path`, `content`, `api`, `digest`, and `workflow` sections summarize
  additional static gates when those policies are supplied.
- Optional `policy_spec_drift` summarizes README, workflow-policy, and
  `.agent-guard` policy alignment when `--drift-check` is enabled.

Report output omits raw context text, snippets, matched text, raw regex
patterns, raw URLs, raw workflow commands, workflow run bodies, hash values,
sensitive material, and absolute local paths.

## SARIF Status

SARIF is intentionally deferred until the JSON evidence contract has downstream
usage. The current supported report surfaces are JSON, Markdown, and GitHub
annotations. This keeps the primary contract small enough for maintainers to
review and for wrappers to validate directly.

## Non-Goals

`agent-guard` should stay narrow. It should not become:

- a general LLM reviewer or issue triage bot;
- a model router, MoA orchestrator, or model-quality scorer;
- a broad replacement for dedicated credential scanners;
- an agent execution log UI;
- a large governance framework or semantic proof system.

Those layers can consume `agent-guard` evidence, but they should not move into
this package.
