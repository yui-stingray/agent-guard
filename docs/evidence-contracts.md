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
  used by Markdown, JSON, and GitHub annotation output.

The sample report in
[`docs/evidence-samples/agent-guard-report.json`](evidence-samples/agent-guard-report.json)
is intentionally public-safe and is validated by the test suite against the
packaged schema.
[`examples/evidence_consumer.py`](../examples/evidence_consumer.py) shows a
small downstream wrapper pattern that loads the packaged report schema and
fails closed on incompatible or unsanitized evidence.

## Minimal Adoption Path

1. Add repo-local policies under `.agent-guard/`, starting with
   `context-policy.yaml` and a digest policy for safety-critical context files.
2. Run the context inventory locally and review only repository-relative paths,
   agent context kinds, counts, and permission-boundary status.
3. Add `agent-guard report` to CI and store the JSON or Markdown output as a
   build artifact.
4. Pair the static report with a runtime admission event from `agent-policy`
   when the repository uses an agent hook or wrapper before side effects.
5. Review the evidence as a maintainer aid, not as a model-generated verdict.

Example commands:

```bash
agent-guard context inventory --root . --policy .agent-guard/context-policy.yaml --json
agent-guard context lock --root . --policy .agent-guard/context-policy.yaml --check --digest-policy .agent-guard/context-digest-policy.yaml --json
agent-guard report --root . --context-policy .agent-guard/context-policy.yaml --digest-policy .agent-guard/context-digest-policy.yaml --format json --output .agent-guard/evidence/agent-guard-report.json
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
- `context_lock` records whether discovered context files are covered by digest
  policy, without emitting hash values.
- Optional `path`, `content`, `api`, `digest`, and `workflow` sections summarize
  additional static gates when those policies are supplied.

Report output omits raw context text, snippets, matched text, raw regex
patterns, raw URLs, hash values, sensitive material, and absolute local paths.

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
