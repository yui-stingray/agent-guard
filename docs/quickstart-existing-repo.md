# Existing Repo Quickstart

This guide adds a small `agent-guard` evidence gate to an existing repository.
It assumes the repository already has at least one agent context file such as
`AGENTS.md`, `CLAUDE.md`, or a tool-specific rule file.

## 1. Initial Diagnostic Path

If `uv` is available, preview the starter plan without installing a persistent
tool or changing the repository:

```console
uvx --python 3.12 --from yui-agent-guard==0.2.4 agent-guard init --root . --json
```

Run these commands from the repository root on the first pass through an
un-onboarded repository. This four-command golden path creates an isolated
Python environment, previews the starter plan, writes the reviewed guard files,
and produces one recommended sanitized report. The report already embeds
recommended conformance and its evidence-pack manifest:

```bash
python3 -m venv .venv && \
  . .venv/bin/activate && \
  python -m pip install yui-agent-guard==0.2.4
agent-guard init --root . --json
agent-guard init --root . --write
agent-guard report \
  --root . \
  --context-policy .agent-guard/context-policy.yaml \
  --evidence-preset recommended \
  --format json \
  --output .agent-guard/evidence/agent-guard-report.json
```

On this initial diagnostic path, findings and drift are useful output. If
`report` or `conformance` exits `1` on an un-onboarded repository, that is the
expected, correct fail-closed behavior: the command completed, found static
evidence gaps, and refused to report a clean gate. It is not the same as a
usage error.

The diagnostic pass is done when the starter files exist, the sanitized report
was written with embedded conformance and evidence-pack sections, and every
finding has an owner or an explicit onboarding decision.
Do not hide exit `1` in CI; use it locally to decide which policy files, README
guard-command guidance, workflows, digest locks, or MCP policy reviews must be
added before the repository is green.

Existing files are not overwritten unless `--force` is used. The dry-run in the
four-command path is intentional: review its proposed files before running the
following `init --write` command.

Before treating `agent-guard drift check` as a clean gate, document the chosen
guard commands in the repository README. The drift gate intentionally reports
missing README guard-command guidance so reviewers can compare the documented
CI recipe with the actual workflow and `.agent-guard` policies.

## 2. Green CI Path

Use the green CI path after the diagnostic findings have been resolved and the
reviewed `.agent-guard` policies, README guard-command guidance, and workflow
references are committed. In this path, the same report and conformance gates
run under automation and everything exits `0`. Any later exit `1` means the
repository has new findings or drift and CI should fail closed.

The shortest green CI path is the packaged GitHub Action. It runs the
recommended evidence preset and leaves artifact upload to the caller:

```yaml
permissions:
  contents: read

jobs:
  agent-guard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
      - id: agent-guard
        uses: yui-stingray/agent-guard@v0.2.4
      - uses: actions/upload-artifact@v7
        if: always()
        with:
          name: agent-guard-evidence
          path: ${{ steps.agent-guard.outputs.evidence-dir }}/
          if-no-files-found: error
```

## 3. Monorepos and Subdirectories

If the reviewed agent-maintained project lives below the repository root, set
`root` to that project directory and keep policy and evidence paths relative to
that selected root:

```yaml
      - id: agent-guard
        uses: yui-stingray/agent-guard@v0.2.4
        with:
          root: services/api
          conformance-profile: recommended
```

The action and CLI resolve relative policy paths such as
`.agent-guard/context-policy.yaml` and `.agent-guard/mcp-policy.yaml` under the
selected root. Use absolute paths only for local experiments; repo-external
policy files do not satisfy recommended or strict reviewed-policy conformance.

Treat each reviewed project root as its own evidence boundary. Do not aggregate
raw scanner JSON across services, and do not use one service's
`.agent-guard/mcp-policy.yaml` as reviewed evidence for another service. If a
monorepo wants a top-level status check, run `agent-guard` once per selected
root and let the wrapper summarize the per-root sanitized reports.

The equivalent local command keeps `--root` on the reviewed project, keeps
policy paths relative to that root, and writes evidence under the selected
project directory:

```text
agent-guard report \
  --root services/api \
  --context-policy .agent-guard/context-policy.yaml \
  --evidence-preset recommended \
  --mcp-policy .agent-guard/mcp-policy.yaml \
  --format json \
  --output services/api/.agent-guard/evidence/agent-guard-report.json
agent-guard conformance check \
  --root services/api \
  --evidence services/api/.agent-guard/evidence/agent-guard-report.json \
  --profile recommended \
  --json
```

The evidence consumer example uses the same root discipline:

```text
AGENT_GUARD_ROOT=services/api \
AGENT_GUARD_EVIDENCE_DIR=services/api/.agent-guard/evidence \
AGENT_GUARD_REPORT_JSON=services/api/.agent-guard/evidence/agent-guard-report.json \
sh examples/evidence_contracts_ci.sh consume
```

## 4. Optional Review Commands

For a local guard-by-guard pass, run the same evidence surfaces directly:

```text
agent-guard context check --root . --policy .agent-guard/context-policy.yaml --json
agent-guard context inventory --root . --policy .agent-guard/context-policy.yaml --json
agent-guard mcp check --root . --policy .agent-guard/mcp-policy.yaml --json
agent-guard surface inventory --root . --context-policy .agent-guard/context-policy.yaml --schema-version v2 --json
```

The inventories are metadata only. Review repository-relative paths, agent
context kinds, policy files, workflow references, documented guard-command
metadata, evidence artifact references, agent skills/profiles/commands/hooks,
MCP server names, MCP transports, command basenames, package-manager pin
status, remote hosts, env var names, filesystem-root presence, line counts,
file sizes, and permission-boundary status. They should not emit raw
instructions, raw workflow commands, MCP args, env values, snippets, matched
text, secrets, hook bodies, or local paths.

Generate a digest policy for the discovered context files:

```text
agent-guard context lock --root . --policy .agent-guard/context-policy.yaml > .agent-guard/context-digest-policy.yaml
agent-guard context lock --root . --policy .agent-guard/context-policy.yaml --check --digest-policy .agent-guard/context-digest-policy.yaml --json
```

Commit the digest policy only after reviewing the context files. Regenerate it
after intentional changes to those files.

Render Markdown, SARIF, or GitHub annotations from the JSON report when you need
additional surfaces; avoid rerunning `agent-guard report` just to change output
format:

```text
agent-guard workflow check --root . --policy .agent-guard/workflow-policy.yaml --json
agent-guard mcp check --root . --policy .agent-guard/mcp-policy.yaml --json
agent-guard drift check --root . --profile recommended --schema-version v2 --json
agent-guard report --root . --context-policy .agent-guard/context-policy.yaml --evidence-preset recommended --mcp-policy .agent-guard/mcp-policy.yaml --digest-policy .agent-guard/context-digest-policy.yaml --format json --output .agent-guard/evidence/agent-guard-report.json
agent-guard render-report --root . --input .agent-guard/evidence/agent-guard-report.json --format markdown --output .agent-guard/evidence/agent-guard-report.md
```

Keep generated evidence out of source control unless it is a deliberately
sanitized sample. In CI, upload it as a build artifact instead.

Do not treat every `--json` command as a public artifact. The report,
render-report, conformance, and evidence-pack outputs are the sanitized review
surfaces. Raw scanner JSON from commands such as `api check --json`, `content
check --json`, `mcp check --json`, or `workflow check --json` may include
scanner-specific metadata or policy diagnostics depending on the scanner and
should stay in local automation or temporary CI storage unless reviewed.

`--evidence-preset recommended` expands unset report options to the current
recommended static gate bundle: path, content, MCP config, workflow,
policy/spec drift v2, surface inventory v2, recommended conformance, and an
embedded evidence-pack manifest. It does not enable API or digest policies
automatically; add those options only when the repository has reviewed policy
files for them.

Run the embedded handoff checks as standalone commands only when a downstream
consumer needs separate payloads or an `agent-policy` admission event must be
attached to the evidence-pack manifest:

```text
agent-guard conformance check --root . \
  --evidence .agent-guard/evidence/agent-guard-report.json \
  --profile recommended \
  --json
agent-guard evidence-pack manifest --root . \
  --report .agent-guard/evidence/agent-guard-report.json \
  --artifact .agent-guard/evidence/agent-guard-report.json \
  --agent-policy-audit-event .agent-guard/evidence/policy-admission-event.json \
  --json
```

These commands are not required for the four-command first pass because the
recommended report already contains the same conformance and manifest
sections.

### Consume Evidence Safely

Downstream wrappers should read the sanitized report JSON and validate it
against the packaged `agent-guard.report_evidence.v1` schema before making
decisions. Fail closed on schema drift, inconsistent counts, missing
`surface_inventory`, missing `evidence_coverage`, unexplained top-level
`status` values, non-sanitized reports, unexpected conformance profiles, or
forbidden public-evidence fragments such as raw snippets, hash values,
token-shaped strings, and absolute local paths.

The copyable `examples/evidence_consumer.py` script demonstrates that consumer
shape. It is still a review wrapper: it does not execute MCP servers, validate
live OAuth flows, detect prompt/tool poisoning, or approve a pull request.
For CI jobs that consume an existing report, lint public evidence artifacts, or
gate releases with the strict profile, use
[`docs/evidence-consumer-contracts.md`](evidence-consumer-contracts.md).
See [`docs/threat-model.md`](threat-model.md) for the full static evidence
boundary.

The recommended report preset already fails on malformed committed MCP config
files and deterministic risky MCP configuration metadata. Pass
`--policy .agent-guard/mcp-policy.yaml` to `mcp check`, or
`--mcp-policy .agent-guard/mcp-policy.yaml` to `report`; recommended and strict
evidence require that reviewed repo-local policy. External policy files can be
used for scanner experiments, but they are reported as `<external-policy>` and
do not satisfy conformance. Use
`--conformance-profile strict` only after reviewing v2 surface inventory output
and deciding that the same labels should also appear as conformance findings.
Both modes are static evidence over repository configuration; they do not
execute MCP servers, inspect MCP tool results, validate live OAuth flows, detect
MCP tool-poisoning behavior, or act as an MCP runtime security validator.

For pull requests that can change guard policy or workflow files, fetch the
base branch in CI and add `--base-ref <ref>` to `drift check` or
`--drift-base-ref <ref>` to `report`. This only records review-required
baseline-sensitive changes in sanitized evidence. It is not an approval system
and does not replace digest or context-lock checks.

## 6. Reading Exit Codes

`agent-guard` uses these exit classes:

| Exit code | Meaning | What to do |
| --- | --- | --- |
| `0` | The enabled check completed and found no violations. | This is the expected green CI result after onboarding. |
| `1` | The enabled check completed and found safety drift or policy violations. | Expected during initial diagnostics on an un-onboarded repo; fail closed in CI and fix or explicitly review the finding. |
| `>=2` | Usage, configuration, or runtime error. | Fix the command, policy path, environment, or invocation before interpreting findings. |

Start with the `scanner`, `status`, `finding_count`, and `findings` fields.
For report output, also check `inventory`, `surface_inventory`,
`evidence_coverage`, `context_lock`, `digest`, `workflow`, and
`policy_spec_drift` sections when those gates are enabled. If conformance and
evidence-pack output are enabled, review the `conformance` and
`evidence_pack_manifest` sections as the short handoff summary.

Common first fixes:

- Add missing approval, tool permission, network, destructive action, sensitive
  material, or local verification boundaries to the agent context file.
- Regenerate the digest policy after an intentional context-file change.
- Keep raw transcripts, local artifacts, private fixtures, and generated
  evidence out of tracked paths.

Common rule ids map to these first checks:

| Rule or section | First thing to inspect | Usual fix |
| --- | --- | --- |
| `mcp_policy_missing` | `mcp_config.policy.path` and `.agent-guard/mcp-policy.yaml` | Commit a reviewed repo-local MCP policy, then rerun `report --evidence-preset recommended`. |
| `required_mcp_policy_not_reviewed` | `conformance.findings` and MCP policy path | Move the reviewed policy under the selected `--root`; do not satisfy recommended or strict evidence with an external policy. |
| `mcp_policy_weakened` | `mcp_config.policy.forbidden_risky_patterns` | Restore the default MCP risk-label set unless you intentionally stay on `minimal`. |
| `required_gate_missing` | `evidence_coverage.gates` | Enable the missing gate in CI or use the adoption profile that matches the repository's current readiness. |
| `required_gate_not_ok` | the named gate section and its findings | Fix the underlying scanner finding before treating conformance as clean. |
| `required_policy_file_missing` | `surface_inventory.surfaces` entries with `surface: policy_file` | Commit the reviewed policy file under the selected `--root` and rerun surface inventory/report. |
| `context_lock` or `digest` findings | `context_lock` and `digest` sections | Regenerate reviewed digest policy only after intentional context or pinned-file changes. |
| `workflow` findings | `workflow.findings` and `.agent-guard/workflow-policy.yaml` | Update the workflow command or the reviewed workflow policy so they agree. |
| `policy_spec_drift` findings | `policy_spec_drift.findings` | Review README, workflow-policy, and guard-policy drift together; it is review evidence, not automatic approval. |

## What This Does Not Add

This quickstart does not add an LLM reviewer, issue triage bot, model router,
MoA orchestrator, broad secret scanner, agent execution UI, an MCP runtime
security layer, MCP tool-poisoning detector, or governance framework. It
creates a deterministic static evidence gate that maintainers can inspect and
combine with higher layers if they choose.
