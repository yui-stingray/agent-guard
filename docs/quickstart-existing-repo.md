# Existing Repo Quickstart

This guide adds a small `agent-guard` evidence gate to an existing repository.
It assumes the repository already has at least one agent context file such as
`AGENTS.md`, `CLAUDE.md`, or a tool-specific rule file.

## 1. Install

Use the Python environment that your CI job will use:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install yui-agent-guard
```

## 2. Review Starter Guard Files

Print the planned starter files first:

```bash
agent-guard init --root . --json
```

The default mode writes nothing. Review the proposed `.agent-guard` policies
and `.github/workflows/agent-guard.yml`, then write them only when they fit the
repository:

```bash
agent-guard init --root . --write
```

Existing files are not overwritten unless `--force` is used.

Before treating `agent-guard drift check` as a clean gate, document the chosen
guard commands in the repository README. The drift gate intentionally reports
missing README guard-command guidance so reviewers can compare the documented
CI recipe with the actual workflow and `.agent-guard` policies.

## 3. Run The First Evidence Pass

The shortest CI path is the packaged GitHub Action. It runs the recommended
evidence preset and leaves artifact upload to the caller:

```yaml
permissions:
  contents: read

jobs:
  agent-guard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
      - id: agent-guard
        uses: yui-stingray/agent-guard@v0.2.0
      - uses: actions/upload-artifact@v7
        if: always()
        with:
          name: agent-guard-evidence
          path: ${{ steps.agent-guard.outputs.evidence-dir }}/
          if-no-files-found: error
```

### Monorepos and Subdirectories

If the reviewed agent-maintained project lives below the repository root, set
`root` to that project directory and keep policy and evidence paths relative to
that selected root:

```yaml
      - id: agent-guard
        uses: yui-stingray/agent-guard@v0.2.0
        with:
          root: services/api
          conformance-profile: recommended
```

The action and CLI resolve relative policy paths such as
`.agent-guard/context-policy.yaml` and `.agent-guard/mcp-policy.yaml` under the
selected root. Use absolute paths only for local experiments; repo-external
policy files do not satisfy recommended or strict reviewed-policy conformance.

For a local first pass, run the same evidence surfaces directly:

```bash
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

## 4. Pin Agent Context Files

Generate a digest policy for the discovered context files:

```bash
agent-guard context lock --root . --policy .agent-guard/context-policy.yaml > .agent-guard/context-digest-policy.yaml
agent-guard context lock --root . --policy .agent-guard/context-policy.yaml --check --digest-policy .agent-guard/context-digest-policy.yaml --json
```

Commit the digest policy only after reviewing the context files. Regenerate it
after intentional changes to those files.

## 5. Store Review Evidence

Create an evidence directory and write a sanitized report:

```bash
mkdir -p .agent-guard/evidence
agent-guard workflow check --root . --policy .agent-guard/workflow-policy.yaml --json
agent-guard mcp check --root . --policy .agent-guard/mcp-policy.yaml --json
agent-guard drift check --root . --profile recommended --schema-version v2 --json
agent-guard report --root . --context-policy .agent-guard/context-policy.yaml --evidence-preset recommended --mcp-policy .agent-guard/mcp-policy.yaml --digest-policy .agent-guard/context-digest-policy.yaml --format json --output .agent-guard/evidence/agent-guard-report.json
agent-guard render-report --root . --input .agent-guard/evidence/agent-guard-report.json --format markdown --output .agent-guard/evidence/agent-guard-report.md
agent-guard conformance check --root . --evidence .agent-guard/evidence/agent-guard-report.json --profile recommended --json
agent-guard evidence-pack manifest --root . --report .agent-guard/evidence/agent-guard-report.json --artifact .agent-guard/evidence/agent-guard-report.json --agent-policy-audit-event .agent-guard/evidence/policy-admission-event.json --json
```

Keep generated evidence out of source control unless it is a deliberately
sanitized sample. In CI, upload it as a build artifact instead.
Render Markdown, SARIF, or GitHub annotations from the JSON report when you need
additional surfaces; avoid rerunning `agent-guard report` just to change output
format.

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

## 6. Read Failures

`agent-guard` uses these exit classes:

- `0`: the enabled check completed and found no violations.
- `1`: the enabled check completed and found safety drift or policy violations.
- `2`: configuration or runtime error.

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

## What This Does Not Add

This quickstart does not add an LLM reviewer, issue triage bot, model router,
MoA orchestrator, broad secret scanner, agent execution UI, an MCP runtime
security layer, MCP tool-poisoning detector, or governance framework. It
creates a deterministic static evidence gate that maintainers can inspect and
combine with higher layers if they choose.
