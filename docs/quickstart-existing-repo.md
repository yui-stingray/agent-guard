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

```bash
agent-guard context check --root . --policy .agent-guard/context-policy.yaml --json
agent-guard context inventory --root . --policy .agent-guard/context-policy.yaml --json
agent-guard surface inventory --root . --context-policy .agent-guard/context-policy.yaml --json
```

The inventories are metadata only. Review repository-relative paths, agent
context kinds, policy files, workflow references, line counts, file sizes, and
permission-boundary status. They should not emit raw instructions, raw workflow
commands, snippets, matched text, secrets, or local paths.

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
agent-guard drift check --root . --json
agent-guard report --root . --context-policy .agent-guard/context-policy.yaml --digest-policy .agent-guard/context-digest-policy.yaml --workflow-policy .agent-guard/workflow-policy.yaml --drift-check --format json --output .agent-guard/evidence/agent-guard-report.json
agent-guard report --root . --context-policy .agent-guard/context-policy.yaml --digest-policy .agent-guard/context-digest-policy.yaml --workflow-policy .agent-guard/workflow-policy.yaml --drift-check --format markdown --output .agent-guard/evidence/agent-guard-report.md
```

Keep generated evidence out of source control unless it is a deliberately
sanitized sample. In CI, upload it as a build artifact instead.

## 6. Read Failures

`agent-guard` uses these exit classes:

- `0`: the enabled check completed and found no violations.
- `1`: the enabled check completed and found safety drift or policy violations.
- `2`: configuration or runtime error.

Start with the `scanner`, `status`, `finding_count`, and `findings` fields.
For report output, also check `inventory`, `surface_inventory`,
`evidence_coverage`, `context_lock`, `digest`, `workflow`, and
`policy_spec_drift` sections when those gates are enabled.

Common first fixes:

- Add missing approval, tool permission, network, destructive action, sensitive
  material, or local verification boundaries to the agent context file.
- Regenerate the digest policy after an intentional context-file change.
- Keep raw transcripts, local artifacts, private fixtures, and generated
  evidence out of tracked paths.

## What This Does Not Add

This quickstart does not add an LLM reviewer, issue triage bot, model router,
MoA orchestrator, broad secret scanner, or governance framework. It creates a
deterministic static evidence gate that maintainers can inspect and combine
with higher layers if they choose.
