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

## 2. Add A Minimal Context Policy

Create `.agent-guard/context-policy.yaml`:

```yaml
scan:
  include:
    - AGENTS.md
    - CLAUDE.md
    - .github/copilot-instructions.md
    - .cursor/rules/**
    - .windsurf/rules/**
  exclude:
    - .git/**
    - .venv/**
    - node_modules/**
```

Run the first check:

```bash
agent-guard context check --root . --policy .agent-guard/context-policy.yaml --json
agent-guard context inventory --root . --policy .agent-guard/context-policy.yaml --json
```

The inventory is metadata only. Review repository-relative paths, agent context
kinds, line counts, file sizes, and permission-boundary status. It should not
emit raw instructions, snippets, matched text, secrets, or local paths.

## 3. Pin Agent Context Files

Generate a digest policy for the discovered context files:

```bash
agent-guard context lock --root . --policy .agent-guard/context-policy.yaml > .agent-guard/context-digest-policy.yaml
agent-guard context lock --root . --policy .agent-guard/context-policy.yaml --check --digest-policy .agent-guard/context-digest-policy.yaml --json
```

Commit the digest policy only after reviewing the context files. Regenerate it
after intentional changes to those files.

## 4. Store Review Evidence

Create an evidence directory and write a sanitized report:

```bash
mkdir -p .agent-guard/evidence
agent-guard report --root . --context-policy .agent-guard/context-policy.yaml --digest-policy .agent-guard/context-digest-policy.yaml --format json --output .agent-guard/evidence/agent-guard-report.json
agent-guard report --root . --context-policy .agent-guard/context-policy.yaml --digest-policy .agent-guard/context-digest-policy.yaml --format markdown --output .agent-guard/evidence/agent-guard-report.md
```

Keep generated evidence out of source control unless it is a deliberately
sanitized sample. In CI, upload it as a build artifact instead.

## 5. Read Failures

`agent-guard` uses these exit classes:

- `0`: the enabled check completed and found no violations.
- `1`: the enabled check completed and found safety drift or policy violations.
- `2`: configuration or runtime error.

Start with the `scanner`, `status`, `finding_count`, and `findings` fields.
For report output, also check `inventory`, `context_lock`, `digest`, and
`workflow` sections when those policies are enabled.

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
