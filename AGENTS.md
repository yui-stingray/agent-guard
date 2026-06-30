# AGENTS.md

Where: repository root
What: durable project guidance for coding agents working on agent-guard
Why: keep self-dogfood for deterministic static evidence checks reviewable

## Project Role

`agent-guard` is a deterministic, local, CI-friendly evidence gate for
repositories touched by coding agents. Keep it model-agnostic: the same static
checks should apply to single-model agents, multi-model or MoA agents, and
persistent coding agents.

`agent-policy` is the companion runtime admission layer. Keep this repository
focused on static repository evidence: context files, policy files, pinned
digests, workflow drift, and sanitized review reports.

## Scope Boundaries

- Prefer small, explicit changes that preserve the current CLI contracts.
- Do not add generic LLM review, issue triage, model routing, model benchmark,
  dashboard, broad governance, or general secret-scanner features here.
- Keep scanner output deterministic and suitable for hooks, CI, and release
  checks.
- Keep public documentation focused only on project behavior and
  repository-local usage.

## Permission Boundary

- Approval is required before publishing releases, changing public GitHub state,
  or performing destructive actions.
- Tool permission is task-scoped: shell, file write, network, and GitHub write
  access are allowed only when the current task requires them.
- Network access should be used for current external facts, official docs,
  package metadata, or workflow status that cannot be verified locally.
- Secret handling is strict: never expose secrets, tokens, API keys, passwords,
  or credentials in logs, reports, docs, examples, commits, issues, or PRs.
- Destructive action boundary: keep changes reviewable and reversible, and
  prefer additive edits over history or filesystem destruction.
- Local verification should use the strongest practical checks, usually
  `pytest`, `actionlint`, CLI smoke commands, build checks, and CI status.

## Self-Dogfood Checks

When changing this repository's agent instructions, `.agent-guard` policies, or
CI guard commands, update and run the self-dogfood checks:

```bash
python -m agent_guard.cli path check --root . --policy .agent-guard/path-policy.yaml --json
python -m agent_guard.cli context check --root . --policy .agent-guard/context-policy.yaml --json
python -m agent_guard.cli digest check --root . --policy .agent-guard/context-digest-policy.yaml --json
python -m agent_guard.cli content check --repo-root . --policy .agent-guard/content-policy.yaml --mode registered --scan-dir . --json
python -m agent_guard.cli mcp check --root . --policy .agent-guard/mcp-policy.yaml --json
python -m agent_guard.cli workflow check --root . --policy .agent-guard/workflow-policy.yaml --json
python -m agent_guard.cli report --root . --context-policy .agent-guard/context-policy.yaml --path-policy .agent-guard/path-policy.yaml --content-policy .agent-guard/content-policy.yaml --content-scan-dir . --api-policy examples/architecture_policy.yaml --mcp-policy .agent-guard/mcp-policy.yaml --digest-policy .agent-guard/context-digest-policy.yaml --workflow-policy .agent-guard/workflow-policy.yaml --format markdown
```
