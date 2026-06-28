# Positioning

`agent-guard` is a repo-scoped deterministic evidence gate for repositories
touched by coding agents. It focuses on agent context files, repository policy
files, pinned digests, workflow drift, and sanitized review reports.

The short description is:

> Static evidence contracts for AI-agent-maintained repositories.

The project deliberately stays below runtime agent platforms. It does not route
models, run LLM review, triage issues, manage approvals, provide an execution
UI, or replace dedicated secret scanners. Those systems can consume
`agent-guard` JSON evidence, but they should not move into this package.

## Why This Layer

Coding agents increasingly read durable repository instructions such as
`AGENTS.md`, `CLAUDE.md`, Copilot instructions, Cursor rules, Windsurf rules,
and similar context files. Maintainers need a local and CI-friendly way to see
whether those instructions still preserve review boundaries, tool permissions,
network boundaries, secret handling, destructive-action limits, and local
verification requirements.

`agent-guard` provides that static layer:

- scan agent context files for unsafe instruction drift;
- inventory agent-facing repository surfaces without emitting raw content;
- pin reviewed context and policy files by digest;
- check that CI still runs the declared guard commands;
- emit a sanitized report and evidence-pack manifest that reviewers can inspect.

## Related Work

The direction is consistent with related independent work on deterministic
control planes for coding agents and with ecosystem movement toward durable
agent instructions such as AGENTS.md. These are alignment signals, not claims
that `agent-guard` implements a full control plane or a comprehensive agent
security framework.

## Adoption Path

For a new adopter, the intended first experience is the evidence report:

1. run `agent-guard init --root . --json` and review the proposed policies;
2. write the starter files only after review;
3. run the GitHub Action or `agent-guard report --evidence-preset recommended`;
4. upload the JSON and Markdown evidence as CI artifacts;
5. treat findings as maintainer evidence, not as an automated merge verdict.
