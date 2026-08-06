# Positioning

`agent-guard` is a repo-scoped deterministic evidence gate for repositories
touched by coding agents. It focuses on agent context files, repository policy
files, URL/API endpoint references, pinned digests, workflow drift, and
sanitized review reports.

The short description is:

> Static evidence contracts for AI-agent-maintained repositories.

The project deliberately stays below runtime agent platforms. It does not route
models, run LLM review, triage issues, manage approvals, provide an execution
UI, perform runtime MCP execution, execute MCP servers or skill code, validate
live OAuth flows, or detect MCP tool poisoning. It does not provide a generic
secret scanner, replace dedicated secret scanners, or automate GitHub
Marketplace publication. Manual and automated Marketplace publication are both
out of scope until a new explicit maintainer instruction authorizes that
separate action.
Its labels and crosswalks are review metadata, not runtime validation,
vulnerability proof, SLSA/provenance verification, or compliance attestation.
Those systems can consume `agent-guard` JSON evidence, but they should not move
into this package.

## Current Strategy

The current strategy is **VALIDATE-NARROW**: keep `agent-guard` as a Python/PyPI
static evidence package and GitHub Action for repository-local review evidence,
not as a broader agent security platform. From 2026-08-10 through 2026-09-20,
public feature expansion is frozen; work is limited to maintenance and
self-infrastructure while a six-week demand validation runs. The default
adoption path remains the documented `init -> report -> upload evidence` golden
path. Runtime admission stays with `agent-policy` and host wrappers.

Demand signals count only under the predeclared protocol. An activation
requires an external maintainer to adopt `agent-guard` on an owner-external
repository's default branch and obtain a qualifying successful run from that
branch. Retention requires the setup to remain on that branch and another
qualifying run to succeed at least 14 days after activation. On 2026-09-21,
continue only if there are at least three qualifying activations, counting at
most one per organization; at least two retained activations; and at least
three deduplicated specific feedback items from at least two external people.
These are minimum evidence thresholds, not a product-market-fit claim.
Validation work is capped at four hours per week. The
full protocol, including exclusions, qualified-exposure tracking, contact
limits, and public-artifact hygiene, is in
[Demand Validation](demand-validation.md).

Broad external benchmarks, public case studies, rename work, and marketing
claims remain out of scope during validation. If public distribution becomes the
main goal after the gate is met, use the short description above alongside the
project name so readers do not confuse this package with runtime security
products that use similar naming.

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
- collect URL/API endpoint pattern evidence without acting as a live API
  client, OAuth validator, or API catalog;
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

1. run `agent-guard init --root . --print` and review the proposed policies;
2. write the starter files only after review;
3. run the GitHub Action or `agent-guard report --evidence-preset recommended`;
4. upload the JSON and Markdown evidence as CI artifacts;
5. treat findings as maintainer evidence, not as an automated merge verdict.
