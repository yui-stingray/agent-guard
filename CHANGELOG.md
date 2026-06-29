# Changelog

Where: `CHANGELOG.md`  
What: release notes for published `yui-agent-guard` versions.  
Why: keep static guard releases auditable while the package is still alpha.

## 0.1.10 - 2026-06-29

- Added `agent-guard render-report` to render an existing sanitized JSON report
  into Markdown, SARIF, GitHub annotations, or canonical JSON without rerunning
  scanner and policy checks.
- Moved report rendering helpers into a small dedicated module so CI delivery
  code no longer imports private CLI helpers.
- Updated the composite GitHub Action and `agent-guard init` starter workflow
  to render Markdown, SARIF, and annotations through the public CLI.
- Expanded default agent-context rules for delegation-based policy bypasses,
  broad tool auto-allow instructions, unreviewed agent output, unreviewed
  background agents, and unreviewed guard suppressions.
- Added public-safe rendering examples and updated adoption docs to keep the
  sanitized JSON report as the single source for review surfaces.

## 0.1.9 - 2026-06-28

- Added a root composite GitHub Action that generates recommended
  `agent-guard` evidence reports and exposes artifact paths for upload.
- Added packaged `pre-commit` hooks with an evidence-first hook before the
  individual context, path, and content scanners.
- Expanded default agent-context rules for approval bypasses, verification
  skips, audit-trail removal, unsafe publication, sandbox and permission
  boundary weakening, and private-data exfiltration instructions.
- Added deterministic context drift classifications for unsafe context
  instructions and context-lock digest drift.
- Added `agent-guard report --format sarif` as a snippet-free SARIF 2.1.0
  adapter over sanitized report evidence.
- Strengthened strict conformance to require a sanitized evidence-pack manifest
  with a report artifact reference.
- Updated README and quickstart docs with badges, an evidence-first adoption
  path, and a narrow public positioning note.

## 0.1.8 - 2026-06-28

- Added `agent-guard report --evidence-preset recommended` as a shorter
  adoption path for the recommended static evidence bundle.
- Added optional `--agent-policy-audit-event` artifact references for
  evidence-pack manifests without reading or embedding runtime event bodies.
- Tightened packaged evidence schemas around conformance profiles and evidence
  artifact roles.
- Updated workflow parsing to recognize GitHub Actions `parallel` step groups
  while keeping repository CI serial until the lint toolchain accepts the new
  syntax.

## 0.1.7 - 2026-06-28

- Added profile-based conformance evidence for `minimal`, `recommended`, and
  `strict` adoption levels.
- Added sanitized evidence pack manifests for pull request review artifacts.
- Added surface inventory v2 metadata for documented guard commands and
  evidence artifact references without emitting raw workflow commands.
- Added profile-aware policy/spec drift v2 checks for README, workflow policy,
  guard policy files, and required agent-context safety boundary categories.
- Updated the downstream evidence consumer and packaged schemas for the new
  conformance and evidence-pack contracts.

## 0.1.6 - 2026-06-28

- Added review-first `agent-guard init` for printing or writing starter
  `.agent-guard` policies and a CI evidence workflow without overwriting
  existing files by default.
- Added `agent-guard surface inventory` to enumerate agent context files,
  `.agent-guard` policy files, workflow files, and agent-guard workflow
  references as sanitized repository-relative metadata.
- Added `agent-guard drift check` plus optional `agent-guard report
  --drift-check` evidence for README recommended guard commands,
  workflow-policy declarations, and required guard policy files.
- Added report `surface_inventory` and `evidence_coverage` payloads so
  downstream consumers can see enabled, missing, clean, and failing gates.
- Updated CI self-dogfood, public evidence docs, and the downstream evidence
  consumer to validate the expanded deterministic evidence contract.

## 0.1.5 - 2026-06-27

- Added packaged JSON Schema resources for the shared result envelope, context
  inventory, context lock coverage, and sanitized report evidence contracts.
- Added `agent-guard report --output <path>` so CI can write deterministic
  Markdown or JSON evidence artifacts without stdout redirection.
- Added hash-free covered context file evidence to context lock coverage and
  report JSON/Markdown output.
- Updated self-dogfood CI to upload sanitized evidence report artifacts.
- Kept SARIF intentionally deferred until the JSON evidence contract has more
  downstream usage.

## 0.1.4 - 2026-06-27

- Added `agent-guard report --format json` for sanitized machine-readable
  evidence reports backed by the shared `agent-guard.result.v1` envelope.
- Added golden fixture coverage for Markdown, JSON, and GitHub annotation
  report evidence outputs.
- Added `agent-guard context lock --check --digest-policy <yaml>` to fail when
  discovered agent context files are missing from, partially pinned by, or
  mismatched against a committed digest policy.
- Added context lock coverage evidence and an `agent-guard.report_evidence.v1`
  contract marker to sanitized reports.
- Documented SARIF as intentionally deferred while JSON and GitHub annotations
  remain the supported CI-friendly report formats.

## 0.1.3 - 2026-06-26

- Added `agent-guard context inventory --json` for redacted agent context
  metadata, permission-boundary evidence, and CI-friendly audit records.
- Kept `context check --json` unchanged while adding the opt-in inventory
  command to the shared scanner result envelope.
- Added `agent-guard workflow check` for deterministic CI guard-command and
  required-policy-file drift checks.
- Added optional workflow drift evidence to `agent-guard report`.
- Added optional path, content, and API evidence sections to
  `agent-guard report` without emitting snippets, URLs, raw regex patterns, or
  absolute local paths.
- Added `agent-guard report --format github-annotations` for sanitized
  GitHub Actions annotations backed by the same report evidence payload.
- Added `agent-guard context lock` to generate digest policy checks for
  discovered agent context files without emitting raw context content.

## 0.1.2 - 2026-06-26

- Added the `context` scanner for agent instruction files such as `AGENTS.md`,
  `CLAUDE.md`, `.github/copilot-instructions.md`, Cursor, Windsurf, and
  Continue rule files.

## 0.1.1 - 2026-04-30

- Added path, digest, and content scanner guidance for `ai-resilience-system` CI gates.
- Added README coverage for the static gate recipe.
- Published the first PyPI release consumed by `ai-resilience-system` final gates.
