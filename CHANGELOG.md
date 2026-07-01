# Changelog

Where: `CHANGELOG.md`  
What: release notes for published `yui-agent-guard` versions.  
Why: keep static guard releases auditable while the package is still alpha.

## Unreleased

- Added a dedicated threat model and evidence-consumer guidance that clarifies
  the static evidence boundary without adding runtime MCP execution, live OAuth
  validation, generic secret scanning, or LLM review behavior.
- Hardened the copyable downstream evidence consumer so it checks conformance
  and evidence-pack consistency, recognizes reviewed MCP policy conformance
  rule ids, rejects unexplained top-level report status values, and uses
  shape-aware public-evidence hygiene checks instead of broad token/hash
  substrings.
- Resolved non-MCP policy path arguments relative to the relevant repository
  root for direct scanner checks and `report`, while keeping public policy path
  display sanitized and repo-relative.
- Trimmed direct `api check` and `content check` finding output to public-safe
  metadata and made direct-check text errors print scrubbed paths.

## 0.1.21 - 2026-07-01

- Clarified the recommended/strict adoption boundary and MCP policy
  failure-reading guidance without changing runtime behavior or expanding beyond
  deterministic static evidence.

## 0.1.20 - 2026-07-01

- Clarified README and GitHub Actions evidence guidance so recommended evidence
  examples pass the reviewed repo-local MCP policy explicitly and avoid implying
  that MCP policy is optional for recommended or strict conformance.
- Documented the existing packaged action `root` input for monorepo or
  subdirectory adoption while keeping policy and evidence paths root-relative.
- Corrected release wording to describe `vX.Y.Z` version tags and added
  regression coverage for explicitly empty MCP `forbidden_risky_patterns`
  weakening.

## 0.1.19 - 2026-06-30

- Tightened `0.1.x` alpha recommended evidence so `report --evidence-preset
  recommended` expects the reviewed repo-local `.agent-guard/mcp-policy.yaml`
  by default and reports a sanitized violation when it is missing.
- Resolved MCP policy paths for `mcp check --policy` and `report --mcp-policy`
  relative to `--root`, while displaying repo-external policy files as
  `<external-policy>` in public payloads.
- Made recommended and strict conformance require the repo-local MCP policy and
  fail when its `forbidden_risky_patterns` omits any default deterministic MCP
  risk labels, while leaving direct `mcp check --policy` subset experiments
  supported.
- Preserved the static evidence boundary: no runtime MCP execution, live OAuth
  validation, generic secret scanning, LLM review, or autonomous policy
  execution was added.

## 0.1.18 - 2026-06-30

- Kept raw per-scanner JSON out of generated CI artifacts by writing scanner
  diagnostics to temporary runner storage while publishing only sanitized
  report, conformance, SARIF, and evidence-pack outputs.
- Made profile conformance fail closed on malformed surface inventory counts
  without exposing local report paths in the CLI error envelope.
- Updated starter, documentation, and repository workflows to the current
  `actions/checkout@v7` major while keeping uploadable evidence read-only and
  review-first.
- Clarified that static MCP labels and risk-theme crosswalks are repository
  review evidence, not runtime MCP execution, live OAuth validation, MCP
  tool-poisoning detection, generic secret scanning, SLSA/provenance
  verification, or compliance attestation.

## 0.1.17 - 2026-06-30

- Extended the deterministic MCP config gate with sanitized static labels for
  unsafe URL schemes, inline authorization values, and broad authorization
  scopes.
- Mapped the new MCP labels to OWASP Agentic risk-theme metadata while keeping
  them as review context, not runtime vulnerability detection or compliance
  proof.
- Added regression coverage that verifies MCP auth/scope/URL findings do not
  emit raw URLs, authorization values, scope strings, host fragments, or local
  paths in public JSON evidence.
- Updated docs and release examples for `0.1.17` while keeping MCP server
  execution, live OAuth validation, tool-poisoning detection, and generic secret
  scanning out of scope.

## 0.1.16 - 2026-06-29

- Promoted committed MCP configuration metadata into a first-class deterministic
  static evidence gate via `agent-guard mcp check` and report
  `--mcp-config-check`.
- Included the `mcp_config` gate in the recommended evidence preset and
  recommended conformance profile, while keeping repository-specific API and
  digest evidence opt-in.
- Added sanitized MCP findings to JSON reports, Markdown, GitHub annotations,
  and SARIF without emitting raw MCP args, env values, secret-shaped server
  names, or local absolute paths.
- Updated the composite Action, starter workflow, self-dogfood workflow, schemas,
  docs, and public sample around the static MCP gate while keeping MCP server
  execution, runtime tool-poisoning detection, and MCP security validation out
  of scope.

## 0.1.15 - 2026-06-29

- Hardened the public composite Action by moving user-supplied inputs out of
  generated shell scripts and into quoted environment variables, with
  allowlist validation for conformance profile and annotation options,
  control-character rejection for shell/path inputs, and safe multiline output
  records.
- Made strict conformance fail on malformed MCP config files surfaced by v2
  inventory, while keeping MCP server execution and runtime validation out of
  scope.
- Removed stale release-candidate execution notes from the public repository and
  kept local execution notes ignored and excluded from package artifacts.

## 0.1.14 - 2026-06-29

- Strengthened the downstream evidence consumer example so it fails closed on
  inconsistent report status, finding counts, evidence coverage, and surface
  inventory counts.
- Added `owasp_agentic_risk_themes` metadata to deterministic sanitized report
  findings, rendered Markdown, GitHub annotations, and SARIF rule properties as
  a review crosswalk to OWASP Agentic Top 10 risk themes.
- Added strict conformance findings for risky MCP configuration metadata from
  surface inventory v2, while keeping MCP server execution and runtime
  poisoning detection out of scope.
- Added a composite Action `conformance-profile` input so adopters can stay on
  the recommended profile or opt into strict MCP configuration review.
- Updated packaged schemas, public evidence docs, and README examples without
  adding LLM review, issue triage, generic secret scanning, agent execution UI,
  or broad governance behavior.

## 0.1.13 - 2026-06-29

- Corrected the release provenance verification example so it downloads both
  the wheel and sdist explicitly from the PyPI release JSON before running
  `gh attestation verify`.

## 0.1.12 - 2026-06-29

- Added GitHub artifact attestations for release workflow `dist/*` outputs so
  published wheel and sdist files can be verified against release workflow
  provenance.
- Documented release provenance verification and its limits: attestation
  verification proves artifact identity and build provenance, not code
  correctness, maintainer approval, or absence of vulnerabilities.
- Kept the change in the release pipeline and documentation only; no generic
  reviewer, issue triage, secret scanner, runtime UI, or governance framework
  behavior was added.

## 0.1.11 - 2026-06-29

- Added optional `--base-ref` / `--drift-base-ref` policy/spec drift evidence
  that flags changed `.agent-guard` policy files, digest policy files, and
  guard workflow/action surfaces relative to an explicit git base ref.
- Added a composite action `base-ref` input that passes the same opt-in
  baseline comparison into raw drift JSON and the sanitized evidence report.
- Kept baseline comparison as review evidence only: reports emit controlled
  categories and repository-relative paths, not raw diffs, hashes, workflow
  bodies, branch names, local paths, or approval decisions.
- Updated adoption docs to pair baseline-sensitive change evidence with
  digest and context-lock checks without expanding into runtime authorization
  or broad governance tooling.

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
- Clarified the public artifact boundary: raw per-scanner JSON is local/CI
  automation material, while report/render-report/conformance/evidence-pack
  outputs are the reviewable sanitized artifacts.
- Expanded surface inventory v2 with metadata-only agent skills, agent
  profiles, agent commands, hooks, and MCP config references without emitting
  instruction bodies, MCP args, env values, secrets, or local paths.
- Recognized `python3 -m agent_guard.cli` workflow references in addition to
  `python -m agent_guard.cli` and `agent-guard` commands.

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
