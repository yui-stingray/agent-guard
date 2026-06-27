# Changelog

Where: `CHANGELOG.md`  
What: release notes for published `yui-agent-guard` versions.  
Why: keep static guard releases auditable while the package is still alpha.

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
