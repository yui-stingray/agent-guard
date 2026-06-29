# agent-guard

[![CI](https://github.com/yui-stingray/agent-guard/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/yui-stingray/agent-guard/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/yui-agent-guard.svg)](https://pypi.org/project/yui-agent-guard/)
[![Python](https://img.shields.io/pypi/pyversions/yui-agent-guard.svg)](https://pypi.org/project/yui-agent-guard/)
[![License](https://img.shields.io/pypi/l/yui-agent-guard.svg)](LICENSE)

> Static repository guardrails for agent-touched codebases.
>
> `agent-policy` decides whether an agent should do something.
> `agent-guard` checks whether the repository content still obeys the rules.

**Status**: `0.1.12` alpha. The current MVP ships six guard scanners:
`api`, `content`, `context`, `path`, `digest`, and `workflow`, plus
review evidence commands for init, surface inventory, policy/spec drift,
profile conformance, and evidence-pack manifests.

**Paired demo**: `agent-guard` is the static repository gate half of the
toolkit. Use [`agent-policy`](https://github.com/yui-stingray/agent-policy)
for runtime admission, and see
[`agent-safety-toolkit-example`](https://github.com/yui-stingray/agent-safety-toolkit-example)
for a public demo that wires both tools together.

## Why

`agent-guard` exists to enforce fail-closed static checks around agent-operated repositories without pulling in a full control plane. It is model- and provider-agnostic: it checks the repository tree and configured policy files, so the same static gate can be used for repos touched by single-model coding agents, MoA-style multi-model agent loops, or persistent agent sessions.

The current extracted scanners are intentionally narrow:
- `api`: scan repository text files for URL/API endpoint references, allow approved endpoint patterns, fail on forbidden endpoint patterns
- `content`: scan Markdown or other configured text files for dangerous instruction patterns
- `context`: scan agent instruction files such as `AGENTS.md`, `CLAUDE.md`, and Copilot/Cursor/Windsurf rules
- `path`: scan repository path names for private artifacts, env files, and other publish-time leaks
- `digest`: verify SHA-256 pins for governance docs and safety-critical scripts
- `workflow`: verify that declared CI guard commands and required policy files remain present
- return stable JSON or text output for local hooks and CI

It does **not** route models, score model quality, run LLM review, manage approvals, logs, state, or UI. Those belong in higher layers.

## Agent safety toolkit

`agent-guard` is one half of a small agent safety toolkit for repositories
touched by coding agents such as Codex, Claude Code, Aider, and similar tools.
It answers the static repository question:

> "Does the repository content still obey the safety rules before hooks, CI,
> release, or publication?"

Pair it with [`agent-policy`](https://github.com/yui-stingray/agent-policy),
which answers the runtime authorization question:

> "Given this repo, capability, and context, should the agent be denied,
> require approval, or be allowed?"

The intended split is:

| Layer | Tool | Responsibility |
| --- | --- | --- |
| Runtime admission | `agent-policy` | Decide whether a normalized agent action is `deny`, `require_approval`, or `auto_allow`. |
| Static repository gate | `agent-guard` | Scan paths, text, URL/API endpoint references, pinned digests, and workflow gates for repository safety drift. |

A practical setup uses `agent-policy` in a shell hook or wrapper before an
agent performs a side effect, then runs `agent-guard` in CI or pre-release
checks before the repository is published or merged.

See
[`agent-safety-toolkit-example`](https://github.com/yui-stingray/agent-safety-toolkit-example)
for a small public demo that wires the two tools together.

See [`docs/evidence-contracts.md`](docs/evidence-contracts.md) for the
versioned evidence contract, public-safe sample report, CI artifact guidance,
SARIF status, and non-goals.
For adoption in an existing repository, start with
[`docs/quickstart-existing-repo.md`](docs/quickstart-existing-repo.md), then use
[`docs/github-actions-evidence.md`](docs/github-actions-evidence.md) for CI
artifacts and annotations. Release timing is described in
[`docs/release-criteria.md`](docs/release-criteria.md). Positioning and
public-facing scope are summarized in [`docs/positioning.md`](docs/positioning.md).

## Install

```bash
pip install yui-agent-guard
```

From a source checkout, install the package in editable mode:

```bash
pip install -e .
```

Requires Python 3.11+. The only runtime dependency is `PyYAML`.

## Quick start

Start by generating deterministic evidence, not by treating `agent-guard` as a
standalone regex scanner.

Preview starter policies and the evidence workflow:

```bash
agent-guard init --root . --json
agent-guard init --root . --write
```

Generate a sanitized evidence report:

```bash
mkdir -p .agent-guard/evidence
agent-guard report --root . --context-policy .agent-guard/context-policy.yaml --evidence-preset recommended --format json --output .agent-guard/evidence/agent-guard-report.json
agent-guard conformance check --root . --evidence .agent-guard/evidence/agent-guard-report.json --profile recommended --json
```

Use the GitHub Action after the starter `.agent-guard` policies are reviewed:

```yaml
permissions:
  contents: read

jobs:
  agent-guard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
      - uses: yui-stingray/agent-guard@v0.1.12
      - name: Upload evidence
        if: always()
        uses: actions/upload-artifact@v7
        with:
          name: agent-guard-evidence
          path: .agent-guard/evidence/
          if-no-files-found: error
```

Run focused scanners when you need faster local feedback:

```bash
agent-guard context check --root . --policy .agent-guard/context-policy.yaml --json
agent-guard path check --root . --policy .agent-guard/path-policy.yaml --json
agent-guard content check --repo-root . --policy .agent-guard/content-policy.yaml --mode registered --scan-dir . --json
```

JSON mode is stable and intended for CI/wrappers:

```bash
agent-guard api check --root . --policy examples/architecture_policy.yaml --json
agent-guard content check --repo-root . --policy .agent-guard/content-policy.yaml --mode registered --scan-dir . --json
agent-guard context check --root . --policy .agent-guard/context-policy.yaml --json
agent-guard surface inventory --root . --context-policy .agent-guard/context-policy.yaml --schema-version v2 --json
agent-guard path check --root . --policy .agent-guard/path-policy.yaml --json
agent-guard digest check --root . --policy .agent-guard/context-digest-policy.yaml --json
agent-guard workflow check --root . --policy .agent-guard/workflow-policy.yaml --json
agent-guard drift check --root . --profile recommended --schema-version v2 --json
```

JSON output uses a shared result envelope across scanners:

```json
{
  "schema_version": "agent-guard.result.v1",
  "tool": {"name": "agent-guard", "version": "0.1.12"},
  "scanner": "context",
  "status": "ok",
  "exit_code": 0,
  "policy": {"path": ".agent-guard/context-policy.yaml"},
  "summary": {
    "finding_count": 0,
    "scanned_count": 1,
    "scanned_unit": "files"
  },
  "finding_count": 0,
  "findings": []
}
```

The envelope keeps existing scanner-specific top-level fields such as
`mode`, `scanned_files`, `scanned_paths`, and `checked_files` where they apply.
Policy paths are emitted as repository-relative or user-provided paths, not
absolute local paths. Error JSON uses the same envelope with `status: "error"`
and `exit_code: 2`.

Raw scanner JSON is for local automation and CI internals, not automatically a
public artifact. Scanner-specific output may include operational details such
as snippets, matched URLs, configured patterns, policy paths, or line-level
diagnostics depending on the scanner and policy. Treat those files as
repository-private unless a maintainer has reviewed them. Public-safe evidence
claims in this README apply to `agent-guard report`, `agent-guard
render-report`, GitHub annotations, SARIF rendered from a report, conformance
output, and evidence-pack manifests.

## CI gate recipe

For ai-resilience-style repositories, use `agent-guard` as the static half of
the publication gate and pair it with a runtime approval wrapper such as
`agent-policy`. A practical final gate runs these static checks:

```bash
agent-guard path check --root . --policy .agent-guard/path-policy.yaml --json
agent-guard context check --root . --policy .agent-guard/context-policy.yaml --json
agent-guard context lock --root . --policy .agent-guard/context-policy.yaml --check --digest-policy .agent-guard/context-digest-policy.yaml --json
agent-guard digest check --root . --policy .agent-guard/context-digest-policy.yaml --json
agent-guard content check --repo-root . --policy .agent-guard/content-policy.yaml --mode registered --scan-dir . --json
agent-guard workflow check --root . --policy .agent-guard/workflow-policy.yaml --json
agent-guard surface inventory --root . --context-policy .agent-guard/context-policy.yaml --schema-version v2 --json
agent-guard drift check --root . --profile recommended --schema-version v2 --json
agent-guard report --root . --context-policy .agent-guard/context-policy.yaml --evidence-preset recommended --api-policy examples/architecture_policy.yaml --digest-policy .agent-guard/context-digest-policy.yaml --format json --output .agent-guard/evidence/agent-guard-report.json
agent-guard conformance check --root . --evidence .agent-guard/evidence/agent-guard-report.json --profile recommended --json
agent-guard evidence-pack manifest --root . --report .agent-guard/evidence/agent-guard-report.json --artifact .agent-guard/evidence/agent-guard-report.json --agent-policy-audit-event .agent-guard/evidence/policy-admission-event.json --json
```

Recommended split:

- `path`: blocks leak-prone names before content is even read, including
  `artifacts/private/`, bypass corpora, red-team logs, and `.env*` files.
- `context`: checks repository-level agent instructions before they become
  durable operating context for coding agents.
- `context lock`: verifies that discovered agent context files are fully
  pinned by the configured digest policy, so newly added agent instructions do
  not bypass drift checks.
- `digest`: pins governance documents and verifier scripts that must not drift
  silently.
- `content`: detects unsafe instruction drift in Markdown, scripts, and other
  configured text surfaces.
- `workflow`: checks that the CI workflow still invokes the declared guard
  commands and still carries the required policy files in the repository.
- `surface inventory v2`: records documented guard commands, evidence artifact
  references, agent skills/profiles/commands/hooks, and MCP configuration
  metadata without emitting raw workflow commands, MCP args, env values, or
  instruction bodies.
- `conformance`: checks sanitized report evidence against `minimal`,
  `recommended`, or `strict` adoption profiles.
- `evidence-pack manifest`: summarizes the public-safe report artifacts that a
  maintainer should inspect in a pull request.

Keep explicit git-history checks in the repository workflow for material that
must never have been tracked, such as bypass corpora and private artifacts.
`agent-guard` checks the current tree; `git log --diff-filter=A --name-only`
checks historical contamination.

## Packaged pre-commit hooks

If a repository already uses
[`pre-commit`](https://pre-commit.com/), `agent-guard` can run as an optional
local gate before commits. This is not required for CI; it is a fast feedback
loop for maintainers who want the same checks locally.

The packaged hooks assume the repository has reviewed `.agent-guard` policies.
Use `agent-guard-evidence` first when you want the deterministic report rather
than a single scanner:

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/yui-stingray/agent-guard
    rev: v0.1.12
    hooks:
      - id: agent-guard-context
      - id: agent-guard-path
      - id: agent-guard-content
      - id: agent-guard-evidence
        stages: [manual]
```

Install and test the hooks with:

```bash
pre-commit install
pre-commit run --all-files
pre-commit run agent-guard-evidence --hook-stage manual --all-files
```

## Current scanners

### API guard

The API guard scans configured paths for URL/API endpoint references and
compares them against allow/deny regex lists. It is endpoint-pattern evidence
for repository architecture boundaries, not a live API client, API catalog,
credential scanner, or network monitor.

Typical use case:
- keep a CLI-first repository from silently drifting into direct inference API endpoint references

It returns:
- exit `0` on clean
- exit `1` on violation
- exit `2` on configuration/runtime error

### Content guard

The content guard scans configured text content for forbidden regex patterns.

Supported modes:
- `registered`: scan a configured directory under the repo
- `preregister`: scan explicit file or directory targets
- `new`: scan changed files from git diff, optionally including untracked files

`new` mode uses two behaviors: with `--since-ref`, it scans files changed between that ref and `HEAD`; without `--since-ref`, it scans the current working tree diff and can optionally include untracked files.

Typical use cases:
- keep dangerous install instructions out of skills docs
- block hardcoded credential-like strings in agent-authored Markdown, YAML, and scripts
- catch destructive command suggestions before they spread

It returns:
- exit `0` on clean
- exit `1` on violation
- exit `2` on configuration/runtime error

### Context guard

The context guard scans common agent instruction files and rule locations:

- `AGENTS.md`
- `CLAUDE.md`
- `GEMINI.md`
- `.github/copilot-instructions.md`
- `.github/instructions/**/*.instructions.md`
- `.cursor/rules/**`
- `.cursorrules`
- `.windsurfrules`
- `.windsurf/rules/**`
- `.continue/rules/**`

Default rules catch context drift that would weaken the repository safety
boundary, such as approval bypass instructions, plaintext secret prompts,
destructive command normalization, and hidden-action instructions.

Typical use cases:
- reject agent context files that tell coding agents to bypass approval or
  policy checks
- keep plaintext secret requests out of durable agent instructions
- scan agent-specific rule files without scanning the entire repository

The opt-in inventory command emits deterministic metadata for discovered
context files without changing `context check --json`:

```bash
agent-guard context inventory --root . --policy .agent-guard/context-policy.yaml --json
agent-guard context lock --root . --policy .agent-guard/context-policy.yaml > .agent-guard/context-lock.yaml
```

Inventory output uses the shared JSON envelope with `command: "inventory"` and
an `inventory` payload. Each entry includes repository-relative paths, context
kind, read status, file size, line count for readable text, and redacted
evidence records for categories such as approval boundaries, tool permissions,
network boundaries, secret handling, destructive-action boundaries, and local
verification guidance. It does not emit raw context contents, snippets, matched
text, raw regex patterns, or absolute local paths.

For `context inventory`, exit `0` means inventory collection succeeded and exit
`2` means configuration/runtime error. Evidence and missing boundary categories
are report data, not violations.

The `context lock` command first requires the existing context check to pass,
then emits a digest policy for the discovered agent context files. It hashes raw
file bytes, emits only repository-relative paths and SHA-256 values, and omits
raw context text. It fails closed when no agent context files are discovered.
The generated YAML can be used directly with `agent-guard digest check` to make
agent context drift explicit. If a repository already has a broader digest
policy for guard policies or verifier scripts, merge the generated context
checks into that policy instead of overwriting it.

Use `context lock --check --digest-policy <yaml>` in CI after the lock has
been reviewed and committed. This coverage gate checks that every discovered
agent context file is present in the digest policy as a full-file pin and that
the current bytes still match. It fails on missing, partial, or mismatched
coverage and emits only repository-relative paths, rule ids, statuses, and
controlled messages.

The report command renders deterministic review evidence for pull requests,
review notes, and GitHub Actions annotations:

```bash
agent-guard report --root . --context-policy .agent-guard/context-policy.yaml --evidence-preset recommended --format json --output .agent-guard/evidence/agent-guard-report.json
agent-guard report --root . --context-policy .agent-guard/context-policy.yaml --format markdown
agent-guard report --root . --context-policy .agent-guard/context-policy.yaml --format json
agent-guard report --root . --context-policy .agent-guard/context-policy.yaml --format json --output .agent-guard/evidence/agent-guard-report.json
agent-guard render-report --root . --input .agent-guard/evidence/agent-guard-report.json --format markdown --output .agent-guard/evidence/agent-guard-report.md
agent-guard render-report --root . --input .agent-guard/evidence/agent-guard-report.json --format github-annotations
agent-guard render-report --root . --input .agent-guard/evidence/agent-guard-report.json --format sarif --output .agent-guard/evidence/agent-guard-results.sarif
agent-guard report --root . --context-policy .agent-guard/context-policy.yaml --digest-policy .agent-guard/context-digest-policy.yaml --format markdown
agent-guard report --root . --context-policy .agent-guard/context-policy.yaml --digest-policy .agent-guard/context-digest-policy.yaml --workflow-policy .agent-guard/workflow-policy.yaml --format markdown
agent-guard report --root . --context-policy .agent-guard/context-policy.yaml --path-policy .agent-guard/path-policy.yaml --content-policy .agent-guard/content-policy.yaml --content-scan-dir . --api-policy examples/architecture_policy.yaml --digest-policy .agent-guard/context-digest-policy.yaml --workflow-policy .agent-guard/workflow-policy.yaml --drift-check --format markdown
agent-guard report --root . --context-policy .agent-guard/context-policy.yaml --path-policy .agent-guard/path-policy.yaml --content-policy .agent-guard/content-policy.yaml --content-scan-dir . --api-policy examples/architecture_policy.yaml --digest-policy .agent-guard/context-digest-policy.yaml --workflow-policy .agent-guard/workflow-policy.yaml --drift-check --drift-schema-version v2 --surface-inventory-version v2 --conformance-profile recommended --evidence-pack-manifest --format json --output .agent-guard/evidence/agent-guard-report.json
agent-guard report --root . --context-policy .agent-guard/context-policy.yaml --path-policy .agent-guard/path-policy.yaml --content-policy .agent-guard/content-policy.yaml --content-scan-dir . --api-policy examples/architecture_policy.yaml --digest-policy .agent-guard/context-digest-policy.yaml --workflow-policy .agent-guard/workflow-policy.yaml --drift-check --drift-schema-version v2 --drift-base-ref origin/main --surface-inventory-version v2 --conformance-profile recommended --evidence-pack-manifest --format json --output .agent-guard/evidence/agent-guard-report.json
```

Use `agent-guard render-report` in CI when Markdown, SARIF, or GitHub
annotations should be derived from one already-sanitized JSON report instead of
rerunning scanner and policy checks for each output format.

`agent-guard report` runs the context check, redacted context inventory, agent surface inventory,
and evidence coverage summary, then emits scanner status, counts,
repository-relative context file paths, permission-boundary status, and finding
anchors limited to severity, rule id, file, and line. Surface inventory lists
agent context files, `.agent-guard` policy files, workflow files, and
agent-guard workflow references as metadata only; v2 also records documented
guard commands, evidence artifact references, agent skills/profiles/commands/
hooks, and MCP configuration metadata. MCP metadata is limited to server name,
transport, command basename, package-manager pin status, remote host, env var
names, filesystem-root presence, and deterministic risk labels; it does not
emit raw args, env values, instruction bodies, or hook bodies. Evidence
coverage records which gates were enabled, missing, clean, or failing without
making missing optional gates a failure. With `--evidence-preset recommended`,
unset report options expand to
the current recommended static evidence bundle: path, content, workflow,
policy/spec drift v2, surface inventory v2, recommended conformance, and an
embedded evidence-pack manifest. The preset intentionally does not enable API
or digest evidence because those policies are repository-specific. With
`--conformance-profile <minimal|recommended|strict>`, it checks
the sanitized report evidence against a named adoption profile. With
`--evidence-pack-manifest`, it embeds a public-safe artifact handoff manifest
for pull request review. Add `--agent-policy-audit-event <path>` to include a
sanitized artifact reference to a companion `agent-policy` audit event without
reading or embedding the event body. With `--path-policy`, it emits path-name evidence
limited to severity, rule id, and repository-relative path. With
`--content-policy`, it emits
registered-mode content evidence limited to severity, rule id,
repository-relative file, and line. With `--api-policy`, it emits API evidence
limited to repository-relative file, line, and controlled category. The report
command does not support content `new` or `preregister` modes; use
`content check` directly for those workflows. With `--digest-policy`, it also
emits sanitized digest drift evidence for pinned context or policy files: check
id, repository-relative path, status, and controlled message. With
`--workflow-policy`, it emits sanitized workflow drift evidence: checked count,
drift finding count, repository-relative workflow file paths, rule ids,
workflow ids, requirement ids, and controlled reasons. With `--drift-check`, it
adds a small policy/spec drift section that checks README recommended guard
commands, required `.agent-guard` policy files, and the workflow policy's
required-file and workflow-command declarations. Add `--drift-base-ref <ref>`
only when CI has fetched an explicit base ref and reviewers need evidence that
`.agent-guard` policies, digest policies, guard workflows, action metadata, or
pre-commit hook metadata changed relative to that baseline. This comparison is
review evidence, not approval or tamper-proof authorization; combine it with
digest and context-lock evidence when context or policy pins matter. It does
not emit the base ref name, raw diffs, expected or actual SHA-256 values, raw
workflow commands, or workflow `run` bodies.

When `--digest-policy` is supplied, the report also emits context lock coverage
evidence. This is separate from digest drift: digest drift checks existing pins,
while context lock coverage checks that all discovered agent context files are
actually pinned. The coverage section contains only severity, rule id,
repository-relative path, status, and check id. It does not emit context text or
hash values.

The Markdown headings for these review sections include `Evidence Coverage`,
`Agent Surface Inventory`, `Conformance Evidence`, `Evidence Pack Manifest`,
and `Context Lock Coverage Evidence`.

Report output omits raw context contents, snippets, matched text, raw regex
patterns, URLs, hashes, secrets, and absolute local paths. These public-safe
claims apply to report/render-report/evidence artifacts, not to raw per-scanner
JSON captured for local automation. Markdown table cells escape HTML and
Markdown control characters before output.

Use `--format json` to emit the same sanitized evidence payload inside the
shared `agent-guard.result.v1` envelope. This is the machine-readable report
contract for wrappers, CI checks, and downstream tooling. Add `--output <path>`
when CI should store the rendered Markdown, JSON, GitHub annotation, or SARIF
evidence as an artifact instead of writing it to stdout. SARIF is a thin
adapter over the sanitized report payload: it emits SARIF 2.1.0 rules,
locations, severity levels, and fingerprints, but not snippets, raw context
text, raw workflow commands, hash values, URLs, secrets, or absolute local
paths.

Use `--format github-annotations` in GitHub Actions to emit `::error` or
`::warning` lines for findings and drift from the same sanitized payload. Clean
reports are quiet in this format. Annotation titles and messages contain only
controlled scanner metadata such as scanner name, rule id, category, status, or
reason.

Use `--format sarif --output .agent-guard/evidence/agent-guard-results.sarif`
when a repository wants to upload findings to GitHub code scanning with
`github/codeql-action/upload-sarif`. Uploading is intentionally left to the
consumer workflow because it changes repository permissions.
SARIF is a thin adapter and not a separate scanner.

For `report`, it returns:
- exit `0` when the report is generated and all enabled checks pass
- exit `1` when the report is generated and any enabled check finds violations
  or context-lock coverage, digest, workflow, or policy/spec drift
- exit `2` on configuration/runtime error

Report output follows `agent-guard.report_evidence.v1`: the evidence payload is
limited to deterministic scanner metadata and sanitized findings. The shared
scanner JSON envelope remains `agent-guard.result.v1`.

#### Packaged JSON schemas

Installed wheels include JSON Schema resources under the `agent_guard.schemas`
package so wrappers and demos can load the evidence contracts without copying
files from the source tree:

- `agent-guard.result.v1.schema.json`: shared scanner result envelope.
- `agent-guard.context_inventory.v1.schema.json`: redacted agent context
  inventory evidence.
- `agent-guard.context_lock_coverage.v1.schema.json`: hash-free context lock
  coverage evidence, including covered context files.
- `agent-guard.report_evidence.v1.schema.json`: sanitized report evidence
  payload for Markdown, JSON, GitHub annotation, and SARIF rendering, including
  surface inventory and evidence coverage on success/violation payloads.
- `agent-guard.conformance.v1.schema.json`: profile evidence for `minimal`,
  `recommended`, and `strict` adoption levels.
- `agent-guard.evidence_pack_manifest.v1.schema.json`: sanitized evidence
  artifact manifest for reviewer handoff.

For `context check`, it returns:
- exit `0` on clean
- exit `1` on violation
- exit `2` on configuration/runtime error

### Path guard

The path guard scans file and directory names under configured roots. It uses
allowlist-first matching so narrow exceptions such as `.env.example` can be
allowed while broader deny patterns still block `.env`, `.env.local`, and
`.env.evil`.

Typical use cases:
- keep `artifacts/private/` out of publishable repository paths
- block bypass corpus files and red-team session logs by name
- catch env-file leaks even when contents are ignored or unreadable

It returns:
- exit `0` on clean
- exit `1` on violation
- exit `2` on configuration/runtime error

### Digest guard

The digest guard verifies pinned SHA-256 values for files that should not
drift silently. Each check names a repository-relative path, an expected
digest, and an optional `start_line` when only the content body should be
hashed.

Typical use cases:
- detect unreviewed edits to governance documents
- pin verifier scripts that protect publication or release gates
- preserve B9-style constitution integrity checks without shell-specific logic

It returns:
- exit `0` on clean
- exit `1` on violation
- exit `2` on configuration/runtime error

### Workflow guard

The workflow guard checks a declared CI workflow for required guard commands
and checks that configured policy files are still present in the repository.
It is intentionally narrower than a workflow security scanner: it does not
evaluate GitHub permissions, branch protection, workflow logs, action versions,
or shell semantics.
Workflow policies must declare `schema_version:
agent-guard.workflow_policy.v1` and at least one `required_files` or
`workflow_checks` entry; empty policies are configuration errors.

Typical use cases:
- catch CI drift where `context`, `digest`, `path`, or `content` guard commands
  are removed from the release gate
- make policy-file presence explicit before a workflow claims to run a guard
- keep static guard coverage reviewable through deterministic JSON output

Command matching only inspects active `jobs.*.steps[*].run` lines. Blank lines,
comments, `echo` / `printf` documentation lines, and here-doc bodies are not
treated as executed guard commands. Findings include repository-relative paths,
rule ids, workflow ids, requirement ids, reasons, and controlled messages; they
do not include raw workflow `run` bodies or raw command text.

It returns:
- exit `0` on clean
- exit `1` on missing required files or missing required workflow commands
- exit `2` on configuration/runtime error

## Example policies

### API guard policy

```yaml
scan:
  include:
    - src
    - scripts
  exclude:
    - scripts/build_instructions.sh

policy:
  allowed_api_patterns:
    - "^https://ntfy\.sh/"
  forbidden_api_patterns:
    - "^https://api\.openai\.com/"
    - "^https://api\.anthropic\.com/"
```

A ready-to-run copy lives in [`examples/architecture_policy.yaml`](examples/architecture_policy.yaml).

### Content guard policy

```yaml
file_globs:
  - "**/*.md"
  - "**/*.yaml"
  - "**/*.yml"
  - "**/*.sh"
  - "**/*.mjs"
exclude_globs:
  - "archive/**"
  - "artifacts/**"
  - "node_modules/**"
  - "examples/content_security_policy.yaml"
forbidden_patterns:
  - id: pipe_to_shell
    severity: high
    pattern: '(?i)curl\s+[^\n|]+\|\s*(bash|sh)\b'
    message: "pipe-to-shell pattern is forbidden"
    exclude_globs:
      - "fixtures/red-team/**"
  - id: destructive_rm_root
    severity: high
    pattern: '(?i)rm\s+-rf\s+(/|~|/home|/mnt/c)'
    message: "destructive rm pattern is forbidden"
```

A ready-to-run copy lives in [`examples/content_security_policy.yaml`](examples/content_security_policy.yaml).

Content rules may define per-rule `include_globs` / `exclude_globs`. Use this
when a repository contains intentional adversarial fixtures that should stay
scannable for secrets but should not fail dangerous-command rules. For narrow
documented examples, append an inline suppression such as
`# agent-guard: allow pipe_to_shell` or `# agent-guard: allow all` on the same
line.

### Context guard policy

```yaml
scan:
  include:
    - "AGENTS.md"
    - "**/AGENTS.md"
    - "CLAUDE.md"
    - "**/CLAUDE.md"
    - ".github/copilot-instructions.md"
    - ".github/instructions/**/*.instructions.md"
    - ".cursor/rules/**/*.md"
    - ".cursorrules"
    - ".windsurfrules"
  exclude:
    - "archive/**"

policy:
  extra_forbidden_patterns:
    - id: unreviewed_tool_allow
      severity: medium
      pattern: "(?i)always\\s+allow.{0,80}(bash|shell|network|write|edit)"
      message: "agent context should not broadly auto-allow risky tools"
```

Use `forbidden_patterns` to replace the default context rules, or
`extra_forbidden_patterns` to append repository-specific rules. A ready-to-run
copy lives in [`examples/agent_context_policy.yaml`](examples/agent_context_policy.yaml).

### Path guard policy

```yaml
scan:
  include:
    - "."
  exclude:
    - ".git"
    - ".venv"
    - "node_modules"

policy:
  allowed_path_patterns:
    - "(^|/)\\.env\\.example$"
  forbidden_path_patterns:
    - id: private_artifacts
      severity: high
      pattern: "(^|/)artifacts/private(/|$)"
      message: "private artifact directory must stay outside published/tracked paths"
    - id: local_artifacts
      severity: high
      pattern: "(^|/)artifacts/local(/|$)"
      message: "local-only artifact directory must stay outside published/tracked paths"
```

A ready-to-run ai-resilience-style copy lives in
[`examples/ai_resilience_path_policy.yaml`](examples/ai_resilience_path_policy.yaml).

### Digest guard policy

```yaml
checks:
  - id: constitution_full
    path: agent-constitution-v0.md
    sha256: "<64-char lowercase sha256>"
  - id: constitution_content
    path: agent-constitution-v0.md
    sha256: "<64-char lowercase sha256>"
    start_line: 15
```

### Workflow guard policy

```yaml
schema_version: agent-guard.workflow_policy.v1

required_files:
  - id: context_policy
    path: .agent-guard/context-policy.yaml
  - id: digest_policy
    path: .agent-guard/context-digest-policy.yaml

workflow_checks:
  - id: ci_static_guards
    path: .github/workflows/ci.yml
    required_commands:
      - id: context_guard
        command: agent-guard context check
      - id: context_lock_coverage
        command: agent-guard context lock --check --digest-policy .agent-guard/context-digest-policy.yaml
      - id: digest_guard
        command: agent-guard digest check
```

Ready-to-run copies live in
[`examples/workflow_policy.yaml`](examples/workflow_policy.yaml) for a minimal
example and [`.agent-guard/workflow-policy.yaml`](.agent-guard/workflow-policy.yaml)
for this repository's self-dogfood gate.

## CLI

```bash
agent-guard init --root <repo> [--print] [--write] [--force] [--json]
agent-guard api check --root <repo> --policy <yaml> [--json]
agent-guard content check --repo-root <repo> --policy <yaml> --mode <registered|preregister|new> [--scan-dir <dir>] [--targets <paths...>] [--since-ref <ref>] [--no-untracked] [--json]
agent-guard context check --root <repo> --policy <yaml> [--json]
agent-guard context inventory --root <repo> --policy <yaml> [--json]
agent-guard context lock --root <repo> --policy <yaml> [--check --digest-policy <yaml>] [--json]
agent-guard surface inventory --root <repo> --context-policy <yaml> [--schema-version <v1|v2>] [--json]
agent-guard report --root <repo> --context-policy <yaml> [--evidence-preset recommended] [--path-policy <yaml>] [--content-policy <yaml>] [--content-scan-dir <dir>] [--api-policy <yaml>] [--digest-policy <yaml>] [--workflow-policy <yaml>] [--drift-check] [--drift-base-ref <ref>] [--agent-policy-audit-event <path>] [--format <markdown|json|github-annotations|sarif>] [--output <path>]
agent-guard render-report --root <repo> --input <agent-guard-report.json> [--format <markdown|json|github-annotations|sarif>] [--output <path>]
agent-guard path check --root <repo> --policy <yaml> [--json]
agent-guard digest check --root <repo> --policy <yaml> [--json]
agent-guard workflow check --root <repo> --policy <yaml> [--json]
agent-guard drift check --root <repo> [--profile <minimal|recommended|strict>] [--schema-version <v1|v2>] [--base-ref <ref>] [--json]
```

## Releases

Tag-driven. Pushing a `vX.Y.Z` annotated tag triggers
[`.github/workflows/release.yml`](.github/workflows/release.yml), which first
verifies that the tag matches `[project].version` in `pyproject.toml`, checks
that the version is not already present on PyPI, then builds the sdist + wheel
and publishes to PyPI via Trusted Publishing (OIDC). No maintainer-side PyPI
token is required once the PyPI project environment is configured. Manual
`workflow_dispatch` with `publish=false` is a build-only dry run; it skips the
publish job. Manual `publish=true` must be run against a `v*` tag ref; running
it from a branch fails before build.

The release build also creates GitHub artifact attestations for the generated
`dist/*` wheel and sdist before upload to the publish job. PyPI Trusted
Publishing and the PyPA publish action provide PyPI-side distribution
attestations for the uploaded files. These attestations are provenance and
integrity evidence for a specific artifact and workflow identity; they are not
proof of code correctness, dependency safety, maintainer approval, or absence
of secrets.

To verify the GitHub provenance for a downloaded release artifact, install the
GitHub CLI and check the tag, repository, and signer workflow explicitly:

```bash
python -m pip download --no-deps "yui-agent-guard==0.1.12" -d dist-verify
gh attestation verify dist-verify/yui_agent_guard-0.1.12-py3-none-any.whl \
  --repo yui-stingray/agent-guard \
  --signer-workflow yui-stingray/agent-guard/.github/workflows/release.yml \
  --source-ref refs/tags/v0.1.12
gh attestation verify dist-verify/yui_agent_guard-0.1.12.tar.gz \
  --repo yui-stingray/agent-guard \
  --signer-workflow yui-stingray/agent-guard/.github/workflows/release.yml \
  --source-ref refs/tags/v0.1.12
```

## License

MIT.
