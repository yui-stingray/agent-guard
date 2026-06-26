# agent-guard

> Static repository guardrails for agent-touched codebases.
>
> `agent-policy` decides whether an agent should do something.
> `agent-guard` checks whether the repository content still obeys the rules.

**Status**: `0.1.3` alpha. The current MVP ships five scanners: `api`, `content`, `context`, `path`, and `digest`.

**Paired demo**: `agent-guard` is the static repository gate half of the
toolkit. Use [`agent-policy`](https://github.com/yui-stingray/agent-policy)
for runtime admission, and see
[`agent-safety-toolkit-example`](https://github.com/yui-stingray/agent-safety-toolkit-example)
for a public demo that wires both tools together.

## Why

`agent-guard` exists to enforce fail-closed static checks around agent-operated repositories without pulling in a full control plane.

The current extracted scanners are intentionally narrow:
- `api`: scan repository text files for URLs, allow approved API patterns, fail on forbidden API patterns
- `content`: scan Markdown or other configured text files for dangerous instruction patterns
- `context`: scan agent instruction files such as `AGENTS.md`, `CLAUDE.md`, and Copilot/Cursor/Windsurf rules
- `path`: scan repository path names for private artifacts, env files, and other publish-time leaks
- `digest`: verify SHA-256 pins for governance docs and safety-critical scripts
- return stable JSON or text output for local hooks and CI

It does **not** manage approvals, logs, state, or UI. Those belong in higher layers.

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
| Static repository gate | `agent-guard` | Scan paths, text, API surfaces, and pinned digests for repository safety drift. |

A practical setup uses `agent-policy` in a shell hook or wrapper before an
agent performs a side effect, then runs `agent-guard` in CI or pre-release
checks before the repository is published or merged.

See
[`agent-safety-toolkit-example`](https://github.com/yui-stingray/agent-safety-toolkit-example)
for a small public demo that wires the two tools together.

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

API surface guard:

```bash
agent-guard api check --root . --policy examples/architecture_policy.yaml
```

Content security guard:

```bash
agent-guard content check --repo-root . --policy examples/content_security_policy.yaml --mode registered --scan-dir skills
```

Agent context guard:

```bash
agent-guard context check --root . --policy examples/agent_context_policy.yaml
```

Redacted agent context inventory:

```bash
agent-guard context inventory --root . --policy examples/agent_context_policy.yaml --json
```

Path-name guard:

```bash
agent-guard path check --root . --policy examples/ai_resilience_path_policy.yaml
```

Digest guard:

```bash
agent-guard digest check --root . --policy digest_policy.yaml
```

JSON mode is stable and intended for CI/wrappers:

```bash
agent-guard api check --root . --policy examples/architecture_policy.yaml --json
agent-guard content check --repo-root . --policy examples/content_security_policy.yaml --mode registered --scan-dir skills --json
agent-guard context check --root . --policy examples/agent_context_policy.yaml --json
agent-guard path check --root . --policy examples/ai_resilience_path_policy.yaml --json
agent-guard digest check --root . --policy digest_policy.yaml --json
```

JSON output uses a shared result envelope across scanners:

```json
{
  "schema_version": "agent-guard.result.v1",
  "tool": {"name": "agent-guard", "version": "0.1.3"},
  "scanner": "context",
  "status": "ok",
  "exit_code": 0,
  "policy": {"path": "examples/agent_context_policy.yaml"},
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

## CI gate recipe

For ai-resilience-style repositories, use `agent-guard` as the static half of
the publication gate and pair it with a runtime approval wrapper such as
`agent-policy`. A practical final gate runs these static checks:

```bash
agent-guard path check --root . --policy .agent-guard/path-policy.yaml --json
agent-guard context check --root . --policy .agent-guard/context-policy.yaml --json
agent-guard digest check --root . --policy .agent-guard/constitution-digest-policy.yaml --json
agent-guard content check --repo-root . --policy .agent-guard/content-policy.yaml --mode registered --scan-dir . --json
```

Recommended split:

- `path`: blocks leak-prone names before content is even read, including
  `artifacts/private/`, bypass corpora, red-team logs, and `.env*` files.
- `context`: checks repository-level agent instructions before they become
  durable operating context for coding agents.
- `digest`: pins governance documents and verifier scripts that must not drift
  silently.
- `content`: detects unsafe instruction drift in Markdown, scripts, and other
  configured text surfaces.

Keep explicit git-history checks in the repository workflow for material that
must never have been tracked, such as bypass corpora and private artifacts.
`agent-guard` checks the current tree; `git log --diff-filter=A --name-only`
checks historical contamination.

## Optional pre-commit example

If a repository already uses
[`pre-commit`](https://pre-commit.com/), `agent-guard` can run as an optional
local gate before commits. This is not required for CI; it is a fast feedback
loop for maintainers who want the same checks locally.

Adapt the policy paths to files in the target repository:

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: agent-guard-path
        name: agent-guard path check
        entry: agent-guard
        language: python
        language_version: python3.11
        additional_dependencies: ["yui-agent-guard==0.1.3"]
        args:
          - path
          - check
          - --root
          - .
          - --policy
          - .agent-guard/path-policy.yaml
          - --json
        pass_filenames: false

      - id: agent-guard-context
        name: agent-guard context check
        entry: agent-guard
        language: python
        language_version: python3.11
        additional_dependencies: ["yui-agent-guard==0.1.3"]
        args:
          - context
          - check
          - --root
          - .
          - --policy
          - .agent-guard/context-policy.yaml
          - --json
        pass_filenames: false

      - id: agent-guard-content
        name: agent-guard content check
        entry: agent-guard
        language: python
        language_version: python3.11
        additional_dependencies: ["yui-agent-guard==0.1.3"]
        args:
          - content
          - check
          - --repo-root
          - .
          - --policy
          - .agent-guard/content-policy.yaml
          - --mode
          - registered
          - --scan-dir
          - .
          - --json
        pass_filenames: false
```

Install and test the hooks with:

```bash
pre-commit install
pre-commit run --all-files
```

## Current scanners

### API guard

The API guard scans configured paths for URLs and compares them against allow/deny regex lists.

Typical use case:
- keep a CLI-first repository from silently drifting into direct inference API calls

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
agent-guard context inventory --root . --policy examples/agent_context_policy.yaml --json
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

## CLI

```bash
agent-guard api check --root <repo> --policy <yaml> [--json]
agent-guard content check --repo-root <repo> --policy <yaml> --mode <registered|preregister|new> [--scan-dir <dir>] [--targets <paths...>] [--since-ref <ref>] [--no-untracked] [--json]
agent-guard context check --root <repo> --policy <yaml> [--json]
agent-guard context inventory --root <repo> --policy <yaml> [--json]
agent-guard path check --root <repo> --policy <yaml> [--json]
agent-guard digest check --root <repo> --policy <yaml> [--json]
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

## License

MIT.
