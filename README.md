# agent-guard

> Static repository guardrails for agent-touched codebases.
>
> `agent-policy` decides whether an agent should do something.
> `agent-guard` checks whether the repository content still obeys the rules.

**Status**: `0.1.0` alpha. The current MVP ships four scanners: `api`, `content`, `path`, and `digest`.

## Why

`agent-guard` exists to enforce fail-closed static checks around agent-operated repositories without pulling in a full control plane.

The current extracted scanners are intentionally narrow:
- `api`: scan repository text files for URLs, allow approved API patterns, fail on forbidden API patterns
- `content`: scan Markdown or other configured text files for dangerous instruction patterns
- `path`: scan repository path names for private artifacts, env files, and other publish-time leaks
- `digest`: verify SHA-256 pins for governance docs and safety-critical scripts
- return stable JSON or text output for local hooks and CI

It does **not** manage approvals, logs, state, or UI. Those belong in higher layers.

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
agent-guard path check --root . --policy examples/ai_resilience_path_policy.yaml --json
agent-guard digest check --root . --policy digest_policy.yaml --json
```

## CI gate recipe

For ai-resilience-style repositories, use `agent-guard` as the static half of
the publication gate and pair it with a runtime approval wrapper such as
`agent-policy`. A practical final gate runs all three static checks:

```bash
agent-guard path check --root . --policy .agent-guard/path-policy.yaml --json
agent-guard digest check --root . --policy .agent-guard/constitution-digest-policy.yaml --json
agent-guard content check --repo-root . --policy .agent-guard/content-policy.yaml --mode registered --scan-dir . --json
```

Recommended split:

- `path`: blocks leak-prone names before content is even read, including
  `artifacts/private/`, bypass corpora, red-team logs, and `.env*` files.
- `digest`: pins governance documents and verifier scripts that must not drift
  silently.
- `content`: detects unsafe instruction drift in Markdown, scripts, and other
  configured text surfaces.

Keep explicit git-history checks in the repository workflow for material that
must never have been tracked, such as bypass corpora and private artifacts.
`agent-guard` checks the current tree; `git log --diff-filter=A --name-only`
checks historical contamination.

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
- block hardcoded credential-like strings in agent-authored Markdown
- catch destructive command suggestions before they spread

It returns:
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
exclude_globs:
  - "archive/**"
forbidden_patterns:
  - id: pipe_to_shell
    severity: high
    pattern: '(?i)curl\s+[^\n|]+\|\s*(bash|sh)\b'
    message: "pipe-to-shell pattern is forbidden"
    exclude_globs:
      - "fixtures/red-team/**"
```

A ready-to-run copy lives in [`examples/content_security_policy.yaml`](examples/content_security_policy.yaml).

Content rules may define per-rule `include_globs` / `exclude_globs`. Use this
when a repository contains intentional adversarial fixtures that should stay
scannable for secrets but should not fail dangerous-command rules. For narrow
documented examples, append an inline suppression such as
`# agent-guard: allow pipe_to_shell` or `# agent-guard: allow all` on the same
line.

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
agent-guard path check --root <repo> --policy <yaml> [--json]
agent-guard digest check --root <repo> --policy <yaml> [--json]
```

## Roadmap

Planned next steps:
- shared result envelope helpers across scanners
- optional pre-commit examples

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
