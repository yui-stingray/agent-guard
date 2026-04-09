# agent-guard

> Static repository guardrails for agent-touched codebases.
>
> `agent-policy` decides whether an agent should do something.
> `agent-guard` checks whether the repository content still obeys the rules.

**Status**: `0.1.0` alpha. The current MVP ships two scanners: `api` and `content`.

## Why

`agent-guard` exists to enforce fail-closed static checks around agent-operated repositories without pulling in a full control plane.

The current extracted scanners are intentionally narrow:
- `api`: scan repository text files for URLs, allow approved API patterns, fail on forbidden API patterns
- `content`: scan Markdown or other configured text files for dangerous instruction patterns
- return stable JSON or text output for local hooks and CI

It does **not** manage approvals, logs, state, or UI. Those belong in higher layers.

## Install

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

JSON mode is stable and intended for CI/wrappers:

```bash
agent-guard api check --root . --policy examples/architecture_policy.yaml --json
agent-guard content check --repo-root . --policy examples/content_security_policy.yaml --mode registered --scan-dir skills --json
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
- block hardcoded credential-like strings in agent-authored Markdown
- catch destructive command suggestions before they spread

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
    pattern: "(?i)curl\s+[^\n|]+\|\s*(bash|sh)\b"
    message: "pipe-to-shell pattern is forbidden"
```

A ready-to-run copy lives in [`examples/content_security_policy.yaml`](examples/content_security_policy.yaml).

## CLI

```bash
agent-guard api check --root <repo> --policy <yaml> [--json]
agent-guard content check --repo-root <repo> --policy <yaml> --mode <registered|preregister|new> [--scan-dir <dir>] [--targets <paths...>] [--since-ref <ref>] [--no-untracked] [--json]
```

## Roadmap

Planned next steps:
- shared result envelope helpers across scanners
- optional pre-commit examples
- public release workflow once the private dogfooding surface is stable

## License

MIT.
