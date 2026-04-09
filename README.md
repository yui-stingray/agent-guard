# agent-guard

> Static repository guardrails for agent-touched codebases.
>
> `agent-policy` decides whether an agent should do something.
> `agent-guard` checks whether the repository content still obeys the rules.

**Status**: `0.1.0` alpha. The current MVP ships the API surface guard only.

## Why

`agent-guard` exists to enforce fail-closed static checks around agent-operated repositories without pulling in a full control plane.

The first extracted scanner is intentionally narrow:
- scan repository text files for URLs
- allow explicitly approved API patterns
- fail on forbidden API patterns
- return stable JSON or text output for local hooks and CI

It does **not** manage approvals, logs, state, or UI. Those belong in higher layers.

## Install

```bash
pip install -e .
```

Requires Python 3.11+. The only runtime dependency is `PyYAML`.

## Quick start

```bash
agent-guard api check --root . --policy examples/architecture_policy.yaml
```

JSON mode is stable and intended for CI/wrappers:

```bash
agent-guard api check --root . --policy examples/architecture_policy.yaml --json
```

## Current scanner: API guard

The API guard scans configured paths for URLs and compares them against allow/deny regex lists.

Typical use case:
- keep a CLI-first repository from silently drifting into direct inference API calls

It returns:
- exit `0` on clean
- exit `1` on violation
- exit `2` on configuration/runtime error

## Example policy

```yaml
scan:
  include:
    - src
    - scripts
  exclude:
    - scripts/build_instructions.sh

policy:
  allowed_api_patterns:
    - "^https://ntfy\\.sh/"
  forbidden_api_patterns:
    - "^https://api\\.openai\\.com/"
    - "^https://api\\.anthropic\\.com/"
```

A ready-to-run copy lives in [`examples/architecture_policy.yaml`](examples/architecture_policy.yaml).

## CLI

```bash
agent-guard api check --root <repo> --policy <yaml> [--json]
```

## Roadmap

Planned next extraction:
- content security guard for skills/docs scanning
- shared result envelope across scanners
- optional pre-commit examples

## License

MIT.
