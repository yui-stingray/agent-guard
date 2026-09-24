# agent-guard

[![CI](https://github.com/yui-stingray/agent-guard/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/yui-stingray/agent-guard/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/yui-agent-guard.svg)](https://pypi.org/project/yui-agent-guard/)
[![Python](https://img.shields.io/pypi/pyversions/yui-agent-guard.svg)](https://pypi.org/project/yui-agent-guard/)
[![License](https://img.shields.io/pypi/l/yui-agent-guard.svg)](LICENSE)

> Deterministic static evidence for repositories maintained with coding agents.

**Status**: source `0.3.10.dev0` development build. Published install and
copyable Action examples remain pinned to the immutable `0.3.9` release under
the post-release refresh contract. Vendor-neutral, static-only, Python 3.11.4+,
with one runtime dependency (`PyYAML`).

Coding agents can change more than application code. They can also change the
durable repository surfaces that shape later agent runs: instruction files,
skills, MCP configuration, policy files, and CI workflows. Reviewers need a
repeatable answer to a narrower question:

> Which agent-facing surfaces are present, and do they still satisfy the
> reviewed static rules?

`agent-guard` scans a selected repository tree without executing agents, tools,
skills, or MCP servers. Think of it as a linter plus an evidence contract for
agent-facing repository configuration:

- **Inventory** agent instructions, skills, MCP metadata, workflows, policies,
  and evidence artifacts without copying raw instruction bodies into reports.
- **Check** reviewed static rules for unsafe instruction patterns, unpinned MCP
  package commands, leak-prone paths, endpoint/content policy violations, and
  digest or workflow drift.
- **Emit** sanitized report JSON, rendered Markdown, GitHub annotations, and
  SARIF derived from the report payload, plus conformance summaries and
  evidence-pack manifests for CI and maintainer review.

The sanitized public-artifact contract applies to `agent-guard report`,
`agent-guard render-report`, standalone `agent-guard surface inventory`,
GitHub annotations, SARIF rendered from a report, conformance output, and
evidence-pack manifests. Other raw per-scanner JSON remains a
local/CI-internal surface unless a maintainer reviews it. See
[`docs/evidence-contracts.md`](docs/evidence-contracts.md).

## Use it when

- Pull requests can modify agent instructions or agent-facing configuration,
  and maintainers want a deterministic static gate before merge or release.
- Multiple repositories need the same conformance level while keeping reviewed
  policies repository-local.
- CI consumers need stable, sanitized evidence instead of repository contents
  or an LLM-generated verdict.

It is **not** an authorship detector, runtime firewall, LLM reviewer, live OAuth
validator, provenance system, or replacement for a dedicated secret scanner.
See [What it does not do](#what-it-does-not-do).

## Start with a reviewed bootstrap

Choose one entry path: inspect the starter plan without changing the selected
repository, or adopt the reviewed files and generate the first evidence report.

### Preview without target-repository writes

If `uv` is available, preview the current alpha without a persistent install or
target-repository writes:

```bash
uvx --python 3.12 --from yui-agent-guard==0.3.9 agent-guard init --root . --print
```

This pinned command may populate caches outside the repository, but it does not
write the proposed policies or workflow into the selected root. It prints the
proposed starter bundle; it is not a scan or evidence result.

### Adopt after review

Using Python 3.11.4+, install the pinned alpha, review the same plan, write the
starter files, and generate the recommended sanitized evidence. The scanned
repository can use any runtime:

```bash
python -m pip install yui-agent-guard==0.3.9
agent-guard init --root . --print
# Review the proposed policies and workflow before the write step.
agent-guard init --root . --write
# Inspect the generated files before running the first local diagnostic.
agent-guard report --root . --context-policy .agent-guard/context-policy.yaml --evidence-preset recommended --format json --output .agent-guard/evidence/agent-guard-report.json --stderr-summary
```

`init --write` creates starter policies and a pinned GitHub Actions workflow
with the context-policy preflight and one-minute Action timeout.
The report command creates its output directory and writes the public-safe
evidence artifact. Exit `1` means evidence was generated with findings or
drift; exit `>=2` means setup, configuration, or execution failed.
Review and commit the starter policies and replacement workflow only after
resolving findings. Keep reports uncommitted unless curated as sanitized
samples. Treat adoption as complete only after a successful default-branch run.
The [existing-repo quickstart](docs/quickstart-existing-repo.md) covers the
green CI path, Windows PowerShell, and monorepo roots.

## Scanners

Seven narrow, composable scanners. Each returns stable JSON or text output for
local hooks and CI, and `agent-guard report` combines them into one sanitized
evidence payload.

| Scanner | Checks |
| --- | --- |
| `api` | Repository text files for URL/API endpoint references; allows approved patterns and fails on forbidden ones. |
| `content` | Markdown or other configured text files for dangerous instruction patterns. |
| `context` | Agent instruction files such as `AGENTS.md`, `CLAUDE.md`, and Copilot/Cursor/Windsurf rules. |
| `mcp` | Committed MCP configuration metadata for parse errors and deterministic risk labels, without executing MCP servers. |
| `path` | Repository path names for private artifacts, env files, and other publish-time leaks. |
| `digest` | SHA-256 pins for governance docs and safety-critical scripts. |
| `workflow` | Declared CI guard commands and required policy files remain present. |

Per-scanner behavior, report details, JSON schemas, and example policies are in
the [scanner reference](docs/scanners.md). The full command synopsis is in the
[CLI reference](docs/cli-reference.md).

## Use in CI

`init --write` generates a pinned GitHub Actions workflow; review and commit it,
or use the packaged Action on a Linux runner. Both generate static evidence
only. The recommended gate checks, runnable locally or in any CI system, are:

```bash
agent-guard path check --root . --policy .agent-guard/path-policy.yaml --json
agent-guard context check --root . --policy .agent-guard/context-policy.yaml --json
agent-guard content check --repo-root . --policy .agent-guard/content-policy.yaml --mode registered --scan-dir . --json
agent-guard mcp check --root . --policy .agent-guard/mcp-policy.yaml --json
agent-guard workflow check --root . --policy .agent-guard/workflow-policy.yaml --json
agent-guard surface inventory --root . --context-policy .agent-guard/context-policy.yaml --schema-version v2 --json
agent-guard drift check --root . --profile recommended --schema-version v2 --json
```

After a digest policy has been reviewed and committed, also check context-lock
coverage and digest drift (required by the `strict` profile):

```bash
agent-guard context lock --root . --policy .agent-guard/context-policy.yaml --check --digest-policy .agent-guard/context-digest-policy.yaml --json
agent-guard digest check --root . --policy .agent-guard/context-digest-policy.yaml --json
```

- [CI reference](docs/ci-reference.md): the copyable Action workflow with the
  context-policy preflight, the full CI gate recipe, optional API/digest/audit
  inputs, and packaged pre-commit hooks.
- [GitHub Actions evidence](docs/github-actions-evidence.md): artifacts,
  annotations, SARIF, and surface-delta evidence on pull requests.

## What it does not do

It does **not** route models, score model quality, run LLM review, manage
approvals, logs, state, or UI. It also does not execute MCP servers, validate
live OAuth flows, or replace dedicated secret scanners. Those belong in higher
layers. The [threat model](docs/threat-model.md) lists the explicit runtime and
security non-goals.

## Related projects

`agent-guard` is the standalone public entry and works on its own as a
standalone static publication gate. If a repository also needs runtime
admission, `agent-policy` is an optional advanced runtime companion.

| Repository | Role |
| --- | --- |
| [`agent-guard`](https://github.com/yui-stingray/agent-guard) | Static repository gate: deterministic evidence before merge, release, or publication (this repository). |
| [`agent-policy`](https://github.com/yui-stingray/agent-policy) | Companion policy decision layer for repository-scoped agent permissions and audit events. |
| [`agent-safety-toolkit-example`](https://github.com/yui-stingray/agent-safety-toolkit-example) | Public demo showing how agent-guard and agent-policy are used together in CI to produce review evidence. |

The optional two-layer setup has this split:

| Layer | Tool | Responsibility |
| --- | --- | --- |
| Optional runtime admission | `agent-policy` | Decide whether a normalized agent action is `deny`, `require_approval`, or `auto_allow`. |
| Static repository gate | `agent-guard` | Scan paths, text, URL/API endpoint references, pinned digests, and workflow gates for static repository drift. |

The example repository is a reference implementation of that setup, not a
prerequisite for the reviewed bootstrap or CI gate above.

## Documentation

**Getting started**

- [Existing-repo quickstart](docs/quickstart-existing-repo.md): the
  minimal-to-recommended path and monorepo/subdirectory roots, plus Windows PowerShell.
- [CI reference](docs/ci-reference.md) and [GitHub Actions evidence](docs/github-actions-evidence.md).

**Reference**

- [Scanner reference](docs/scanners.md) and [CLI reference](docs/cli-reference.md).
- [Evidence contracts](docs/evidence-contracts.md): versioned report contract, public-safe sample report, and SARIF status.
- [Evidence consumer contracts](docs/evidence-consumer-contracts.md): for downstream CI consumers that need
  fail-closed missing/invalid/report-visible drift checks, public-artifact linting, or strict release gates.
- [Compatibility](docs/compatibility.md) and [AST crosswalk](docs/ast-crosswalk.md).
- [Benchmark results](docs/benchmark-results.md): Agent-Guard Bench (AGB) is local deterministic regression
  evidence, not an independently verified quality benchmark.

**Design and project**

- [Threat model](docs/threat-model.md) and [positioning](docs/positioning.md), with a focused [`agent-audit` comparison](docs/comparison.md).
- [Ecosystem design](docs/architecture/agent-guard-ecosystem-design.md): the cross-repository normative baseline.
- [Operations governance](docs/operations-governance.md): audited break-glass and release-containment procedures.
- [Release criteria](docs/release-criteria.md), [releases](docs/releasing.md), and the [demand-validation plan](docs/demand-validation.md).

## Installation notes

The evaluation and adoption commands above pin the current alpha so the
reviewed behavior does not change between runs.

Windows PowerShell users can follow the non-activation virtual-environment
commands in the [existing-repo quickstart](docs/quickstart-existing-repo.md).

From a source checkout, install the package in editable mode:

```bash
pip install -e .
```

Requires Python 3.11.4+. The only runtime dependency is `PyYAML`.
That requirement is for the `agent-guard` execution environment only. The
repository being scanned can be Go, JavaScript, Ruby, a different Python
version, or any other source tree because `agent-guard` reads repository files
statically. The packaged GitHub Action provisions its own Python runtime.
The Python CLI supports the platforms described in
[`docs/compatibility.md`](docs/compatibility.md); the packaged composite Action
currently requires a Linux runner.

## License

MIT.
