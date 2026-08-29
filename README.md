# agent-guard

[![CI](https://github.com/yui-stingray/agent-guard/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/yui-stingray/agent-guard/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/yui-agent-guard.svg)](https://pypi.org/project/yui-agent-guard/)
[![Python](https://img.shields.io/pypi/pyversions/yui-agent-guard.svg)](https://pypi.org/project/yui-agent-guard/)
[![License](https://img.shields.io/pypi/l/yui-agent-guard.svg)](LICENSE)

> Deterministic static evidence for repositories maintained with coding agents.

**Status**: `0.3.9` alpha. Package install examples use this release; copyable
Action examples remain pinned to the immutable `0.3.8` release under the
post-release refresh contract. Vendor-neutral, static-only, Python 3.11.4+,
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
`agent-guard` is the standalone public entry. For advanced runtime admission,
[`agent-policy`](https://github.com/yui-stingray/agent-policy) is an optional advanced runtime companion; the public
[`agent-safety-toolkit-example`](https://github.com/yui-stingray/agent-safety-toolkit-example)
is a reference implementation that shows the two layers together.

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

Agent-Guard Bench (AGB) is documented in
[`docs/benchmark-results.md`](docs/benchmark-results.md). It is local
deterministic regression evidence, not an independently verified quality
benchmark.

## Why

The seven scanners are intentionally narrow and composable:

- `api`: scan repository text files for URL/API endpoint references, allow approved endpoint patterns, fail on forbidden endpoint patterns
- `content`: scan Markdown or other configured text files for dangerous instruction patterns
- `context`: scan agent instruction files such as `AGENTS.md`, `CLAUDE.md`, and Copilot/Cursor/Windsurf rules
- `mcp`: scan committed MCP configuration metadata for parse errors and deterministic risk labels without executing MCP servers
- `path`: scan repository path names for private artifacts, env files, and other publish-time leaks
- `digest`: verify SHA-256 pins for governance docs and safety-critical scripts
- `workflow`: verify that declared CI guard commands and required policy files remain present
- return stable JSON or text output for local hooks and CI

It does **not** route models, score model quality, run LLM review, manage
approvals, logs, state, or UI. It also does not execute MCP servers, validate
live OAuth flows, or replace dedicated secret scanners. Those belong in higher
layers.

## Agent safety toolkit

`agent-guard` is the standalone public entry for repositories touched by coding
agents such as Codex, Claude Code, Aider, and similar tools. It answers the
static repository question:

> "Does the repository content still obey the safety rules before hooks, CI,
> release, or publication?"

For advanced runtime admission, [`agent-policy`](https://github.com/yui-stingray/agent-policy) is an optional advanced
runtime companion that answers the runtime authorization question:

> "Given this repo, capability, and context, should the agent be denied,
> require approval, or be allowed?"

The optional two-layer setup has this split:

| Layer | Tool | Responsibility |
| --- | --- | --- |
| Optional runtime admission | `agent-policy` | Decide whether a normalized agent action is `deny`, `require_approval`, or `auto_allow`. |
| Static repository gate | `agent-guard` | Scan paths, text, URL/API endpoint references, pinned digests, and workflow gates for static repository drift. |

An advanced setup can use `agent-policy` in a shell hook or wrapper before an
agent performs a side effect, then run `agent-guard` in CI or pre-release checks
before the repository is published or merged.

[`agent-safety-toolkit-example`](https://github.com/yui-stingray/agent-safety-toolkit-example)
is a reference implementation of that optional two-layer setup, not a
prerequisite for the reviewed bootstrap or CI gate above.

See [`docs/evidence-contracts.md`](docs/evidence-contracts.md) for the
versioned evidence contract, public-safe sample report, CI artifact guidance,
SARIF status, and non-goals. For the static evidence threat model and explicit
runtime/security non-goals, see [`docs/threat-model.md`](docs/threat-model.md).
Downstream CI consumers that need fail-closed missing/invalid/report-visible drift checks,
public-artifact linting, or strict release gates can start from
[`docs/evidence-consumer-contracts.md`](docs/evidence-consumer-contracts.md).
For adoption in an existing repository, start with
[`docs/quickstart-existing-repo.md`](docs/quickstart-existing-repo.md) for the
minimal-to-recommended path and monorepo/subdirectory roots, then use
[`docs/github-actions-evidence.md`](docs/github-actions-evidence.md) for CI
artifacts and annotations. Release timing is described in
[`docs/release-criteria.md`](docs/release-criteria.md), and the current
[demand-validation plan](docs/demand-validation.md) records the public-feature
freeze and continuation gate. Positioning and
public-facing scope are summarized in [`docs/positioning.md`](docs/positioning.md),
with a focused [`agent-audit` comparison](docs/comparison.md).

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

## Adoption and CI reference

The reviewed bootstrap above is the canonical adoption path. Start by
generating deterministic evidence, not by treating `agent-guard` as a
standalone regex scanner.

The command names the reviewed repo-local context policy explicitly so the
policy choice remains visible in review. The recommended preset supplies the
reviewed repo-local MCP policy and embeds recommended conformance plus an
evidence-pack manifest. `--output` creates parent directories as needed;
`--stderr-summary` prints one sanitized status line for humans and CI logs after
the report is written. Exit `1` is a diagnostic success: evidence was generated
and findings or drift were found. Exit `>=2` is a usage, configuration, or
runtime error that must be fixed before interpreting findings. Run the
standalone commands only when a separate consumer artifact is needed.

If the repository already has some reviewed guard files, use partial adoption
only to preserve them with
`agent-guard init --root . --write --skip-existing`. `--skip-existing` keeps
existing files unchanged and writes only missing starter files. It is not a
trust signal. Follow it with the recommended report and conformance review so
maintainers can inspect which files were preserved, created, and still need
policy or workflow alignment.

`init --write` also creates `.github/workflows/agent-guard.yml`. Review and
commit that generated workflow, or use the packaged alpha GitHub Action
directly on a Linux runner. The action generates static evidence only; it does
not execute agents, MCP servers, or an LLM reviewer:

```yaml
permissions:
  contents: read
on: [push, pull_request]
jobs:
  agent-guard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0 # v7
        with:
          fetch-depth: 0
          persist-credentials: false
      - name: Reject unreviewed context policy changes
        if: github.event_name == 'pull_request'
        env:
          AGENT_GUARD_PR_BASE_SHA: ${{ github.event.pull_request.base.sha }}
          AGENT_GUARD_ROOT: "."
          AGENT_GUARD_CONTEXT_POLICY: .agent-guard/context-policy.yaml
        run: |
          set -euo pipefail

          fail_preflight() {
            echo "::error::pull request context policy preflight configuration is invalid"
            exit 2
          }

          validate_repo_relative_path() {
            local candidate="$1"
            local allow_root_dot="$2"
            local part
            local -a parts

            if [ "$allow_root_dot" = "true" ] && [ "$candidate" = "." ]; then
              return 0
            fi
            case "$candidate" in
              ""|/*|*/|*//* ) fail_preflight ;;
            esac
            if [[ ! "$candidate" =~ ^[A-Za-z0-9._@+=,~/-]+$ ]]; then
              fail_preflight
            fi
            IFS='/' read -r -a parts <<< "$candidate"
            for part in "${parts[@]}"; do
              case "$part" in
                ""|.|..) fail_preflight ;;
              esac
            done
          }

          base_sha="${AGENT_GUARD_PR_BASE_SHA:-}"
          root="${AGENT_GUARD_ROOT:-.}"
          context_policy="${AGENT_GUARD_CONTEXT_POLICY:-.agent-guard/context-policy.yaml}"

          case "$base_sha" in
            ""|*[!0-9a-f]*) fail_preflight ;;
          esac
          if [ "${#base_sha}" -ne 40 ] && [ "${#base_sha}" -ne 64 ]; then
            fail_preflight
          fi
          if ! git cat-file -e "${base_sha}^{commit}" 2>/dev/null; then
            fail_preflight
          fi

          validate_repo_relative_path "$root" true
          validate_repo_relative_path "$context_policy" false
          if [ "$root" = "." ]; then
            effective_policy="$context_policy"
          else
            effective_policy="$root/$context_policy"
          fi

          cursor=""
          IFS='/' read -r -a policy_parts <<< "$effective_policy"
          for part in "${policy_parts[@]}"; do
            cursor="${cursor:+$cursor/}$part"
            if [ -L "$cursor" ]; then
              fail_preflight
            fi
          done
          if [ ! -f "$effective_policy" ] || [ -L "$effective_policy" ]; then
            fail_preflight
          fi

          current_entry="$(git ls-files --stage -- "$effective_policy")"
          current_mode="${current_entry%% *}"
          case "$current_mode" in
            100644|100755) ;;
            *) fail_preflight ;;
          esac

          base_entry="$(git ls-tree "$base_sha" -- "$effective_policy")"
          base_mode="${base_entry%% *}"
          base_rest="${base_entry#* }"
          base_type="${base_rest%% *}"
          case "$base_mode:$base_type" in
            100644:blob|100755:blob) ;;
            *) fail_preflight ;;
          esac

          if git diff --quiet "$base_sha" -- "$effective_policy"; then
            :
          else
            diff_status="$?"
            if [ "$diff_status" -eq 1 ]; then
              echo "::error::context policy preflight rejected a pull-request change; review and merge it separately before rerunning evidence from a trusted revision"
              exit 1
            fi
            fail_preflight
          fi
      - id: agent-guard
        uses: yui-stingray/agent-guard@3d8c99ee502b914ccc3d605ad469d96b098d6212 # v0.3.8
        timeout-minutes: 1
        with:
          conformance-profile: recommended
      - name: Upload evidence
        if: >-
          always() &&
          steps.agent-guard.outputs.ready == 'true' && (steps.agent-guard.outputs.status == '0' || steps.agent-guard.outputs.status == '1')
        uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1
        with:
          name: agent-guard-evidence
          path: |
            ${{ steps.agent-guard.outputs.report-json }}
            ${{ steps.agent-guard.outputs.report-markdown }}
            ${{ steps.agent-guard.outputs.report-sarif }}
            ${{ steps.agent-guard.outputs.evidence-dir }}/agent-guard-conformance.json
            ${{ steps.agent-guard.outputs.evidence-dir }}/agent-guard-evidence-pack.json
            ${{ steps.agent-guard.outputs.evidence-dir }}/agent-surface-inventory.json
          if-no-files-found: error
```

The pull-request preflight derives the effective context-policy path from the
same `root` and `context-policy` values passed to the Action. It requires a
tracked regular file at that repository-relative path, rejects symlinked path
components, and emits no diff or path value. Keep it before the current published
`v0.3.8` Action and keep the one-minute step limit, which is GitHub Actions'
smallest supported positive timeout. These controls remain useful as
defense in depth after the regex isolation fix. If a pull request changes the
effective context policy, review and merge that policy change separately before
rerunning evidence from the trusted revision. A pull request that changes this
workflow must receive the repository's normal workflow review; an in-repository
preflight is not an independent trust anchor.

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
  "tool": {"name": "agent-guard", "version": "0.3.9"},
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
public artifact, except for the recursively sanitized standalone
`surface inventory` payload named below. Scanner-specific output may include
operational details such as scanner metadata, policy paths, or line-level
diagnostics depending on the scanner and policy. Treat those files as
repository-private unless a maintainer has reviewed them. Public-safe evidence
statements apply to `agent-guard report`, `agent-guard render-report`,
standalone `agent-guard surface inventory`, GitHub annotations, SARIF rendered
from a report, conformance output, and evidence-pack manifests.

## CI gate recipe

For repositories that publish artifacts or accept changes to agent-facing
configuration, use `agent-guard` as a standalone static publication gate. If a
repository also needs runtime admission, pair it with an approval wrapper such
as `agent-policy`. A practical final static gate runs the starter-policy
baseline generated by `init --write`:

```bash
agent-guard path check --root . --policy .agent-guard/path-policy.yaml --json
agent-guard context check --root . --policy .agent-guard/context-policy.yaml --json
agent-guard content check --repo-root . --policy .agent-guard/content-policy.yaml --mode registered --scan-dir . --json
agent-guard mcp check --root . --policy .agent-guard/mcp-policy.yaml --json
agent-guard workflow check --root . --policy .agent-guard/workflow-policy.yaml --json
agent-guard surface inventory --root . --context-policy .agent-guard/context-policy.yaml --schema-version v2 --json
agent-guard drift check --root . --profile recommended --schema-version v2 --json
agent-guard report --root . --context-policy .agent-guard/context-policy.yaml --evidence-preset recommended --mcp-policy .agent-guard/mcp-policy.yaml --format json --output .agent-guard/evidence/agent-guard-report.json
agent-guard conformance check --root . --evidence .agent-guard/evidence/agent-guard-report.json --profile recommended --json
agent-guard evidence-pack manifest --root . --report .agent-guard/evidence/agent-guard-report.json --artifact .agent-guard/evidence/agent-guard-report.json --json
```

Add each of the following only after its repository-specific input has been
reviewed.

**Optional reviewed API policy.** Run
`agent-guard api check --root . --policy <reviewed-api-policy.yaml> --json`,
then add `--api-policy <reviewed-api-policy.yaml>` to the `report` command when
that policy is part of the gate.

**Optional reviewed digest policy.** After reviewing context files, generate
and commit the digest policy, then run:

```bash
agent-guard context lock --root . --policy .agent-guard/context-policy.yaml > .agent-guard/context-digest-policy.yaml
agent-guard context lock --root . --policy .agent-guard/context-policy.yaml --check --digest-policy .agent-guard/context-digest-policy.yaml --json
agent-guard digest check --root . --policy .agent-guard/context-digest-policy.yaml --json
```

Add `--digest-policy .agent-guard/context-digest-policy.yaml` to the `report`
command only after that policy is reviewed and committed.

**Optional reviewed audit event.** To record a companion `agent-policy` audit
event, add the same `--agent-policy-audit-event <reviewed-audit-event-path>` and
`--agent-policy-audit-event-profile agent-guard.public_agent_policy_audit_event.v1`
options to
both producer commands. Regenerate both artifacts after a maintainer reviews
the repo-local JSON event. The manifest records a sanitized relative path and
profile-bound digest, never the body. Producer and consumer validate the
recognized event shape; this checks semantics, not who approved the event.
When consuming source-tree v2 evidence, also pass `--repo-root <repo>` to the
consumer. Each supplied event must use a canonical repository-relative path or
a canonical absolute in-root path whose derived relative path exactly matches
the same-position manifest artifact; dot/parent aliases and path escapes fail
closed. The CLI retains the raw spelling. Programmatic v2 callers must likewise
pass raw `str` values; `Path` objects are rejected because alias spelling may
already have been erased. The bounded descriptor must remain metadata-stable
and identify the current no-follow path after the read. Event-free v1
consumption does not require this option.
For this guard-owned v2 contract, sanitized paths use non-whitespace printable
ASCII only and reject absolute paths, colons, backslashes, dot segments,
controlled secret-shaped values, and every embedded raw 64-hex hash. This is a
public-artifact grammar, not generic secret scanning.
Events select evidence v2; event-free reports stay v1. A standalone manifest
must match the embedded one, and consumers require the event and profile again.
Keep the event outside `.agent-guard/evidence`; the bundle allow-list rejects
it.

The following optional PR review command is available in `0.3.0`:

```bash
agent-guard surface delta --root . --context-policy .agent-guard/context-policy.yaml --base-ref <base-ref> --json
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
- `mcp`: checks committed MCP configuration metadata for parse errors,
  unpinned or `@latest` package-manager server commands, filesystem-root
  references, unsafe URL schemes, broad authorization scopes, and inline
  authorization values without running MCP servers. Recommended and strict
  conformance require the reviewed repo-local `.agent-guard/mcp-policy.yaml`,
  which makes the enforced static risk-label set explicit while keeping the same
  metadata boundary.
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
    rev: v0.3.9
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

`new` mode always scans bytes from the current working tree. With
`--since-ref`, the `ref...HEAD` diff selects file names and does not add staged,
unstaged, or untracked names. Without `--since-ref`, staged and unstaged names
are selected and untracked names are optional. A selected staged file whose
index and working-tree versions differ is rejected with exit `2` instead of
claiming that either version was checked for commit. Use a clean, quiescent
checkout when treating `--since-ref` output as change-range evidence.

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
agent-guard context lock --root . --policy .agent-guard/context-policy.yaml > .agent-guard/context-digest-policy.yaml
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
agent-guard report --root . --context-policy .agent-guard/context-policy.yaml --evidence-preset recommended --mcp-policy .agent-guard/mcp-policy.yaml --format json --output .agent-guard/evidence/agent-guard-report.json
agent-guard report --root . --context-policy .agent-guard/context-policy.yaml --format markdown
agent-guard report --root . --context-policy .agent-guard/context-policy.yaml --format json
agent-guard report --root . --context-policy .agent-guard/context-policy.yaml --format json --output .agent-guard/evidence/agent-guard-report.json
agent-guard render-report --root . --input .agent-guard/evidence/agent-guard-report.json --format markdown --output .agent-guard/evidence/agent-guard-report.md
agent-guard render-report --root . --input .agent-guard/evidence/agent-guard-report.json --format github-annotations
agent-guard render-report --root . --input .agent-guard/evidence/agent-guard-report.json --format sarif --output .agent-guard/evidence/agent-guard-results.sarif
agent-guard report --root . --context-policy .agent-guard/context-policy.yaml --digest-policy .agent-guard/context-digest-policy.yaml --format markdown
agent-guard report --root . --context-policy .agent-guard/context-policy.yaml --digest-policy .agent-guard/context-digest-policy.yaml --workflow-policy .agent-guard/workflow-policy.yaml --format markdown
agent-guard report --root . --context-policy .agent-guard/context-policy.yaml --path-policy .agent-guard/path-policy.yaml --content-policy .agent-guard/content-policy.yaml --content-scan-dir . --api-policy examples/architecture_policy.yaml --digest-policy .agent-guard/context-digest-policy.yaml --workflow-policy .agent-guard/workflow-policy.yaml --drift-check --format markdown
agent-guard report --root . --context-policy .agent-guard/context-policy.yaml --path-policy .agent-guard/path-policy.yaml --content-policy .agent-guard/content-policy.yaml --content-scan-dir . --api-policy examples/architecture_policy.yaml --mcp-policy .agent-guard/mcp-policy.yaml --digest-policy .agent-guard/context-digest-policy.yaml --workflow-policy .agent-guard/workflow-policy.yaml --drift-check --drift-schema-version v2 --surface-inventory-version v2 --conformance-profile recommended --evidence-pack-manifest --format json --output .agent-guard/evidence/agent-guard-report.json
agent-guard report --root . --context-policy .agent-guard/context-policy.yaml --path-policy .agent-guard/path-policy.yaml --content-policy .agent-guard/content-policy.yaml --content-scan-dir . --api-policy examples/architecture_policy.yaml --mcp-policy .agent-guard/mcp-policy.yaml --digest-policy .agent-guard/context-digest-policy.yaml --workflow-policy .agent-guard/workflow-policy.yaml --drift-check --drift-schema-version v2 --drift-base-ref origin/main --surface-inventory-version v2 --conformance-profile recommended --evidence-pack-manifest --format json --output .agent-guard/evidence/agent-guard-report.json
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
names, filesystem-root presence, and deterministic risk labels for static
authorization, scope, URL-scheme, package, path, and inline-value review; it
does not emit raw args, env values, authorization values, scope strings, URLs,
instruction bodies, or hook bodies. Static authorization, scope, and URL-scheme
labels are review metadata over committed configuration only; they do not prove
that a live OAuth flow is correctly implemented or that an MCP server is safe to
execute. Findings and surface risk labels may also include
`owasp_agentic_risk_themes`, a static crosswalk to OWASP Agentic Top 10 risk
themes. These labels are review metadata for deterministic evidence; they are
not runtime vulnerability detection, live OAuth validation,
SLSA/provenance verification, or proof that a category is exploitable.
Evidence coverage records which gates
were enabled, missing, clean, or failing without
making missing optional gates a failure. With `--evidence-preset recommended`,
unset report options expand to
the current recommended static evidence bundle: path, content, MCP config,
workflow, policy/spec drift v2, surface inventory v2, recommended conformance,
and an embedded evidence-pack manifest. The preset intentionally does not enable
API or digest evidence because those policies are repository-specific. With
`--conformance-profile <minimal|recommended|strict>`, it checks the sanitized
report evidence against a named adoption profile. `mcp check` and the
recommended report preset fail on malformed committed MCP config files or risky
MCP configuration metadata, such as unpinned package-manager commands or
secret-shaped inline values, unsafe URL schemes, broad authorization scopes, or
inline authorization values. For recommended and strict evidence, keep the
reviewed risk-label policy at `.agent-guard/mcp-policy.yaml`; external MCP
policy files can be used for scanner experiments but do not satisfy conformance.
The `strict` profile also turns the same v2 surface inventory labels into conformance findings.
None of these modes execute MCP servers, inspect tool results, validate live OAuth flows,
detect MCP tool-poisoning behavior, or act as an MCP runtime security validator. The current
MCP 2026-07-28 protocol/runtime/OAuth changes do not justify runtime execution or live OAuth
validation. No changelog item directly invalidates the current static committed-config labels, so
this update does not change their taxonomy or code. With `--evidence-pack-manifest`,
it embeds a public-safe artifact handoff manifest for pull request review. Use
`--agent-policy-audit-event <path>` with profile
`agent-guard.public_agent_policy_audit_event.v1`
to bind a reviewed event without its body. Consumers require that event again;
source-tree v2 consumers also require `--repo-root <repo>` and exact positional
artifact-path equality. Arbitrary JSON objects, path aliases or escapes, and
unsupported profile labels fail closed before binding verification. The
programmatic v2 validator accepts only raw path strings, not normalized `Path`
objects, and rejects replacement of the repository path during its bounded
descriptor read.

Read `recommended` as the reviewed static evidence baseline, not as the full
pin-integrity profile. The recommended preset can emit digest and context-lock
evidence when `--digest-policy` is supplied, but recommended conformance does not
require those gates because digest policies are repository-specific. Use
`strict` when context-lock coverage, digest drift, sanitized evidence-pack
artifacts, and v2 MCP configuration risk labels should be conformance
requirements.

With `--path-policy`, it emits path-name evidence
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
patterns, raw evidence URLs, raw repository/content/digest hashes, secrets, and
absolute local paths. Here, public-safe means sanitized under the declared
controlled-field/controlled-pattern contract, not a generic guarantee that an
artifact contains no secrets or PII; it does not replace a dedicated secret scanner.
This scope applies only to report/render-report/evidence artifacts, not raw per-scanner JSON; Markdown table cells escape HTML and Markdown control characters before output.

Use `--format json` to emit the same sanitized evidence payload inside the
shared `agent-guard.result.v1` envelope. This is the machine-readable report
contract for wrappers, CI checks, and downstream tooling. Add `--output <path>`
when CI should store the rendered Markdown, JSON, GitHub annotation, or SARIF
evidence as an artifact instead of writing it to stdout. SARIF is a thin
adapter over the sanitized report payload: it emits SARIF 2.1.0 rules,
locations, severity levels, and fingerprints derived from sanitized rule,
location, and message metadata, but not snippets, raw context text, raw
workflow commands, raw repository/content/digest hash values, raw evidence
URLs, secrets, or absolute local paths.

Relative report and render-report output paths are resolved beneath `--root`;
parent traversal and symlink or Windows reparse-point ancestors are rejected.
An absolute output path is an explicit trusted destination. Both forms write
through an exclusive regular temporary file in the validated destination
directory and atomically replace the final entry without following a final
symlink.

Use `--format github-annotations` in GitHub Actions to emit `::error` or
`::warning` lines for findings and drift from the same sanitized payload. Clean
reports are quiet in this format. Annotation titles and messages contain only
controlled scanner metadata such as scanner name, rule id, category, status, or
reason, plus OWASP risk-theme labels when a deterministic rule maps to them.

Use `--format sarif --output .agent-guard/evidence/agent-guard-results.sarif`
when a repository wants to upload findings to GitHub code scanning with
`github/codeql-action/upload-sarif`. Uploading is intentionally left to the
consumer workflow because it changes repository permissions.
SARIF is a thin adapter and not a separate scanner.

`agent-guard` does not detect runtime prompt injection, MCP tool poisoning,
live MCP authorization failures, or agent memory poisoning. It emits static
repository evidence that can help a maintainer decide where those runtime
controls may be needed.

For `report`, it returns:
- exit `0` when the report is generated and all enabled checks pass
- exit `1` when the report is generated and any enabled check finds violations
  or context-lock coverage, digest, workflow, or policy/spec drift
- exit `2` on configuration/runtime error

Event-free output follows `agent-guard.report_evidence.v1`; attaching a reviewed
audit event selects `agent-guard.report_evidence.v2` with a bound v2 manifest.
Both remain sanitized, inside the shared `agent-guard.result.v1` envelope.

#### Packaged JSON schemas

Installed wheels include JSON Schema resources under the `agent_guard.schemas`
package so wrappers and demos can load the evidence contracts without copying
files from the source tree:

- `agent-guard.result.v1.schema.json`: shared scanner result envelope.
- `agent-guard.context_inventory.v1.schema.json`: redacted agent context
  inventory evidence.
- `agent-guard.context_lock_coverage.v1.schema.json`: hash-free context lock
  coverage evidence, including covered context files.
- `agent-guard.report_evidence.v1.schema.json` (event-free) and
  `agent-guard.report_evidence.v2.schema.json` (bound audit event): sanitized
  report evidence, including surface inventory and evidence coverage.
- `agent-guard.conformance.v1.schema.json`: profile evidence for `minimal`,
  `recommended`, and `strict` adoption levels.
- `agent-guard.evidence_pack_manifest.v1.schema.json` (legacy unbound) and
  `agent-guard.evidence_pack_manifest.v2.schema.json` (bound): sanitized manifests.

Installed wheels also include `agent-guard.surface_delta.v1.schema.json` for
sanitized PR base/head agent surface delta evidence.

For `context check`, it returns:
- exit `0` on clean
- exit `1` on violation
- exit `2` on configuration/runtime error

### Surface delta evidence

Surface Delta evidence is available in `0.3.0`.

`agent-guard surface delta --root . --context-policy <policy> --base-ref <ref>`
computes a sanitized diff of surface inventory v2 between the merge base of a
fetched base ref and `HEAD`, including current working-tree changes: which
agent-facing surfaces (context files, skills, MCP servers, workflows, policies,
hooks) were added, removed, or modified. Resolving `git merge-base <ref> HEAD`
prevents base-branch-only additions from appearing as PR removals when the base
branch advances. The base snapshot is built from raw Git tree/blob objects for
the requested repository root; release-archive attributes (`export-ignore` and
`export-subst`) are not applied, and configured clean/process/smudge filters are
not executed. Tree metadata is filtered against the requested root and inventory
patterns, including context `scan.exclude`, before blobs are read, so unrelated
tracked blobs are not materialized. Selected repository-internal symlink targets
and chains are materialized with bounded expansion so target-only changes remain
comparable. Repository-external symlink targets are not followed; external,
`.git`, cyclic, and otherwise unsafe targets fail closed, while context-excluded
alias paths and resolved in-repo target paths are not expanded through
context-selected symlinks. Target values are never published.
Git queries and base materialization run with shared scanner deadlines and
per-file, aggregate-input, selected-file, process-output, and tar-output ceilings;
exceeding any ceiling fails with a fixed sanitized runtime error.
Tracked submodules are opaque boundaries for the parent repository delta:
initialized checkout contents and dirty/untracked submodule files are not
inventoried, while a superproject gitlink pin change is reported only as
`changed_fields: ["content"]` without publishing an object id or submodule
content. Opaque paths are pruned before collector file reads. When no existing
skill/profile/command surface represents the boundary, the delta uses the
controlled `git_submodule` kind. Scan each submodule as its own repository when
its internal surfaces also require review evidence.
`changed_fields` lists metadata field names only, never values, and
the section never emits the base ref name, raw diffs, MCP args/env values, or
instruction/description text. Repeated records retain their count, while
line-number and workflow-step-position-only moves remain unchanged. Content-only
changes to existing file-backed context, policy, workflow, evidence artifact,
skill, profile, command, hook, and MCP configuration surfaces are reported with
`changed_fields: ["content"]`; neither content nor a content fingerprint value
is published. It is
deterministic review evidence, not a gate: exit `0` regardless of whether
entries are present, exit `2` on
configuration/runtime error such as an unfetched base ref. Pass
`--surface-delta-base-ref <ref>` to `agent-guard report` to embed the same
evidence as an optional `surface_delta` section (Markdown heading
`## Surface Delta Evidence`, informational GitHub annotations, never SARIF).

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
or complete shell semantics.
Workflow policies must declare `schema_version:
agent-guard.workflow_policy.v1` and at least one `required_files` or
`workflow_checks` entry; empty policies are configuration errors.

Typical use cases:
- catch CI drift where `context`, `digest`, `path`, or `content` guard commands
  are removed from the release gate
- make policy-file presence explicit before a workflow declares guard coverage
- keep static guard coverage reviewable through deterministic JSON output

Command matching only inspects active `jobs.*.steps[*].run` lines. Its bounded
lexical recognizer tracks supported quoting, substitutions, arrays,
continuations, comments, and here-documents across lines. Blank lines, comments,
`echo` / `printf` documentation lines, and recognized here-document bodies are
not treated as executed guard commands. Unsupported, unterminated, or
over-budget shell/YAML structure fails closed with exit `2`. A command does not
count when its job or step has a recognized literal-false `if`, when job/step
`continue-on-error` is not absent or explicitly false, or when its effective
shell is an explicit custom template instead of `bash`, `sh`, `pwsh`,
`powershell`, or `cmd`.
Other context- or matrix-dependent `if` expressions are not evaluated.

A requirement is satisfied only by a dedicated supported-shell step whose
active shell body reduces to one direct command. The evidence step cannot also
contain setup, another active command, a shell list/control operator, a compound
group, a leading assignment or command wrapper, or a dynamic redirection
target. Static redirections remain supported. Workflow-, job-, or step-level
`PATH`, Python/import, shell-startup, loader, or equivalent resolution-sensitive
environment declarations make the step ineligible. Any job-container
declaration is also ineligible because its image, mounts, environment, and
runtime options can change executable resolution. This includes Python
startup, warning, user-site, and import selectors such as `PYTHONSTARTUP`,
`PYTHONINSPECT`, `PYTHONWARNINGS`, `PYTHON_PRESITE`, `PYTHONUSERBASE`,
`PYTHONNOUSERSITE`, `PYTHONSAFEPATH`, `PYTHONPLATLIBDIR`, `PYTHONCASEOK`, `HOME`,
`USERPROFILE`, and `APPDATA`. An effective `working-directory` declaration is
also ineligible.

The installed `agent-guard` console script remains a supported entrypoint.
When a requirement uses the Python module entrypoint, both the policy and the
workflow must use `python -I -m agent_guard.cli ...`; bare
`python -m agent_guard.cli ...` does not count because a package in the
reviewed checkout can shadow the installed module.

This boundary proves only the checked repository text has that restricted
static shape. It does not prove which host executable a runner resolves, runner
integrity, shell startup behavior, mutations persisted by prior steps (including
`GITHUB_PATH` / `GITHUB_ENV`), or that a context-dependent job or step executes
on every workflow path.
Findings include repository-relative paths, rule ids, workflow ids, requirement ids, reasons, and controlled messages; they do not include raw workflow `run` bodies or raw command text.

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
    - '^https://ntfy\.sh/'
  forbidden_api_patterns:
    - '^https://api\.openai\.com/'
    - '^https://api\.anthropic\.com/'
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
reviewed exceptions, scope the rule in the policy; inline `agent-guard: allow`
text is scanned as ordinary content and cannot suppress a finding.

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

For symlinked context files, `scan.exclude` is evaluated against both the
repository-relative alias path and the resolved in-repo target path.

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

A ready-to-run example policy lives in
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
agent-guard init --root <repo> [--print] [--write] [--skip-existing] [--force] [--json]
agent-guard api check --root <repo> --policy <yaml> [--json]
agent-guard content check --repo-root <repo> --policy <yaml> --mode <registered|preregister|new> [--scan-dir <dir>] [--targets <paths...>] [--since-ref <ref>] [--no-untracked] [--json]
agent-guard context check --root <repo> --policy <yaml> [--json]
agent-guard context inventory --root <repo> --policy <yaml> [--json]
agent-guard context lock --root <repo> --policy <yaml> [--check --digest-policy <yaml>] [--json]
agent-guard mcp check --root <repo> [--policy <yaml>] [--json]
agent-guard surface inventory --root <repo> --context-policy <yaml> [--schema-version <v1|v2>] [--json]
agent-guard report --root <repo> --context-policy <yaml> [--evidence-preset recommended] [--path-policy <yaml>] [--content-policy <yaml>] [--content-scan-dir <dir>] [--api-policy <yaml>] [--mcp-config-check] [--mcp-policy <yaml>] [--digest-policy <yaml>] [--workflow-policy <yaml>] [--drift-check] [--drift-base-ref <ref>] [--agent-policy-audit-event <path> --agent-policy-audit-event-profile <profile>] [--format <markdown|json|github-annotations|sarif>] [--output <path>] [--stderr-summary]
agent-guard render-report --root <repo> --input <agent-guard-report.json> [--format <markdown|json|github-annotations|sarif>] [--output <path>]
agent-guard path check --root <repo> --policy <yaml> [--json]
agent-guard digest check --root <repo> --policy <yaml> [--json]
agent-guard workflow check --root <repo> --policy <yaml> [--json]
agent-guard drift check --root <repo> [--profile <minimal|recommended|strict>] [--schema-version <v1|v2>] [--base-ref <ref>] [--json]
agent-guard surface delta --root <repo> --context-policy <yaml> --base-ref <ref> [--schema-version <v1>] [--json]
agent-guard report --root <repo> --context-policy <yaml> --surface-delta-base-ref <ref> [--format <markdown|json|github-annotations>] [--output <path>]
```

Policy path arguments are resolved relative to the relevant repository root
(`--root` or `--repo-root`) unless an absolute path is provided. Public report
payloads keep in-repository policy paths repo-relative and display external
policy files as `<external-policy>`. In the repo-scoped `content check` modes
(`registered` and `new`), `--scan-dir` must resolve under `--repo-root`;
registered file targets and discovered directory symlinks must also resolve
under that root. Use `preregister` with explicit `--targets` for local review
of candidates outside the repository.

## Releases

Tag-driven. Pushing a `vX.Y.Z` version tag triggers
[`.github/workflows/release.yml`](.github/workflows/release.yml), which first
verifies that the tag matches `[project].version` in `pyproject.toml`, checks
that the version is not already present on PyPI, then builds the sdist + wheel
and publishes to PyPI via Trusted Publishing (OIDC). No maintainer-side PyPI
token is required once the PyPI project environment is configured. Manual
`workflow_dispatch` with `publish=false` is a build-only dry run; it skips the
publish job. Manual `publish=true` must be run against a `v*` tag ref; running
it from a branch fails before build.

The follow-up GitHub Release workflow publishes automatically only after the
upstream PyPI job succeeds, the tag resolves to that run's commit on protected
`master` history, and PyPI exposes exactly the expected non-yanked wheel and
sdist for the version. A manual GitHub Release retry must run from the current
default branch and requires a matching successful tag-push PyPI publication.

After the release build passes its contract checks, a separate least-privilege
job creates GitHub artifact attestations for the generated `dist/*` wheel and
sdist before the publish job runs. PyPI Trusted
Publishing and the PyPA publish action provide PyPI-side distribution
attestations for the uploaded files. These attestations are provenance metadata
and integrity evidence for a specific artifact and workflow identity; they are
not proof of code correctness, dependency safety, maintainer approval, or
absence of secrets.

To verify the GitHub provenance for a downloaded release artifact, install the
GitHub CLI and check the tag, repository, and signer workflow explicitly:

```bash
(
set -euo pipefail
verify_dir="$(mktemp -d "${TMPDIR:-/tmp}/agent-guard-dist-verify.XXXXXX")"
trap 'rm -rf -- "$verify_dir"' EXIT
python - "$verify_dir" <<'PY'
import json
import shutil
import sys
import urllib.request
from pathlib import Path
from urllib.parse import urlparse

version = "0.3.9"
target = Path(sys.argv[1])
request_timeout_seconds = 20
metadata_url = f"https://pypi.org/pypi/yui-agent-guard/{version}/json"
with urllib.request.urlopen(metadata_url, timeout=request_timeout_seconds) as response:
    final_metadata_url = urlparse(response.geturl())
    if final_metadata_url.scheme != "https" or final_metadata_url.hostname != "pypi.org":
        raise SystemExit("PyPI release metadata URL is not an expected HTTPS host")
    release = json.load(response)
if not isinstance(release, dict):
    raise SystemExit("PyPI release metadata is malformed")
expected = {
    f"yui_agent_guard-{version}-py3-none-any.whl": "bdist_wheel",
    f"yui_agent_guard-{version}.tar.gz": "sdist",
}
files = release.get("urls")
if not isinstance(files, list) or len(files) != len(expected):
    raise SystemExit("PyPI release does not contain the exact expected artifact set")
by_name = {}
for file_info in files:
    if not isinstance(file_info, dict):
        raise SystemExit("PyPI release metadata is malformed")
    filename = file_info.get("filename")
    url = file_info.get("url")
    if (
        not isinstance(filename, str)
        or filename not in expected
        or file_info.get("packagetype") != expected[filename]
        or file_info.get("yanked") is not False
        or not isinstance(url, str)
    ):
        raise SystemExit("PyPI release metadata does not match the expected artifact contract")
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.hostname != "files.pythonhosted.org":
        raise SystemExit("PyPI release artifact URL is not an expected HTTPS host")
    if filename in by_name:
        raise SystemExit("PyPI release metadata contains duplicate artifacts")
    by_name[filename] = url
if set(by_name) != set(expected):
    raise SystemExit("PyPI release does not contain the exact expected artifact set")
for filename in sorted(expected):
    with urllib.request.urlopen(
        by_name[filename], timeout=request_timeout_seconds
    ) as response:
        final_artifact_url = urlparse(response.geturl())
        if (
            final_artifact_url.scheme != "https"
            or final_artifact_url.hostname != "files.pythonhosted.org"
        ):
            raise SystemExit("Downloaded artifact URL is not an expected HTTPS host")
        with (target / filename).open("xb") as destination:
            shutil.copyfileobj(response, destination)
PY
gh attestation verify "$verify_dir/yui_agent_guard-0.3.9-py3-none-any.whl" \
  --repo yui-stingray/agent-guard \
  --signer-workflow yui-stingray/agent-guard/.github/workflows/release.yml \
  --source-ref refs/tags/v0.3.9
gh attestation verify "$verify_dir/yui_agent_guard-0.3.9.tar.gz" \
  --repo yui-stingray/agent-guard \
  --signer-workflow yui-stingray/agent-guard/.github/workflows/release.yml \
  --source-ref refs/tags/v0.3.9
)
```

## License

MIT.
