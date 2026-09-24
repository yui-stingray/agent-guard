# CI reference

Adoption details, CI gate recipes, and packaged pre-commit hooks for
`agent-guard`. Start with the reviewed bootstrap in the
[README](../README.md#start-with-a-reviewed-bootstrap) before using these recipes.

## Adoption and CI reference

The reviewed bootstrap in the README is the canonical adoption path. Start by
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
        uses: yui-stingray/agent-guard@1b2bdec263f84b97313f45106405a38765d72019 # v0.3.10
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
`v0.3.10` Action and keep the one-minute step limit, which is GitHub Actions'
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
  "tool": {"name": "agent-guard", "version": "0.3.10"},
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
    rev: v0.3.10
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
