"""Where: src/agent_guard/init_guard.py
What: review-first starter files for adopting agent-guard in an existing repo.
Why: existing repositories need a deterministic, inspectable bootstrap path.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

INIT_PLAN_SCHEMA_VERSION = "agent-guard.init_plan.v1"
PUBLISHED_PACKAGE_VERSION = "0.3.7"
GITHUB_EVENT_BASE_SHA_EXPRESSION = (
    "${{ github.event_name == 'pull_request' && "
    "github.event.pull_request.base.sha || github.event.before }}"
)
PUBLISHED_CONTEXT_POLICY_PREFLIGHT = r'''set -euo pipefail

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
fi'''


CONTEXT_POLICY = """# Where: .agent-guard/context-policy.yaml
# What: agent context file scan policy for agent-guard.
# Why: keep durable agent instructions within explicit safety boundaries.

scan:
  include:
    - AGENTS.md
    - "**/AGENTS.md"
    - CLAUDE.md
    - "**/CLAUDE.md"
    - GEMINI.md
    - "**/GEMINI.md"
    - .github/copilot-instructions.md
    - .github/instructions/**/*.instructions.md
    - .cursor/rules
    - .cursor/rules/**/*.md
    - .cursorrules
    - .windsurfrules
    - .windsurf/rules/**/*.md
    - .continue/rules/**/*.md
  exclude:
    - .git/**
    - .venv/**
    - node_modules/**
    - dist/**
    - build/**
"""


PATH_POLICY = """# Where: .agent-guard/path-policy.yaml
# What: path-name guard policy for local and private artifacts.
# Why: block common publish-time leaks before file content is read.

scan:
  include:
    - .
  exclude:
    - .git
    - .venv
    - node_modules
    - dist
    - build

policy:
  allowed_path_patterns:
    - "(^|/)\\\\.env\\\\.example$"
  forbidden_path_patterns:
    - id: env_file
      severity: high
      pattern: "(^|/)\\\\.env(\\\\..+)?$"
      message: "env files are forbidden except .env.example"
    - id: private_artifacts
      severity: high
      pattern: "(^|/)artifacts/private(/|$)"
      message: "private artifacts must stay outside tracked paths"
    - id: local_artifacts
      severity: high
      pattern: "(^|/)artifacts/local(/|$)"
      message: "local-only artifacts must stay outside tracked paths"
"""


CONTENT_POLICY = """# Where: .agent-guard/content-policy.yaml
# What: small static content guard for dangerous agent-facing instructions.
# Why: catch unsafe instruction drift in tracked text before review.

file_globs:
  - "**/*.md"
  - "**/*.yaml"
  - "**/*.yml"
  - "**/*.sh"
exclude_globs:
  - .git/**
  - .venv/**
  - node_modules/**
  - dist/**
  - build/**
  - .agent-guard/content-policy.yaml
forbidden_patterns:
  - id: pipe_to_shell
    severity: high
    pattern: '(?i)curl\\s+[^\\n|]+\\|\\s*(bash|sh)\\b'
    message: "pipe-to-shell pattern is forbidden"
  - id: secret_prompt
    severity: high
    pattern: '(?i)((provide|paste|enter).*(api[_ -]?key|token|password|secret))'
    message: "plaintext secret prompt is forbidden"
  - id: force_history_rewrite
    severity: high
    pattern: '(?i)git\\s+(reset\\s+--hard|push\\s+--force\\b|clean\\s+-f)'
    message: "destructive git command pattern is forbidden"
"""


MCP_POLICY = """# Where: .agent-guard/mcp-policy.yaml
# What: static MCP configuration policy for agent-guard.
# Why: make MCP risk-label enforcement reviewable without executing MCP servers.

schema_version: agent-guard.mcp_policy.v1

policy:
  fail_on_parse_error: true
  forbidden_risky_patterns:
    - broad_authorization_scope
    - filesystem_root_reference
    - inline_authorization_value
    - inline_env_value
    - instruction_like_description
    - latest_package
    - secret_shaped_inline_value
    - unsafe_url_scheme
    - unpinned_package
"""


WORKFLOW_POLICY = """# Where: .agent-guard/workflow-policy.yaml
# What: starter workflow drift policy for agent-guard evidence.
# Why: verify that the reviewable guard files and evidence workflow exist.

schema_version: agent-guard.workflow_policy.v1

required_files:
  - id: context_policy
    path: .agent-guard/context-policy.yaml
  - id: path_policy
    path: .agent-guard/path-policy.yaml
  - id: content_policy
    path: .agent-guard/content-policy.yaml
  - id: mcp_policy
    path: .agent-guard/mcp-policy.yaml
  - id: workflow_policy
    path: .agent-guard/workflow-policy.yaml
  - id: agent_guard_workflow
    path: .github/workflows/agent-guard.yml

workflow_checks:
  - id: agent_guard_evidence
    path: .github/workflows/agent-guard.yml
    required_commands:
      - id: context_guard
        command: agent-guard context check --root . --policy .agent-guard/context-policy.yaml
      - id: path_guard
        command: agent-guard path check --root . --policy .agent-guard/path-policy.yaml
      - id: content_guard
        command: agent-guard content check --repo-root . --policy .agent-guard/content-policy.yaml
      - id: mcp_config_guard
        command: agent-guard mcp check --root . --policy .agent-guard/mcp-policy.yaml
      - id: surface_inventory
        command: agent-guard surface inventory --root . --context-policy .agent-guard/context-policy.yaml --schema-version v2
      - id: workflow_guard
        command: agent-guard workflow check --root . --policy .agent-guard/workflow-policy.yaml
      - id: drift_guard
        command: ( agent-guard drift check --root . --profile recommended --schema-version v2 --base-ref "${{ github.event_name == 'pull_request' && github.event.pull_request.base.sha || github.event.before }}" --json 2>/dev/null > "$raw_dir/drift.json" )
      - id: evidence_report_with_drift
        command: ( agent-guard report --root . --context-policy .agent-guard/context-policy.yaml --evidence-preset recommended --mcp-policy .agent-guard/mcp-policy.yaml --drift-base-ref "${{ github.event_name == 'pull_request' && github.event.pull_request.base.sha || github.event.before }}" --format json --output "$report_json" > /dev/null 2>&1 )
      - id: conformance_check
        command: agent-guard conformance check --root . --evidence "$report_json" --profile recommended
      - id: evidence_pack_manifest
        command: agent-guard evidence-pack manifest --root . --report "$report_json"
"""


GITHUB_WORKFLOW = """# Where: .github/workflows/agent-guard.yml
# What: starter agent-guard evidence workflow.
# Why: upload deterministic static evidence for maintainer review.

name: agent-guard

on:
  pull_request:
  push:
    branches: [main, master]

permissions:
  contents: read

jobs:
  evidence:
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
__PUBLISHED_CONTEXT_POLICY_PREFLIGHT__
      - uses: actions/setup-python@ece7cb06caefa5fff74198d8649806c4678c61a1 # v6
        with:
          python-version: "3.12"
      - name: Install agent-guard
        run: python -I -m pip install yui-agent-guard==__PUBLISHED_AGENT_GUARD_VERSION__
      - id: generate-evidence
        name: Generate evidence
        timeout-minutes: 1
        env:
          AGENT_GUARD_EVENT_NAME: ${{ github.event_name }}
        run: |
          set +e
          status=0
          record_status() {
            code="$1"
            if [ "$code" -ge 2 ] || { [ "$code" -ne 0 ] && [ "$status" -eq 0 ]; }; then
              status="$code"
            fi
          }
          base_sha="${{ github.event_name == 'pull_request' && github.event.pull_request.base.sha || github.event.before }}"
          baseline_label=""
          case "${AGENT_GUARD_EVENT_NAME:-}" in
            pull_request)
              baseline_label="pull request base"
              ;;
            push)
              baseline_label="push before"
              ;;
            *)
              echo "::error::workflow event type is unsupported"
              exit 2
              ;;
          esac
          if [ -z "$base_sha" ]; then
            echo "::error::${baseline_label} SHA is unavailable"
            exit 2
          fi
          case "$base_sha" in
            *[!0-9a-f]*)
              echo "::error::${baseline_label} SHA is invalid"
              exit 2
              ;;
          esac
          if [ "${#base_sha}" -ne 40 ] && [ "${#base_sha}" -ne 64 ]; then
            echo "::error::${baseline_label} SHA is invalid"
            exit 2
          fi
          runner_temp="${RUNNER_TEMP:-/tmp}"
          if ! mkdir -p "$runner_temp" 2>/dev/null; then
            echo "::error::evidence staging setup failed"
            exit 2
          fi
          if ! raw_dir="$(mktemp -d "$runner_temp/agent-guard-raw.XXXXXX" 2>/dev/null)"; then
            echo "::error::evidence staging setup failed"
            exit 2
          fi
          if ! evidence_dir="$(mktemp -d "$runner_temp/agent-guard-evidence.XXXXXX" 2>/dev/null)"; then
            rm -rf "$raw_dir" 2>/dev/null || true
            echo "::error::evidence staging setup failed"
            exit 2
          fi
          evidence_ready=false
          cleanup() {
            rm -rf "$raw_dir" 2>/dev/null || true
            if [ "$evidence_ready" != "true" ]; then
              rm -rf "$evidence_dir" 2>/dev/null || true
            fi
          }
          trap cleanup EXIT
          report_json="${evidence_dir%/}/agent-guard-report.json"
          report_markdown="${evidence_dir%/}/agent-guard-report.md"
          report_sarif="${evidence_dir%/}/agent-guard-results.sarif"
          conformance_json="${evidence_dir%/}/agent-guard-conformance.json"
          evidence_pack_json="${evidence_dir%/}/agent-guard-evidence-pack.json"
          surface_inventory_json="${evidence_dir%/}/agent-surface-inventory.json"
          public_artifact_names=(
            agent-guard-report.json
            agent-guard-report.md
            agent-guard-results.sarif
            agent-guard-conformance.json
            agent-guard-evidence-pack.json
            agent-surface-inventory.json
          )
          validate_raw_result() {
            code="$1"
            output_path="$2"
            if [ ! -f "$output_path" ] || [ -L "$output_path" ]; then
              return 2
            fi
            return "$code"
          }
          agent-guard context check --root . --policy .agent-guard/context-policy.yaml --json 2>/dev/null > "$raw_dir/context.json"
          validate_raw_result "$?" "$raw_dir/context.json"
          record_status "$?"
          agent-guard path check --root . --policy .agent-guard/path-policy.yaml --json 2>/dev/null > "$raw_dir/path.json"
          validate_raw_result "$?" "$raw_dir/path.json"
          record_status "$?"
          agent-guard content check --repo-root . --policy .agent-guard/content-policy.yaml --mode registered --scan-dir . --json 2>/dev/null > "$raw_dir/content.json"
          validate_raw_result "$?" "$raw_dir/content.json"
          record_status "$?"
          agent-guard mcp check --root . --policy .agent-guard/mcp-policy.yaml --json 2>/dev/null > "$raw_dir/mcp.json"
          validate_raw_result "$?" "$raw_dir/mcp.json"
          record_status "$?"
          agent-guard workflow check --root . --policy .agent-guard/workflow-policy.yaml --json 2>/dev/null > "$raw_dir/workflow.json"
          validate_raw_result "$?" "$raw_dir/workflow.json"
          record_status "$?"
          ( agent-guard drift check --root . --profile recommended --schema-version v2 --base-ref "${{ github.event_name == 'pull_request' && github.event.pull_request.base.sha || github.event.before }}" --json 2>/dev/null > "$raw_dir/drift.json" )
          validate_raw_result "$?" "$raw_dir/drift.json"
          record_status "$?"
          ( agent-guard report --root . --context-policy .agent-guard/context-policy.yaml --evidence-preset recommended --mcp-policy .agent-guard/mcp-policy.yaml --drift-base-ref "${{ github.event_name == 'pull_request' && github.event.pull_request.base.sha || github.event.before }}" --format json --output "$report_json" > /dev/null 2>&1 )
          record_status "$?"
          agent-guard surface inventory --root . --context-policy .agent-guard/context-policy.yaml --schema-version v2 --json 2>/dev/null > "$surface_inventory_json"
          validate_raw_result "$?" "$surface_inventory_json"
          record_status "$?"
          agent-guard render-report --root . --input "$report_json" --format markdown --output "$report_markdown" > /dev/null 2>&1
          record_status "$?"
          agent-guard render-report --root . --input "$report_json" --format sarif --output "$report_sarif" > /dev/null 2>&1
          record_status "$?"
          agent-guard conformance check --root . --evidence "$report_json" --profile recommended --json 2>/dev/null > "$conformance_json"
          validate_raw_result "$?" "$conformance_json"
          record_status "$?"
          agent-guard evidence-pack manifest --root . --report "$report_json" --artifact "$report_json" --json 2>/dev/null > "$evidence_pack_json"
          validate_raw_result "$?" "$evidence_pack_json"
          record_status "$?"
          if [ "$status" -ge 2 ]; then
            echo "::error::evidence generation failed"
            exit 2
          fi
          validate_public_evidence() (
            if [ ! -d "$evidence_dir" ] || [ -L "$evidence_dir" ]; then
              return 1
            fi
            shopt -s nullglob dotglob
            evidence_entries=("$evidence_dir"/*)
            if [ "${#evidence_entries[@]}" -ne "${#public_artifact_names[@]}" ]; then
              return 1
            fi
            for artifact_name in "${public_artifact_names[@]}"; do
              artifact_path="${evidence_dir%/}/$artifact_name"
              if [ ! -f "$artifact_path" ] || [ -L "$artifact_path" ]; then
                return 1
              fi
            done
          )
          if ! validate_public_evidence; then
            echo "::error::evidence validation failed"
            exit 2
          fi
          agent-guard render-report --root . --input "$report_json" --format github-annotations 2>/dev/null > "$raw_dir/annotations.txt"
          validate_raw_result "$?" "$raw_dir/annotations.txt"
          record_status "$?"
          if [ "$status" -ge 2 ]; then
            echo "::error::evidence generation failed"
            exit 2
          fi
          annotations_path="${evidence_dir%/}/agent-guard-annotations.txt"
          if ! mv "${raw_dir%/}/annotations.txt" "$annotations_path" 2>/dev/null; then
            echo "::error::evidence validation failed"
            exit 2
          fi
          if [ ! -f "$annotations_path" ] || [ -L "$annotations_path" ]; then
            echo "::error::evidence validation failed"
            exit 2
          fi
          if ! python -I -m agent_guard.consumer --evidence-dir "$evidence_dir" --emit-annotations "$report_json" 2>/dev/null; then
            echo "::error::evidence validation failed"
            exit 2
          fi
          if ! rm -f "$annotations_path" 2>/dev/null; then
            echo "::error::evidence validation failed"
            exit 2
          fi
          if ! validate_public_evidence; then
            echo "::error::evidence validation failed"
            exit 2
          fi
          write_evidence_dir_output() {
            printf 'evidence-dir=%s\\n' "$evidence_dir" >> "$GITHUB_OUTPUT"
          }
          if ! write_evidence_dir_output 2>/dev/null; then
            echo "::error::evidence output setup failed"
            exit 2
          fi
          evidence_ready=true
          write_ready_output() {
            printf 'ready=true\\n' >> "$GITHUB_OUTPUT"
          }
          if ! write_ready_output 2>/dev/null; then
            echo "::error::evidence output setup failed"
            exit 2
          fi
          exit "$status"
      - name: Upload evidence
        if: always() && steps.generate-evidence.outputs.ready == 'true'
        uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1
        with:
          name: agent-guard-evidence
          path: |
            ${{ steps.generate-evidence.outputs.evidence-dir }}/agent-guard-report.json
            ${{ steps.generate-evidence.outputs.evidence-dir }}/agent-guard-report.md
            ${{ steps.generate-evidence.outputs.evidence-dir }}/agent-guard-results.sarif
            ${{ steps.generate-evidence.outputs.evidence-dir }}/agent-guard-conformance.json
            ${{ steps.generate-evidence.outputs.evidence-dir }}/agent-guard-evidence-pack.json
            ${{ steps.generate-evidence.outputs.evidence-dir }}/agent-surface-inventory.json
          if-no-files-found: error
""".replace(
    "__PUBLISHED_CONTEXT_POLICY_PREFLIGHT__",
    "\n".join(
        f"          {line}" if line else ""
        for line in PUBLISHED_CONTEXT_POLICY_PREFLIGHT.splitlines()
    ),
).replace("__PUBLISHED_AGENT_GUARD_VERSION__", PUBLISHED_PACKAGE_VERSION)


PREVIEW_NEXT_STEPS = [
    "Review every planned file before writing it to the repository.",
    (
        "From the repository root, run `agent-guard init --root . --write` only "
        "after the printed plan is acceptable."
    ),
    "Document the guard commands in README.md before expecting `agent-guard drift check` to pass cleanly.",
    "After context files are reviewed, run `agent-guard context lock --root . --policy .agent-guard/context-policy.yaml > .agent-guard/context-digest-policy.yaml` if digest pinning is required.",
    "Treat raw per-scanner JSON as local or CI-internal; publish only the sanitized report, render-report, or evidence-pack outputs after review.",
    "Do not treat MCP evidence as runtime MCP validation, live OAuth validation, or MCP tool-poisoning detection.",
    "Commit generated evidence only when it is deliberately sanitized sample data; otherwise upload it as a CI artifact.",
]


WRITE_NEXT_STEPS = [
    "Review every written and preserved starter file before relying on the bundle.",
    (
        "Run `agent-guard report --root . --context-policy "
        ".agent-guard/context-policy.yaml --evidence-preset recommended --mcp-policy "
        ".agent-guard/mcp-policy.yaml --stderr-summary --format json --output "
        ".agent-guard/evidence/agent-guard-report.json` and review the sanitized "
        "report before publication."
    ),
    (
        "Run `agent-guard conformance check --root . --evidence "
        ".agent-guard/evidence/agent-guard-report.json --profile recommended --json` "
        "and review the result before treating the bundle as ready."
    ),
    (
        "Treat exit code 1 as policy findings that require review; treat exit code "
        ">=2 as an execution/configuration error that must be fixed before relying "
        "on evidence."
    ),
    (
        "Treat raw per-scanner JSON as local or CI-internal; publish only the "
        "sanitized report, render-report, or evidence-pack outputs after review."
    ),
    (
        "Do not treat MCP evidence as runtime MCP validation, live OAuth validation, "
        "or MCP tool-poisoning detection."
    ),
]


BLOCKED_WRITE_NEXT_STEPS = [
    "Review the existing starter files in the repository before deciding how to continue.",
    (
        "From the repository root, run `agent-guard init --root . --write "
        "--skip-existing` so only missing starter files are created."
    ),
    (
        "Use `agent-guard init --root . --write --force` only after intentionally "
        "reviewing which existing starter files will be overwritten."
    ),
    (
        "After any preserved or overwritten files are reviewed, run the recommended "
        "report and conformance checks before treating the bundle as ready."
    ),
]


@dataclass(frozen=True)
class InitFile:
    path: str
    content: str


INIT_FILES = (
    InitFile(".agent-guard/context-policy.yaml", CONTEXT_POLICY),
    InitFile(".agent-guard/path-policy.yaml", PATH_POLICY),
    InitFile(".agent-guard/content-policy.yaml", CONTENT_POLICY),
    InitFile(".agent-guard/mcp-policy.yaml", MCP_POLICY),
    InitFile(".agent-guard/workflow-policy.yaml", WORKFLOW_POLICY),
    InitFile(".github/workflows/agent-guard.yml", GITHUB_WORKFLOW),
)


def resolve_init_path(root: Path, rel_path: str) -> Path:
    target = (root / rel_path).resolve()
    try:
        target.relative_to(root.resolve())
    except ValueError as exc:
        raise ValueError(f"init file escapes root: {rel_path}") from exc
    return target


def build_init_plan(*, root: Path, force: bool = False) -> dict[str, object]:
    root = root.resolve()
    files: list[dict[str, object]] = []
    for item in INIT_FILES:
        target = resolve_init_path(root, item.path)
        exists = target.exists()
        files.append(
            {
                "path": item.path,
                "status": "overwrite" if exists and force else "exists" if exists else "create",
                "content": item.content,
            }
        )

    return {
        "schema_version": INIT_PLAN_SCHEMA_VERSION,
        "mode": "print",
        "file_count": len(files),
        "files": files,
        "next_steps": PREVIEW_NEXT_STEPS,
    }


def write_init_plan(
    *,
    root: Path,
    force: bool = False,
    skip_existing: bool = False,
) -> tuple[dict[str, object], int]:
    plan = build_init_plan(root=root, force=force)
    files = plan["files"]
    assert isinstance(files, list)
    blocked = [item for item in files if isinstance(item, dict) and item.get("status") == "exists"]
    if blocked and not skip_existing:
        return {
            **plan,
            "mode": "write",
            "status": "blocked",
            "next_steps": BLOCKED_WRITE_NEXT_STEPS,
        }, 1

    results: list[dict[str, object]] = []
    for item in INIT_FILES:
        target = resolve_init_path(root.resolve(), item.path)
        if skip_existing and target.exists():
            results.append({"path": item.path, "status": "skipped_existing"})
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(item.content, encoding="utf-8")
        results.append({"path": item.path, "status": "written"})

    written_count = sum(1 for item in results if item["status"] == "written")
    skipped_count = sum(1 for item in results if item["status"] == "skipped_existing")
    write_plan: dict[str, object] = {
        "schema_version": INIT_PLAN_SCHEMA_VERSION,
        "mode": "write",
        "status": "ok",
        "file_count": len(results),
        "written_count": written_count,
        "skipped_count": skipped_count,
        "files": results,
        "next_steps": WRITE_NEXT_STEPS,
    }
    if skipped_count:
        write_plan["bundle_state"] = "mixed_unverified"
    return write_plan, 0


def render_init_plan_text(plan: dict[str, object], *, include_content: bool) -> str:
    lines = [
        "# agent-guard init",
        "",
        f"Schema: {plan.get('schema_version')}",
        f"Mode: {plan.get('mode')}",
        f"Status: {plan.get('status', 'planned')}",
    ]
    if "bundle_state" in plan:
        lines.append(f"Bundle state: {plan['bundle_state']}")
    if "written_count" in plan:
        lines.append(f"Written: {plan['written_count']}")
    if "skipped_count" in plan:
        lines.append(f"Skipped existing: {plan['skipped_count']}")
    lines.append("")
    files = plan.get("files", [])
    if isinstance(files, list):
        for item in files:
            if not isinstance(item, dict):
                continue
            lines.append(f"## {item.get('path')} ({item.get('status')})")
            if include_content:
                lines.extend(["", "```", str(item.get("content", "")).rstrip(), "```"])
            lines.append("")
    next_steps = plan.get("next_steps", [])
    if isinstance(next_steps, list):
        lines.extend(["## Next steps", ""])
        for step in next_steps:
            lines.append(f"- {step}")
    return "\n".join(lines).rstrip() + "\n"
