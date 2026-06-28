"""Where: src/agent_guard/init_guard.py
What: review-first starter files for adopting agent-guard in an existing repo.
Why: existing repositories need a deterministic, inspectable bootstrap path.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


INIT_PLAN_SCHEMA_VERSION = "agent-guard.init_plan.v1"


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
      - id: surface_inventory
        command: agent-guard surface inventory --root . --context-policy .agent-guard/context-policy.yaml --schema-version v2
      - id: workflow_guard
        command: agent-guard workflow check --root . --policy .agent-guard/workflow-policy.yaml
      - id: drift_guard
        command: agent-guard drift check --root . --profile recommended --schema-version v2
      - id: evidence_report_with_drift
        command: agent-guard report --root . --context-policy .agent-guard/context-policy.yaml --evidence-preset recommended
      - id: conformance_check
        command: agent-guard conformance check --root . --evidence .agent-guard/evidence/agent-guard-report.json --profile recommended
      - id: evidence_pack_manifest
        command: agent-guard evidence-pack manifest --root . --report .agent-guard/evidence/agent-guard-report.json
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
      - uses: actions/checkout@v6
      - uses: actions/setup-python@v6
        with:
          python-version: "3.12"
      - name: Install agent-guard
        run: python -m pip install yui-agent-guard
      - name: Generate evidence
        run: |
          set +e
          status=0
          mkdir -p .agent-guard/evidence
          agent-guard context check --root . --policy .agent-guard/context-policy.yaml --json
          code=$?
          if [ "$code" -ne 0 ]; then status=$code; fi
          agent-guard path check --root . --policy .agent-guard/path-policy.yaml --json
          code=$?
          if [ "$code" -ne 0 ]; then status=$code; fi
          agent-guard content check --repo-root . --policy .agent-guard/content-policy.yaml --mode registered --scan-dir . --json
          code=$?
          if [ "$code" -ne 0 ]; then status=$code; fi
          agent-guard surface inventory --root . --context-policy .agent-guard/context-policy.yaml --schema-version v2 --json > .agent-guard/evidence/agent-surface-inventory.json
          code=$?
          if [ "$code" -ne 0 ]; then status=$code; fi
          agent-guard workflow check --root . --policy .agent-guard/workflow-policy.yaml --json
          code=$?
          if [ "$code" -ne 0 ]; then status=$code; fi
          agent-guard drift check --root . --profile recommended --schema-version v2 --json
          code=$?
          if [ "$code" -ne 0 ]; then status=$code; fi
          agent-guard report --root . --context-policy .agent-guard/context-policy.yaml --evidence-preset recommended --format markdown --output .agent-guard/evidence/agent-guard-report.md
          code=$?
          if [ "$code" -ne 0 ]; then status=$code; fi
          agent-guard report --root . --context-policy .agent-guard/context-policy.yaml --evidence-preset recommended --format json --output .agent-guard/evidence/agent-guard-report.json
          code=$?
          if [ "$code" -ne 0 ]; then status=$code; fi
          agent-guard conformance check --root . --evidence .agent-guard/evidence/agent-guard-report.json --profile recommended --json
          code=$?
          if [ "$code" -ne 0 ]; then status=$code; fi
          agent-guard evidence-pack manifest --root . --report .agent-guard/evidence/agent-guard-report.json --artifact .agent-guard/evidence/agent-guard-report.json --json
          code=$?
          if [ "$code" -ne 0 ]; then status=$code; fi
          agent-guard report --root . --context-policy .agent-guard/context-policy.yaml --evidence-preset recommended --format github-annotations
          code=$?
          if [ "$code" -ne 0 ]; then status=$code; fi
          exit "$status"
      - name: Upload evidence
        if: always()
        uses: actions/upload-artifact@v7
        with:
          name: agent-guard-evidence
          path: .agent-guard/evidence/
          if-no-files-found: error
"""


NEXT_STEPS = [
    "Review every planned file before writing it to the repository.",
    "Run `agent-guard init --write` only after the printed plan is acceptable.",
    "Document the guard commands in README.md before expecting `agent-guard drift check` to pass cleanly.",
    "After context files are reviewed, run `agent-guard context lock --root . --policy .agent-guard/context-policy.yaml > .agent-guard/context-digest-policy.yaml` if digest pinning is required.",
    "Commit generated evidence only when it is deliberately sanitized sample data; otherwise upload it as a CI artifact.",
]


@dataclass(frozen=True)
class InitFile:
    path: str
    content: str


INIT_FILES = (
    InitFile(".agent-guard/context-policy.yaml", CONTEXT_POLICY),
    InitFile(".agent-guard/path-policy.yaml", PATH_POLICY),
    InitFile(".agent-guard/content-policy.yaml", CONTENT_POLICY),
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
        "next_steps": NEXT_STEPS,
    }


def write_init_plan(*, root: Path, force: bool = False) -> tuple[dict[str, object], int]:
    plan = build_init_plan(root=root, force=force)
    files = plan["files"]
    assert isinstance(files, list)
    blocked = [item for item in files if isinstance(item, dict) and item.get("status") == "exists"]
    if blocked:
        return {**plan, "mode": "write", "status": "blocked"}, 1

    written: list[dict[str, object]] = []
    for item in INIT_FILES:
        target = resolve_init_path(root.resolve(), item.path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(item.content, encoding="utf-8")
        written.append({"path": item.path, "status": "written"})
    return {
        "schema_version": INIT_PLAN_SCHEMA_VERSION,
        "mode": "write",
        "status": "ok",
        "file_count": len(written),
        "files": written,
        "next_steps": NEXT_STEPS,
    }, 0


def render_init_plan_text(plan: dict[str, object], *, include_content: bool) -> str:
    lines = [
        "# agent-guard init",
        "",
        f"Schema: {plan.get('schema_version')}",
        f"Mode: {plan.get('mode')}",
        f"Status: {plan.get('status', 'planned')}",
        "",
    ]
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
