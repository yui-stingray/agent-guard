# Where: tests/cli/test_report_integrations.py
# What: subprocess tests for report evidence integrations with other guards.
# Why: keep digest, workflow, path, content, and API report coverage focused.

from __future__ import annotations

from pathlib import Path

import pytest

from agent_guard.bounded_repo_reader import DistinctInputBudget
from agent_guard.cli import build_parser
import agent_guard.cli.report as report_cli
from agent_guard.digest_guard import MAX_DIGEST_DISTINCT_INPUT_BYTES
from tests.cli.helpers import run_cli, sha256_text, write


def test_report_uses_separate_context_read_pass_and_digest_budget(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    context_policy = tmp_path / "context_policy.yaml"
    context_policy.write_text("{}\n", encoding="utf-8")
    agent_context = "Use project tests before reporting success.\n"
    write(tmp_path / "AGENTS.md", agent_context)
    digest_policy = tmp_path / "digest_policy.yaml"
    digest_policy.write_text(
        "checks:\n"
        "  - id: agent_context_pin\n"
        "    path: AGENTS.md\n"
        f"    sha256: '{sha256_text(agent_context)}'\n",
        encoding="utf-8",
    )
    observed: dict[str, object] = {}
    original_load_context_policy = report_cli.load_context_policy
    original_load_digest_policy = report_cli.load_digest_policy
    original_build_context_lock_report = report_cli.build_context_lock_report
    original_scan_digests = report_cli.scan_digests

    def tracked_load_context_policy(*args: object, **kwargs: object) -> object:
        observed["context_policy"] = kwargs.get("_input_budget")
        return original_load_context_policy(*args, **kwargs)

    def tracked_load_digest_policy(*args: object, **kwargs: object) -> object:
        observed["digest_policy"] = kwargs.get("_input_budget")
        return original_load_digest_policy(*args, **kwargs)

    def tracked_build_context_lock_report(**kwargs: object) -> object:
        observed["context_lock"] = kwargs.get("_input_budget")
        return original_build_context_lock_report(**kwargs)

    def tracked_scan_digests(**kwargs: object) -> object:
        observed["digest_scan"] = kwargs.get("_input_budget")
        return original_scan_digests(**kwargs)

    monkeypatch.setattr(report_cli, "load_context_policy", tracked_load_context_policy)
    monkeypatch.setattr(report_cli, "load_digest_policy", tracked_load_digest_policy)
    monkeypatch.setattr(
        report_cli,
        "build_context_lock_report",
        tracked_build_context_lock_report,
    )
    monkeypatch.setattr(report_cli, "scan_digests", tracked_scan_digests)
    args = build_parser().parse_args(
        [
            "report",
            "--root",
            str(tmp_path),
            "--context-policy",
            str(context_policy),
            "--digest-policy",
            str(digest_policy),
            "--format",
            "json",
        ]
    )

    assert report_cli.run_report(args) == 0
    captured = capsys.readouterr()
    assert captured.err == ""
    context_budget = observed["context_policy"]
    context_lock_budget = observed["context_lock"]
    digest_budget = observed["digest_policy"]
    assert isinstance(context_budget, DistinctInputBudget)
    assert isinstance(context_lock_budget, DistinctInputBudget)
    assert context_lock_budget is not context_budget
    context_used_bytes = context_budget.used_bytes
    context_lock_budget.charge_bytes(b"x", identity="shared-pass-probe")
    assert context_budget.used_bytes == context_used_bytes + 1
    assert observed["digest_scan"] is digest_budget
    assert digest_budget is not context_budget
    assert getattr(digest_budget, "max_bytes") == MAX_DIGEST_DISTINCT_INPUT_BYTES


def test_report_cli_markdown_digest_policy_ok(tmp_path: Path) -> None:
    context_policy = tmp_path / "context_policy.yaml"
    context_policy.write_text("{}\n", encoding="utf-8")
    agent_context = "Use project tests before reporting success.\n"
    write(tmp_path / "AGENTS.md", agent_context)
    digest_policy = tmp_path / "digest_policy.yaml"
    digest_policy.write_text(
        "checks:\n"
        "  - id: agent_context_pin\n"
        "    path: AGENTS.md\n"
        f"    sha256: '{sha256_text(agent_context)}'\n",
        encoding="utf-8",
    )

    result = run_cli(
        "report",
        "--root",
        str(tmp_path),
        "--context-policy",
        str(context_policy),
        "--digest-policy",
        str(digest_policy),
    )

    assert result.returncode == 0
    assert "| Scope | context+digest |" in result.stdout
    assert "| Status | ok |" in result.stdout
    assert "| Evidence contract | agent-guard.report_evidence.v1 |" in result.stdout
    assert "| Digest policy | digest_policy.yaml |" in result.stdout
    assert "| Context lock checked | 1 |" in result.stdout
    assert "| Context lock covered | 1 |" in result.stdout
    assert "| Context lock coverage findings | 0 |" in result.stdout
    assert "Covered context files:" in result.stdout
    assert "| AGENTS.md | agents_md | covered | agent_context_pin |" in result.stdout
    assert "| Digest checks | 1 |" in result.stdout
    assert "| Digest drift findings | 0 |" in result.stdout
    assert "## Context Lock Coverage Evidence" in result.stdout
    assert "All discovered agent context files are fully pinned by the digest policy." in result.stdout
    assert "## Digest Drift Evidence" in result.stdout
    assert "No digest drift was detected." in result.stdout
    assert sha256_text(agent_context) not in result.stdout
    assert str(tmp_path) not in result.stdout

def test_report_cli_markdown_context_lock_missing_coverage_is_sanitized(tmp_path: Path) -> None:
    context_policy = tmp_path / "context_policy.yaml"
    context_policy.write_text("{}\n", encoding="utf-8")
    agent_context = "Use project tests before reporting success.\n"
    claude_context = "Run tests before reporting completion.\n"
    write(tmp_path / "AGENTS.md", agent_context)
    write(tmp_path / "CLAUDE.md", claude_context)
    digest_policy = tmp_path / "digest_policy.yaml"
    digest_policy.write_text(
        "checks:\n"
        "  - id: agent_context_pin\n"
        "    path: AGENTS.md\n"
        f"    sha256: '{sha256_text(agent_context)}'\n",
        encoding="utf-8",
    )

    result = run_cli(
        "report",
        "--root",
        str(tmp_path),
        "--context-policy",
        str(context_policy),
        "--digest-policy",
        str(digest_policy),
    )

    assert result.returncode == 1
    assert "| Status | violation |" in result.stdout
    assert "| Context lock checked | 2 |" in result.stdout
    assert "| Context lock covered | 1 |" in result.stdout
    assert "| Context lock coverage findings | 1 |" in result.stdout
    assert (
        "| high | context_lock_missing | ASI04 Agentic Supply Chain Vulnerabilities; "
        "ASI06 Memory &amp; Context Poisoning | CLAUDE.md | missing | - |"
        in result.stdout
    )
    assert sha256_text(agent_context) not in result.stdout
    assert agent_context.strip() not in result.stdout
    assert claude_context.strip() not in result.stdout
    assert str(tmp_path) not in result.stdout

def test_report_cli_github_annotations_context_lock_missing_coverage(tmp_path: Path) -> None:
    context_policy = tmp_path / "context_policy.yaml"
    context_policy.write_text("{}\n", encoding="utf-8")
    agent_context = "Use project tests before reporting success.\n"
    claude_context = "Run tests before reporting completion.\n"
    write(tmp_path / "AGENTS.md", agent_context)
    write(tmp_path / "CLAUDE.md", claude_context)
    digest_policy = tmp_path / "digest_policy.yaml"
    digest_policy.write_text(
        "checks:\n"
        "  - id: agent_context_pin\n"
        "    path: AGENTS.md\n"
        f"    sha256: '{sha256_text(agent_context)}'\n",
        encoding="utf-8",
    )

    result = run_cli(
        "report",
        "--root",
        str(tmp_path),
        "--context-policy",
        str(context_policy),
        "--digest-policy",
        str(digest_policy),
        "--format",
        "github-annotations",
    )

    assert result.returncode == 1
    assert result.stdout == (
        "::error file=CLAUDE.md,title=agent-guard context lock%3A context_lock_missing"
        "::context lock coverage: missing (OWASP risk themes: "
        "ASI04 Agentic Supply Chain Vulnerabilities; ASI06 Memory & Context Poisoning)\n"
    )
    assert sha256_text(agent_context) not in result.stdout
    assert claude_context.strip() not in result.stdout
    assert str(tmp_path) not in result.stdout

def test_report_cli_markdown_workflow_policy_ok(tmp_path: Path) -> None:
    context_policy = tmp_path / "context_policy.yaml"
    context_policy.write_text("{}\n", encoding="utf-8")
    write(tmp_path / "AGENTS.md", "Use project tests before reporting success.\n")
    write(
        tmp_path / ".github" / "workflows" / "ci.yml",
        """
name: ci
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Run guard checks
        run: |
          python -m agent_guard.cli context check --root . --policy context_policy.yaml --json
""",
    )
    workflow_policy = tmp_path / "workflow_policy.yaml"
    workflow_policy.write_text(
        "schema_version: agent-guard.workflow_policy.v1\n"
        "required_files:\n"
        "  - id: context_policy\n"
        "    path: context_policy.yaml\n"
        "workflow_checks:\n"
        "  - id: ci_guard_smoke\n"
        "    path: .github/workflows/ci.yml\n"
        "    required_commands:\n"
        "      - id: context_guard\n"
        "        command: python -m agent_guard.cli context check\n",
        encoding="utf-8",
    )

    result = run_cli(
        "report",
        "--root",
        str(tmp_path),
        "--context-policy",
        str(context_policy),
        "--workflow-policy",
        str(workflow_policy),
    )

    assert result.returncode == 0
    assert "| Scope | context+workflow |" in result.stdout
    assert "| Status | ok |" in result.stdout
    assert "| Workflow policy | workflow_policy.yaml |" in result.stdout
    assert "| Workflow checks | 2 |" in result.stdout
    assert "| Workflow drift findings | 0 |" in result.stdout
    assert "## Workflow Drift Evidence" in result.stdout
    assert "No workflow drift was detected." in result.stdout
    assert "python -m agent_guard.cli context check" not in result.stdout
    assert str(tmp_path) not in result.stdout

def test_report_cli_markdown_workflow_missing_command_is_sanitized(tmp_path: Path) -> None:
    context_policy = tmp_path / "context_policy.yaml"
    context_policy.write_text("{}\n", encoding="utf-8")
    write(tmp_path / "AGENTS.md", "Use project tests before reporting success.\n")
    raw_command = "python -m agent_guard.cli digest check --root . --policy digest_policy.yaml --json"
    write(
        tmp_path / ".github" / "workflows" / "ci.yml",
        f"""
name: ci
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: |
          # {raw_command}
          echo "{raw_command}"
          python - <<'PY'
          print("{raw_command}")
          PY
""",
    )
    workflow_policy = tmp_path / "workflow_policy.yaml"
    workflow_policy.write_text(
        "schema_version: agent-guard.workflow_policy.v1\n"
        "workflow_checks:\n"
        "  - id: ci_guard_smoke\n"
        "    path: .github/workflows/ci.yml\n"
        "    required_commands:\n"
        "      - id: digest_guard\n"
        "        command: python -m agent_guard.cli digest check\n",
        encoding="utf-8",
    )

    result = run_cli(
        "report",
        "--root",
        str(tmp_path),
        "--context-policy",
        str(context_policy),
        "--workflow-policy",
        str(workflow_policy),
    )

    assert result.returncode == 1
    assert "| Scope | context+workflow |" in result.stdout
    assert "| Status | violation |" in result.stdout
    assert "| Workflow drift findings | 1 |" in result.stdout
    assert (
        "| high | digest_guard | ASI04 Agentic Supply Chain Vulnerabilities; "
        "ASI08 Cascading Failures | .github/workflows/ci.yml | "
        "missing_required_workflow_command | ci_guard_smoke | digest_guard |"
        in result.stdout
    )
    assert raw_command not in result.stdout
    assert "echo" not in result.stdout
    assert str(tmp_path) not in result.stdout

def test_report_cli_markdown_workflow_missing_required_file_is_sanitized(tmp_path: Path) -> None:
    context_policy = tmp_path / "context_policy.yaml"
    context_policy.write_text("{}\n", encoding="utf-8")
    write(tmp_path / "AGENTS.md", "Use project tests before reporting success.\n")
    workflow_policy = tmp_path / "workflow_policy.yaml"
    workflow_policy.write_text(
        "schema_version: agent-guard.workflow_policy.v1\n"
        "required_files:\n"
        "  - id: workflow_policy_file\n"
        "    path: .agent-guard/workflow-policy.yaml\n",
        encoding="utf-8",
    )

    result = run_cli(
        "report",
        "--root",
        str(tmp_path),
        "--context-policy",
        str(context_policy),
        "--workflow-policy",
        str(workflow_policy),
    )

    assert result.returncode == 1
    assert "| Status | violation |" in result.stdout
    assert "| Workflow drift findings | 1 |" in result.stdout
    assert (
        "| high | workflow_policy_file | ASI04 Agentic Supply Chain Vulnerabilities; "
        "ASI08 Cascading Failures | .agent-guard/workflow-policy.yaml | "
        "missing_required_file | - | workflow_policy_file |"
        in result.stdout
    )
    assert str(tmp_path) not in result.stdout

def test_report_cli_markdown_digest_mismatch_is_sanitized(tmp_path: Path) -> None:
    context_policy = tmp_path / "context_policy.yaml"
    context_policy.write_text("{}\n", encoding="utf-8")
    content = "Use project tests before reporting success.\n"
    html_like_rule = "<img src=x onerror=alert(1)>"
    write(tmp_path / "bang!" / "<img src=x onerror=alert(1)>" / "AGENTS.md", content)
    expected_hash = "0" * 64
    actual_hash = sha256_text(content)
    digest_policy = tmp_path / "digest_policy.yaml"
    digest_policy.write_text(
        "checks:\n"
        f"  - id: {html_like_rule!r}\n"
        "    path: 'bang!/<img src=x onerror=alert(1)>/AGENTS.md'\n"
        f"    sha256: '{expected_hash}'\n",
        encoding="utf-8",
    )

    result = run_cli(
        "report",
        "--root",
        str(tmp_path),
        "--context-policy",
        str(context_policy),
        "--digest-policy",
        str(digest_policy),
    )

    assert result.returncode == 1
    assert "| Status | violation |" in result.stdout
    assert "| Digest drift findings | 1 |" in result.stdout
    assert "sha256 digest mismatch" in result.stdout
    assert "mismatch" in result.stdout
    assert "&lt;img src=x onerror=alert\\(1\\)&gt;" in result.stdout
    assert "bang\\!/" in result.stdout
    assert "<img src=x" not in result.stdout
    assert expected_hash not in result.stdout
    assert actual_hash not in result.stdout
    assert content.strip() not in result.stdout
    assert str(tmp_path) not in result.stdout

def test_report_cli_markdown_digest_missing_file_is_sanitized(tmp_path: Path) -> None:
    context_policy = tmp_path / "context_policy.yaml"
    context_policy.write_text("{}\n", encoding="utf-8")
    write(tmp_path / "AGENTS.md", "Use project tests before reporting success.\n")
    digest_policy = tmp_path / "digest_policy.yaml"
    expected_hash = "0" * 64
    digest_policy.write_text(
        "checks:\n"
        "  - id: missing_context_pin\n"
        "    path: MISSING_AGENTS.md\n"
        f"    sha256: '{expected_hash}'\n",
        encoding="utf-8",
    )

    result = run_cli(
        "report",
        "--root",
        str(tmp_path),
        "--context-policy",
        str(context_policy),
        "--digest-policy",
        str(digest_policy),
    )

    assert result.returncode == 1
    assert "| Status | violation |" in result.stdout
    assert (
        "| missing_context_pin | MISSING_AGENTS.md | missing | "
        "ASI04 Agentic Supply Chain Vulnerabilities; ASI06 Memory &amp; Context Poisoning | "
        "pinned file is missing |"
        in result.stdout
    )
    assert expected_hash not in result.stdout
    assert str(tmp_path) not in result.stdout

def test_report_cli_markdown_digest_and_workflow_combined_status(tmp_path: Path) -> None:
    context_policy = tmp_path / "context_policy.yaml"
    context_policy.write_text("{}\n", encoding="utf-8")
    agent_context = "Use project tests before reporting success.\n"
    write(tmp_path / "AGENTS.md", agent_context)
    digest_policy = tmp_path / "digest_policy.yaml"
    digest_policy.write_text(
        "checks:\n"
        "  - id: agent_context_pin\n"
        "    path: AGENTS.md\n"
        f"    sha256: '{sha256_text(agent_context)}'\n",
        encoding="utf-8",
    )
    write(
        tmp_path / ".github" / "workflows" / "ci.yml",
        """
name: ci
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: echo "documented only"
""",
    )
    workflow_policy = tmp_path / "workflow_policy.yaml"
    workflow_policy.write_text(
        "schema_version: agent-guard.workflow_policy.v1\n"
        "workflow_checks:\n"
        "  - id: ci_guard_smoke\n"
        "    path: .github/workflows/ci.yml\n"
        "    required_commands:\n"
        "      - id: context_guard\n"
        "        command: python -m agent_guard.cli context check\n",
        encoding="utf-8",
    )

    result = run_cli(
        "report",
        "--root",
        str(tmp_path),
        "--context-policy",
        str(context_policy),
        "--digest-policy",
        str(digest_policy),
        "--workflow-policy",
        str(workflow_policy),
    )

    assert result.returncode == 1
    assert "| Scope | context+digest+workflow |" in result.stdout
    assert "| Status | violation |" in result.stdout
    assert "| Digest checks | 1 |" in result.stdout
    assert "| Digest drift findings | 0 |" in result.stdout
    assert "| Workflow checks | 1 |" in result.stdout
    assert "| Workflow drift findings | 1 |" in result.stdout
    assert "python -m agent_guard.cli context check" not in result.stdout
    assert sha256_text(agent_context) not in result.stdout
    assert str(tmp_path) not in result.stdout

def test_report_cli_markdown_all_enabled_evidence_ok(tmp_path: Path) -> None:
    context_policy = tmp_path / "context_policy.yaml"
    context_policy.write_text("{}\n", encoding="utf-8")
    agent_context = "Require approval before shell writes.\nRun pytest before reporting completion.\n"
    write(tmp_path / "AGENTS.md", agent_context)
    path_policy = tmp_path / "path_policy.yaml"
    path_policy.write_text(
        "scan:\n"
        "  include:\n"
        "    - .\n"
        "  exclude: []\n"
        "policy:\n"
        "  forbidden_path_patterns:\n"
        "    - id: env_file\n"
        "      severity: high\n"
        "      pattern: '(^|/)\\.env(\\..+)?$'\n",
        encoding="utf-8",
    )
    content_policy = tmp_path / "content_policy.yaml"
    content_policy.write_text(
        "file_globs:\n  - '**/*.md'\nexclude_globs: []\nforbidden_patterns: []\n",
        encoding="utf-8",
    )
    api_policy = tmp_path / "api_policy.yaml"
    api_policy.write_text(
        "scan:\n  include:\n    - src\n  exclude: []\npolicy:\n  forbidden_api_patterns:\n    - '^https://api\\.openai\\.com/'\n",
        encoding="utf-8",
    )
    write(tmp_path / "src" / "ok.py", 'URL = "https://example.com"\n')
    digest_policy = tmp_path / "digest_policy.yaml"
    digest_policy.write_text(
        "checks:\n"
        "  - id: agent_context_pin\n"
        "    path: AGENTS.md\n"
        f"    sha256: '{sha256_text(agent_context)}'\n",
        encoding="utf-8",
    )
    write(
        tmp_path / ".github" / "workflows" / "ci.yml",
        "name: ci\n"
        "jobs:\n"
        "  test:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - run: python -m agent_guard.cli context check --root . --policy context_policy.yaml --json\n",
    )
    workflow_policy = tmp_path / "workflow_policy.yaml"
    workflow_policy.write_text(
        "schema_version: agent-guard.workflow_policy.v1\n"
        "workflow_checks:\n"
        "  - id: ci_guard_smoke\n"
        "    path: .github/workflows/ci.yml\n"
        "    required_commands:\n"
        "      - id: context_guard\n"
        "        command: python -m agent_guard.cli context check\n",
        encoding="utf-8",
    )

    result = run_cli(
        "report",
        "--root",
        str(tmp_path),
        "--context-policy",
        str(context_policy),
        "--path-policy",
        str(path_policy),
        "--content-policy",
        str(content_policy),
        "--content-scan-dir",
        ".",
        "--api-policy",
        str(api_policy),
        "--digest-policy",
        str(digest_policy),
        "--workflow-policy",
        str(workflow_policy),
    )

    assert result.returncode == 0
    assert "| Scope | context+path+content+api+digest+workflow |" in result.stdout
    assert "| Status | ok |" in result.stdout
    assert "| Path policy | path_policy.yaml |" in result.stdout
    assert "| Content policy | content_policy.yaml |" in result.stdout
    assert "| API policy | api_policy.yaml |" in result.stdout
    assert "| Path guard findings | 0 |" in result.stdout
    assert "| Content guard findings | 0 |" in result.stdout
    assert "| API guard findings | 0 |" in result.stdout
    assert "## Path Guard Evidence" in result.stdout
    assert "## Content Guard Evidence" in result.stdout
    assert "## API Guard Evidence" in result.stdout
    assert "https://example.com" not in result.stdout
    assert "python -m agent_guard.cli context check" not in result.stdout
    assert sha256_text(agent_context) not in result.stdout
    assert str(tmp_path) not in result.stdout

def test_report_cli_markdown_static_scanner_violations_are_sanitized(tmp_path: Path) -> None:
    context_policy = tmp_path / "context_policy.yaml"
    context_policy.write_text("{}\n", encoding="utf-8")
    write(tmp_path / "AGENTS.md", "Require approval before shell writes.\n")
    path_policy = tmp_path / "path_policy.yaml"
    path_policy.write_text(
        "scan:\n"
        "  include:\n"
        "    - .\n"
        "  exclude: []\n"
        "policy:\n"
        "  forbidden_path_patterns:\n"
        "    - id: private_path\n"
        "      severity: high\n"
        "      pattern: '(^|/)secrets/\\.env\\.local$'\n"
        "      message: 'private path message must not appear'\n",
        encoding="utf-8",
    )
    write(tmp_path / "secrets" / ".env.local", "TOKEN=x\n")
    content_policy = tmp_path / "content_policy.yaml"
    content_policy.write_text(
        "file_globs:\n"
        "  - '**/*.md'\n"
        "exclude_globs: []\n"
        "forbidden_patterns:\n"
        "  - id: secret_prompt\n"
        "    severity: high\n"
        "    pattern: '(?i)paste.*token'\n"
        "    message: 'raw content message must not appear'\n",
        encoding="utf-8",
    )
    raw_content = "please paste token sk-" + ("a" * 24)
    write(tmp_path / "docs" / "bad.md", raw_content + "\n")
    api_policy = tmp_path / "api_policy.yaml"
    api_policy.write_text(
        "scan:\n  include:\n    - src\n  exclude: []\npolicy:\n  forbidden_api_patterns:\n    - '^https://api\\.openai\\.com/'\n",
        encoding="utf-8",
    )
    raw_url = "https://api.openai.com/v1/responses"
    write(tmp_path / "src" / "bad.py", f'URL = "{raw_url}"\n')

    result = run_cli(
        "report",
        "--root",
        str(tmp_path),
        "--context-policy",
        str(context_policy),
        "--path-policy",
        str(path_policy),
        "--content-policy",
        str(content_policy),
        "--content-scan-dir",
        ".",
        "--api-policy",
        str(api_policy),
    )

    assert result.returncode == 1
    assert "| Status | violation |" in result.stdout
    assert "| Path guard findings | 1 |" in result.stdout
    assert "| Content guard findings | 1 |" in result.stdout
    assert "| API guard findings | 1 |" in result.stdout
    assert (
        "| high | private_path | ASI03 Identity and Privilege Abuse; "
        "ASI04 Agentic Supply Chain Vulnerabilities | secrets/.env.local |"
        in result.stdout
    )
    assert "| high | secret_prompt | ASI03 Identity and Privilege Abuse | docs/bad.md | 1 |" in result.stdout
    assert "| src/bad.py | 1 | forbidden_api | ASI02 Tool Misuse and Exploitation |" in result.stdout
    assert raw_content not in result.stdout
    assert raw_url not in result.stdout
    assert "^https://api" not in result.stdout
    assert "private path message must not appear" not in result.stdout
    assert "raw content message must not appear" not in result.stdout
    assert "matched_pattern" not in result.stdout
    assert "matched_forbidden_pattern" not in result.stdout
    assert "snippet" not in result.stdout
    assert str(tmp_path) not in result.stdout

def test_report_cli_github_annotations_static_scanner_violations_are_sanitized(
    tmp_path: Path,
) -> None:
    context_policy = tmp_path / "context_policy.yaml"
    context_policy.write_text("{}\n", encoding="utf-8")
    agent_context = "Require approval before shell writes.\n"
    write(tmp_path / "AGENTS.md", agent_context)
    path_policy = tmp_path / "path_policy.yaml"
    path_policy.write_text(
        "scan:\n"
        "  include:\n"
        "    - .\n"
        "  exclude: []\n"
        "policy:\n"
        "  forbidden_path_patterns:\n"
        "    - id: private_path\n"
        "      severity: high\n"
        "      pattern: '(^|/)secrets/\\.env\\.local$'\n"
        "      message: 'private path message must not appear'\n",
        encoding="utf-8",
    )
    write(tmp_path / "secrets" / ".env.local", "TOKEN=x\n")
    content_policy = tmp_path / "content_policy.yaml"
    content_policy.write_text(
        "file_globs:\n"
        "  - '**/*.md'\n"
        "exclude_globs: []\n"
        "forbidden_patterns:\n"
        "  - id: secret_prompt\n"
        "    severity: high\n"
        "    pattern: '(?i)paste.*token'\n"
        "    message: 'raw content message must not appear'\n",
        encoding="utf-8",
    )
    raw_content = "please paste token sk-" + ("a" * 24)
    write(tmp_path / "docs" / "bad.md", raw_content + "\n")
    api_policy = tmp_path / "api_policy.yaml"
    api_policy.write_text(
        "scan:\n  include:\n    - src\n  exclude: []\npolicy:\n  forbidden_api_patterns:\n    - '^https://api\\.openai\\.com/'\n",
        encoding="utf-8",
    )
    raw_url = "https://api.openai.com/v1/responses"
    write(tmp_path / "src" / "bad.py", f'URL = "{raw_url}"\n')
    digest_policy = tmp_path / "digest_policy.yaml"
    digest_policy.write_text(
        "checks:\n"
        "  - id: agent_context_pin\n"
        "    path: AGENTS.md\n"
        f"    sha256: '{'0' * 64}'\n",
        encoding="utf-8",
    )
    raw_required_command = (
        "python -m agent_guard.cli digest check --root . --policy digest_policy.yaml --json"
    )
    write(
        tmp_path / ".github" / "workflows" / "ci.yml",
        """
name: ci
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Run guard checks
        run: |
          python -m agent_guard.cli context check --root . --policy context_policy.yaml --json
""",
    )
    workflow_policy = tmp_path / "workflow_policy.yaml"
    workflow_policy.write_text(
        "schema_version: agent-guard.workflow_policy.v1\n"
        "workflow_checks:\n"
        "  - id: ci_guard_smoke\n"
        "    path: .github/workflows/ci.yml\n"
        "    required_commands:\n"
        "      - id: digest_guard\n"
        f"        command: {raw_required_command}\n",
        encoding="utf-8",
    )

    result = run_cli(
        "report",
        "--root",
        str(tmp_path),
        "--context-policy",
        str(context_policy),
        "--path-policy",
        str(path_policy),
        "--content-policy",
        str(content_policy),
        "--content-scan-dir",
        ".",
        "--api-policy",
        str(api_policy),
        "--digest-policy",
        str(digest_policy),
        "--workflow-policy",
        str(workflow_policy),
        "--format",
        "github-annotations",
    )

    assert result.returncode == 1
    assert (
        "::error file=secrets/.env.local,title=agent-guard path%3A private_path"
        "::path guard finding: private_path (OWASP risk themes: "
        "ASI03 Identity and Privilege Abuse; ASI04 Agentic Supply Chain Vulnerabilities)\n"
    ) in result.stdout
    assert (
        "::error file=docs/bad.md,line=1,title=agent-guard content%3A secret_prompt"
        "::content guard finding: secret_prompt (OWASP risk themes: ASI03 Identity and Privilege Abuse)\n"
    ) in result.stdout
    assert (
        "::error file=src/bad.py,line=1,title=agent-guard api%3A forbidden_api"
        "::api guard finding: forbidden_api (OWASP risk themes: ASI02 Tool Misuse and Exploitation)\n"
    ) in result.stdout
    assert (
        "::error file=AGENTS.md,title=agent-guard digest%3A agent_context_pin"
        "::digest drift: agent_context_pin (mismatch) (OWASP risk themes: "
        "ASI04 Agentic Supply Chain Vulnerabilities; ASI06 Memory & Context Poisoning)\n"
    ) in result.stdout
    assert (
        "::error file=.github/workflows/ci.yml,title=agent-guard workflow%3A digest_guard"
        "::workflow drift: missing_required_workflow_command (ci_guard_smoke/digest_guard) "
        "(OWASP risk themes: ASI04 Agentic Supply Chain Vulnerabilities; ASI08 Cascading Failures)\n"
    ) in result.stdout
    assert raw_content not in result.stdout
    assert raw_url not in result.stdout
    assert "^https://api" not in result.stdout
    assert raw_required_command not in result.stdout
    assert "private path message must not appear" not in result.stdout
    assert "raw content message must not appear" not in result.stdout
    assert sha256_text(agent_context) not in result.stdout
    assert "0000000000000000000000000000000000000000000000000000000000000000" not in result.stdout
    assert str(tmp_path) not in result.stdout
