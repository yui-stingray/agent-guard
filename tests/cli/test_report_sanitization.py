# Where: tests/cli/test_report_sanitization.py
# What: subprocess tests for report path, policy, and error sanitization.
# Why: keep report redaction edge cases separate from report integration coverage.

from __future__ import annotations

import json
from pathlib import Path

from agent_guard.cli import scrub_report_error_message

from tests.cli.helpers import run_cli, run_cli_from, sha256_text, write

def test_report_cli_markdown_missing_static_policy_scrubs_path(tmp_path: Path) -> None:
    context_policy = tmp_path / "context_policy.yaml"
    context_policy.write_text("{}\n", encoding="utf-8")
    write(tmp_path / "AGENTS.md", "Use project tests before reporting success.\n")

    cases = [
        ("--path-policy", "missing_path.yaml", "Path policy"),
        ("--content-policy", "missing_content.yaml", "Content policy"),
        ("--api-policy", "missing_api.yaml", "API policy"),
    ]
    for flag, missing_name, label in cases:
        result = run_cli(
            "report",
            "--root",
            str(tmp_path),
            "--context-policy",
            str(context_policy),
            flag,
            str(tmp_path / missing_name),
        )

        assert result.returncode == 2
        assert "| Status | error |" in result.stdout
        assert f"| {label} | {missing_name} |" in result.stdout
        assert missing_name in result.stdout
        assert str(tmp_path) not in result.stdout

def test_report_cli_url_like_policy_path_is_sanitized(tmp_path: Path) -> None:
    url_policy = "https://policy.example.invalid/reviewed/context-policy.yaml"
    write(tmp_path / "AGENTS.md", "Use project tests before reporting success.\n")

    result = run_cli(
        "report",
        "--root",
        str(tmp_path),
        "--context-policy",
        url_policy,
        "--format",
        "json",
    )

    assert result.returncode == 2
    payload = json.loads(result.stdout)
    assert payload["policy"] == {"path": "<external-policy>"}
    assert payload["report"]["sanitized"] is True
    assert "policy.example.invalid" not in result.stdout
    assert "reviewed/context-policy" not in result.stdout
    assert str(tmp_path) not in result.stdout

def test_report_cli_policy_paths_are_root_relative_from_external_cwd(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    cwd = tmp_path / "cwd"
    context_policy_arg = ".agent-guard/context-policy.yaml"
    path_policy_arg = ".agent-guard/path-policy.yaml"
    content_policy_arg = ".agent-guard/content-policy.yaml"
    api_policy_arg = ".agent-guard/api-policy.yaml"
    digest_policy_arg = ".agent-guard/digest-policy.yaml"
    workflow_policy_arg = ".agent-guard/workflow-policy.yaml"
    agent_context = "Require approval before shell writes.\nRun tests locally.\n"
    write(repo / context_policy_arg, "{}\n")
    write(repo / "AGENTS.md", agent_context)
    write(
        repo / path_policy_arg,
        "scan:\n"
        "  include:\n"
        "    - .\n"
        "  exclude: []\n"
        "policy:\n"
        "  forbidden_path_patterns: []\n",
    )
    write(
        repo / content_policy_arg,
        "file_globs:\n"
        "  - '**/*.md'\n"
        "exclude_globs: []\n"
        "forbidden_patterns: []\n",
    )
    write(repo / "docs" / "safe.md", "safe\n")
    write(
        repo / api_policy_arg,
        "scan:\n"
        "  include:\n"
        "    - src\n"
        "  exclude: []\n"
        "policy:\n"
        "  allowed_api_patterns: []\n"
        "  forbidden_api_patterns:\n"
        "    - '^https://api\\.openai\\.com/'\n",
    )
    write(repo / "src" / "ok.py", 'URL = "https://example.com"\n')
    write(
        repo / digest_policy_arg,
        "checks:\n"
        "  - id: root_agents_md\n"
        "    path: AGENTS.md\n"
        f"    sha256: '{sha256_text(agent_context)}'\n",
    )
    write(
        repo / ".github" / "workflows" / "ci.yml",
        """
name: ci
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: python -m agent_guard.cli context check --root . --policy .agent-guard/context-policy.yaml --json
""",
    )
    write(
        repo / workflow_policy_arg,
        "schema_version: agent-guard.workflow_policy.v1\n"
        "required_files:\n"
        "  - id: context_policy\n"
        "    path: .agent-guard/context-policy.yaml\n"
        "workflow_checks:\n"
        "  - id: ci_smoke\n"
        "    path: .github/workflows/ci.yml\n"
        "    required_commands:\n"
        "      - id: context_guard\n"
        "        command: python -m agent_guard.cli context check\n",
    )
    for policy_arg in (
        context_policy_arg,
        path_policy_arg,
        content_policy_arg,
        api_policy_arg,
        digest_policy_arg,
        workflow_policy_arg,
    ):
        write(cwd / policy_arg, "not: [valid\n")

    result = run_cli_from(
        cwd,
        "report",
        "--root",
        str(repo),
        "--context-policy",
        context_policy_arg,
        "--path-policy",
        path_policy_arg,
        "--content-policy",
        content_policy_arg,
        "--content-scan-dir",
        "docs",
        "--api-policy",
        api_policy_arg,
        "--digest-policy",
        digest_policy_arg,
        "--workflow-policy",
        workflow_policy_arg,
        "--format",
        "json",
    )

    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert payload["status"] == "ok"
    assert payload["policy"] == {"path": context_policy_arg}
    assert payload["path"]["policy"] == {"path": path_policy_arg}
    assert payload["content"]["policy"] == {"path": content_policy_arg}
    assert payload["api"]["policy"] == {"path": api_policy_arg}
    assert payload["context_lock"]["policy"] == {"path": digest_policy_arg}
    assert payload["digest"]["policy"] == {"path": digest_policy_arg}
    assert payload["workflow"]["policy"] == {"path": workflow_policy_arg}
    assert str(tmp_path) not in result.stdout

def test_report_cli_json_redacts_secret_shaped_path_segments(tmp_path: Path) -> None:
    secret_like = "sk-" + ("a" * 24)
    context_policy = tmp_path / "context_policy.yaml"
    context_policy.write_text("{}\n", encoding="utf-8")
    write(tmp_path / "AGENTS.md", "Use project tests before reporting success.\n")
    content_policy = tmp_path / "content_policy.yaml"
    content_policy.write_text("{}\n", encoding="utf-8")
    write(tmp_path / "docs" / secret_like / "bad.md", f"Hardcoded token: {secret_like}\n")
    api_policy = tmp_path / "api_policy.yaml"
    api_policy.write_text(
        "scan:\n"
        "  include:\n"
        "    - src\n"
        "  exclude: []\n"
        "policy:\n"
        "  allowed_api_patterns: []\n"
        "  forbidden_api_patterns:\n"
        "    - '^https://api\\.openai\\.com/'\n",
        encoding="utf-8",
    )
    write(tmp_path / "src" / secret_like / "bad.py", 'URL = "https://api.openai.com/v1/responses"\n')

    result = run_cli(
        "report",
        "--root",
        str(tmp_path),
        "--context-policy",
        str(context_policy),
        "--content-policy",
        str(content_policy),
        "--content-scan-dir",
        "docs",
        "--api-policy",
        str(api_policy),
        "--format",
        "json",
    )

    assert result.returncode == 1
    assert secret_like not in result.stdout
    payload = json.loads(result.stdout)
    assert payload["content"]["findings"][0]["file"] == "docs/<redacted>/bad.md"
    assert payload["api"]["findings"][0]["path"] == "src/<redacted>/bad.py"

def test_report_cli_markdown_content_scan_dir_must_stay_under_root(tmp_path: Path) -> None:
    context_policy = tmp_path / "context_policy.yaml"
    context_policy.write_text("{}\n", encoding="utf-8")
    write(tmp_path / "AGENTS.md", "Use project tests before reporting success.\n")
    content_policy = tmp_path / "content_policy.yaml"
    content_policy.write_text(
        "file_globs:\n  - '**/*.md'\nexclude_globs: []\nforbidden_patterns: []\n",
        encoding="utf-8",
    )
    outside = tmp_path.parent / f"{tmp_path.name}-outside"
    outside.mkdir()

    result = run_cli(
        "report",
        "--root",
        str(tmp_path),
        "--context-policy",
        str(context_policy),
        "--content-policy",
        str(content_policy),
        "--content-scan-dir",
        str(outside),
    )

    assert result.returncode == 2
    assert "| Status | error |" in result.stdout
    assert "content scan dir must stay under report root" in result.stdout
    assert str(tmp_path) not in result.stdout
    assert str(outside) not in result.stdout


def test_report_cli_rejects_external_content_symlink_target(tmp_path: Path) -> None:
    context_policy = tmp_path / "context_policy.yaml"
    context_policy.write_text("{}\n", encoding="utf-8")
    write(tmp_path / "AGENTS.md", "Use project tests before reporting success.\n")
    content_policy = tmp_path / "content_policy.yaml"
    content_policy.write_text(
        "file_globs:\n  - '**/*.md'\nexclude_globs: []\nforbidden_patterns: []\n",
        encoding="utf-8",
    )
    outside = tmp_path.parent / f"{tmp_path.name}-external-target"
    write(outside / "private-marker.md", "synthetic external content\n")
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "linked.md").symlink_to(outside / "private-marker.md")

    result = run_cli(
        "report",
        "--root",
        str(tmp_path),
        "--context-policy",
        str(context_policy),
        "--content-policy",
        str(content_policy),
        "--content-scan-dir",
        "docs",
    )

    assert result.returncode == 2
    assert "| Status | error |" in result.stdout
    assert "content scan target must stay under repo root" in result.stdout
    assert str(tmp_path) not in result.stdout
    assert str(outside) not in result.stdout
    assert "private-marker" not in result.stdout
    assert "synthetic external content" not in result.stdout


def test_report_cli_markdown_static_policy_error_omits_raw_regex(tmp_path: Path) -> None:
    context_policy = tmp_path / "context_policy.yaml"
    context_policy.write_text("{}\n", encoding="utf-8")
    write(tmp_path / "AGENTS.md", "Use project tests before reporting success.\n")
    raw_regex = "sk-" + ("a" * 24) + "("
    path_policy = tmp_path / "path_policy.yaml"
    path_policy.write_text(
        "scan:\n"
        "  include:\n"
        "    - .\n"
        "policy:\n"
        "  forbidden_path_patterns:\n"
        "    - id: invalid_secret_regex\n"
        "      severity: high\n"
        f"      pattern: {raw_regex!r}\n",
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
    )

    assert result.returncode == 2
    assert "| Status | error |" in result.stdout
    assert "invalid forbidden_path_patterns regex" in result.stdout
    assert "&lt;regex&gt;" in result.stdout
    assert raw_regex not in result.stdout
    assert "sk-" not in result.stdout
    assert str(tmp_path) not in result.stdout

def test_report_cli_markdown_escapes_repo_controlled_cells(tmp_path: Path) -> None:
    policy = tmp_path / "context_policy.yaml"
    html_like_rule = "<img src=x onerror=alert(1)>"
    policy.write_text(
        "policy:\n"
        "  extra_forbidden_patterns:\n"
        f"    - id: {html_like_rule!r}\n"
        "      severity: high\n"
        "      pattern: 'trigger-report-finding'\n"
        "      message: 'html-like rule id should be escaped'\n",
        encoding="utf-8",
    )
    write(
        tmp_path / "bang!" / "<img src=x onerror=alert(1)>" / "AGENTS.md",
        "trigger-report-finding\n",
    )

    result = run_cli("report", "--root", str(tmp_path), "--context-policy", str(policy))

    assert result.returncode == 1
    assert "<img src=x" not in result.stdout
    assert "bang!<absolute-path>" not in result.stdout
    assert "bang\\!/" in result.stdout
    assert "&lt;img src=x onerror=alert\\(1\\)&gt;" in result.stdout
    assert "| high | &lt;img src=x onerror=alert\\(1\\)&gt; |" in result.stdout
    assert str(tmp_path) not in result.stdout

def test_report_cli_markdown_error_scrubs_policy_path(tmp_path: Path) -> None:
    result = run_cli("report", "--root", str(tmp_path), "--context-policy", str(tmp_path / "missing.yaml"))

    assert result.returncode == 2
    assert result.stdout.startswith("# Agent Guard Evidence Report\n")
    assert "| Status | error |" in result.stdout
    assert "## Error" in result.stdout
    assert "missing.yaml" in result.stdout
    assert str(tmp_path) not in result.stdout

def test_report_cli_github_annotations_error_scrubs_policy_path(tmp_path: Path) -> None:
    result = run_cli(
        "report",
        "--root",
        str(tmp_path),
        "--context-policy",
        str(tmp_path / "missing.yaml"),
        "--format",
        "github-annotations",
    )

    assert result.returncode == 2
    assert result.stdout.startswith("::error title=agent-guard report::report error: ")
    assert "missing.yaml" in result.stdout
    assert str(tmp_path) not in result.stdout

def test_report_cli_markdown_digest_policy_error_scrubs_paths(tmp_path: Path) -> None:
    context_policy = tmp_path / "context_policy.yaml"
    context_policy.write_text("{}\n", encoding="utf-8")
    write(tmp_path / "AGENTS.md", "Use project tests before reporting success.\n")
    digest_policy = tmp_path / "digest_policy.yaml"
    outside = tmp_path.parent / f"{tmp_path.name}-outside" / "AGENTS.md"
    digest_policy.write_text(
        "checks:\n"
        "  - id: outside_context_pin\n"
        f"    path: {str(outside)!r}\n"
        f"    sha256: '{'0' * 64}'\n",
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

    assert result.returncode == 2
    assert "| Status | error |" in result.stdout
    assert "| Scope | context+digest |" in result.stdout
    assert "| Digest policy | digest_policy.yaml |" in result.stdout
    assert "outside_context_pin" in result.stdout
    assert str(tmp_path) not in result.stdout
    assert str(outside) not in result.stdout
    assert "0000000000000000000000000000000000000000000000000000000000000000" not in result.stdout

def test_report_cli_markdown_missing_digest_policy_scrubs_path(tmp_path: Path) -> None:
    context_policy = tmp_path / "context_policy.yaml"
    context_policy.write_text("{}\n", encoding="utf-8")
    write(tmp_path / "AGENTS.md", "Use project tests before reporting success.\n")

    result = run_cli(
        "report",
        "--root",
        str(tmp_path),
        "--context-policy",
        str(context_policy),
        "--digest-policy",
        str(tmp_path / "missing_digest.yaml"),
    )

    assert result.returncode == 2
    assert "| Status | error |" in result.stdout
    assert "| Scope | context+digest |" in result.stdout
    assert "| Digest policy | missing_digest.yaml |" in result.stdout
    assert "missing_digest.yaml" in result.stdout
    assert str(tmp_path) not in result.stdout

def test_report_cli_markdown_missing_workflow_policy_scrubs_path(tmp_path: Path) -> None:
    context_policy = tmp_path / "context_policy.yaml"
    context_policy.write_text("{}\n", encoding="utf-8")
    write(tmp_path / "AGENTS.md", "Use project tests before reporting success.\n")

    result = run_cli(
        "report",
        "--root",
        str(tmp_path),
        "--context-policy",
        str(context_policy),
        "--workflow-policy",
        str(tmp_path / "missing_workflow.yaml"),
    )

    assert result.returncode == 2
    assert "| Status | error |" in result.stdout
    assert "| Scope | context+workflow |" in result.stdout
    assert "| Workflow policy | missing_workflow.yaml |" in result.stdout
    assert "missing_workflow.yaml" in result.stdout
    assert str(tmp_path) not in result.stdout

def test_report_cli_markdown_workflow_policy_error_scrubs_paths(tmp_path: Path) -> None:
    context_policy = tmp_path / "context_policy.yaml"
    context_policy.write_text("{}\n", encoding="utf-8")
    write(tmp_path / "AGENTS.md", "Use project tests before reporting success.\n")
    workflow_policy = tmp_path / "workflow_policy.yaml"
    workflow_policy.write_text(
        "schema_version: agent-guard.workflow_policy.v1\n"
        "required_files:\n"
        "  - id: outside\n"
        "    path: ../outside.yaml\n",
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

    assert result.returncode == 2
    assert "| Status | error |" in result.stdout
    assert "| Scope | context+workflow |" in result.stdout
    assert "| Workflow policy | workflow_policy.yaml |" in result.stdout
    assert "path must not contain" in result.stdout
    assert str(tmp_path) not in result.stdout

def test_report_cli_markdown_malformed_workflow_yaml_omits_run_body(tmp_path: Path) -> None:
    raw_command = "python -m agent_guard.cli digest check --root . --policy digest_policy.yaml --json"
    context_policy = tmp_path / "context_policy.yaml"
    context_policy.write_text("{}\n", encoding="utf-8")
    write(tmp_path / "AGENTS.md", "Use project tests before reporting success.\n")
    write(
        tmp_path / ".github" / "workflows" / "ci.yml",
        "name: ci\n"
        "jobs:\n"
        "  test:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        f'      - run: "{raw_command}\n',
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

    assert result.returncode == 2
    assert "| Status | error |" in result.stdout
    assert "workflow YAML is invalid" in result.stdout
    assert raw_command not in result.stdout
    assert "python -m agent_guard.cli" not in result.stdout
    assert str(tmp_path) not in result.stdout

def test_scrub_report_error_message_omits_workflow_run_variants() -> None:
    raw_command = "python -m agent_guard.cli digest check --root . --policy digest_policy.yaml --json"
    messages = [
        f'      - run: "{raw_command}',
        f'      - run : "{raw_command}',
        f'      - "run": "{raw_command}',
        f"      - 'run': \"{raw_command}",
    ]

    for message in messages:
        scrubbed = scrub_report_error_message(message)
        assert raw_command not in scrubbed
        assert "python -m agent_guard.cli" not in scrubbed
        assert "<workflow-run>" in scrubbed
