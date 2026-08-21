# Where: tests/cli/test_mcp_report.py
# What: focused subprocess tests for MCP evidence embedded in reports.
# Why: keep MCP/report integration coverage separate from generic report tests.

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tests.cli.helpers import mcp_policy_text, run_cli, run_cli_from, write

def test_report_external_mcp_policy_path_is_sanitized_and_not_conformant(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    external = tmp_path / "outside" / "sk-examplePolicyName12345.yaml"
    write(
        repo / "AGENTS.md",
        "Require approval before shell writes.\n"
        "Keep credentials redacted in public evidence.\n"
        "Run pytest before reporting success.\n",
    )
    write(repo / ".agent-guard" / "context-policy.yaml", "{}\n")
    write(
        repo / ".agent-guard" / "path-policy.yaml",
        "scan:\n  include:\n    - .\n  exclude: []\npolicy:\n  allowed_path_patterns: []\n  forbidden_path_patterns: []\n",
    )
    write(
        repo / ".agent-guard" / "content-policy.yaml",
        "file_globs:\n  - '**/*.md'\nexclude_globs: []\nforbidden_patterns: []\n",
    )
    write(
        repo / ".agent-guard" / "workflow-policy.yaml",
        "schema_version: agent-guard.workflow_policy.v1\n"
        "required_files:\n"
        "  - id: context_policy\n"
        "    path: .agent-guard/context-policy.yaml\n",
    )
    write(external, mcp_policy_text())

    result = run_cli_from(
        repo,
        "report",
        "--root",
        str(repo),
        "--context-policy",
        ".agent-guard/context-policy.yaml",
        "--evidence-preset",
        "recommended",
        "--mcp-policy",
        "../outside/sk-examplePolicyName12345.yaml",
        "--format",
        "json",
    )

    assert result.returncode == 1
    payload = json.loads(result.stdout)
    assert payload["mcp_config"]["policy"]["path"] == "<external-policy>"
    assert any(item["rule_id"] == "required_mcp_policy_not_reviewed" for item in payload["conformance"]["findings"])
    assert "sk-examplePolicyName12345" not in result.stdout
    assert "../outside" not in result.stdout
    assert str(tmp_path) not in result.stdout

def test_report_cli_mcp_policy_parse_error_does_not_leak_yaml_content(tmp_path: Path) -> None:
    secret_like_yaml_value = "sk-exampleYamlLineLeak12345"
    write(tmp_path / "AGENTS.md", "Require approval before shell writes.\n")
    write(tmp_path / "context-policy.yaml", "{}\n")
    write(tmp_path / ".mcp.json", json.dumps({"mcpServers": {}}))
    write(
        tmp_path / "mcp-policy.yaml",
        "schema_version: agent-guard.mcp_policy.v1\n"
        f"policy:\n\tforbidden_risky_patterns: [{secret_like_yaml_value}]\n",
    )

    result = run_cli(
        "report",
        "--root",
        str(tmp_path),
        "--context-policy",
        str(tmp_path / "context-policy.yaml"),
        "--mcp-policy",
        str(tmp_path / "mcp-policy.yaml"),
        "--format",
        "json",
    )

    assert result.returncode == 2
    payload = json.loads(result.stdout)
    assert payload["status"] == "error"
    assert payload["error"] == "MCP policy YAML is not parseable"
    assert payload["mcp_config"] == {"policy": {"path": "mcp-policy.yaml"}}
    assert secret_like_yaml_value not in result.stdout
    assert str(tmp_path) not in result.stdout

def test_report_cli_mcp_policy_implies_mcp_config_check(tmp_path: Path) -> None:
    write(tmp_path / "AGENTS.md", "Require approval before shell writes.\n")
    write(tmp_path / "context-policy.yaml", "{}\n")
    write(
        tmp_path / ".mcp.json",
        json.dumps(
            {
                "mcpServers": {
                    "browser": {
                        "command": "npx",
                        "args": ["@vendor/browser-mcp@latest"],
                    }
                }
            }
        ),
    )
    write(
        tmp_path / "mcp-policy.yaml",
        "schema_version: agent-guard.mcp_policy.v1\n"
        "policy:\n"
        "  forbidden_risky_patterns:\n"
        "    - latest_package\n",
    )

    result = run_cli(
        "report",
        "--root",
        str(tmp_path),
        "--context-policy",
        str(tmp_path / "context-policy.yaml"),
        "--mcp-policy",
        str(tmp_path / "mcp-policy.yaml"),
        "--format",
        "json",
    )

    assert result.returncode == 1
    payload = json.loads(result.stdout)
    assert payload["report"]["scope"] == "context+mcp"
    assert payload["mcp_config"]["policy"]["path"] == "mcp-policy.yaml"
    assert payload["mcp_config"]["policy"]["forbidden_risky_patterns"] == ["latest_package"]
    assert {item["reason"] for item in payload["mcp_config"]["findings"]} == {"latest_package"}
    gates = {item["gate"]: item for item in payload["evidence_coverage"]["gates"]}
    assert gates["mcp_config"]["policy"] == {"path": "mcp-policy.yaml"}
    assert str(tmp_path) not in result.stdout


@pytest.mark.parametrize(
    ("command", "args", "expected_latest"),
    [
        ("npm", ["--loglevel=silent", "exec", "--", "pkg@latest"], True),
        ("npm", ["-C", "exec", "exec", "--", "pkg@latest"], True),
        ("npm", ["-C", "exec", "ignored@latest"], False),
        ("npm", ["-C=exec", "exec", "--", "pkg@latest"], True),
        ("npm", ["-C=exec", "ignored@latest"], False),
        ("npm", ["--prefix=exec", "x", "--", "pkg@latest"], True),
        ("npm", ["--userconfig=exec", "x", "--", "pkg@latest"], True),
        ("npm", ["--userconfig", "exec", "ignored@latest"], False),
        ("npx", ["-C", "exec", "pkg@latest"], True),
        ("npx", ["-C=exec", "pkg@latest"], True),
        ("npx", ["--userconfig=exec", "pkg@latest"], True),
        ("uvx", ["--color=always", "pkg@latest"], True),
        ("npm", ["--prefix", "exec", "exec", "--", "pkg@latest"], True),
        ("npm", ["--unknown", "exec", "pkg@latest"], False),
    ],
)
def test_report_cli_latest_policy_respects_explicit_launcher_option_arity(
    tmp_path: Path,
    command: str,
    args: list[str],
    expected_latest: bool,
) -> None:
    write(tmp_path / "AGENTS.md", "Require approval before shell writes.\n")
    write(tmp_path / "context-policy.yaml", "{}\n")
    write(
        tmp_path / ".mcp.json",
        json.dumps(
            {
                "mcpServers": {
                    "package-manager": {
                        "command": command,
                        "args": args,
                    }
                }
            }
        ),
    )
    write(tmp_path / "mcp-policy.yaml", mcp_policy_text(["latest_package"]))

    result = run_cli(
        "report",
        "--root",
        str(tmp_path),
        "--context-policy",
        str(tmp_path / "context-policy.yaml"),
        "--mcp-policy",
        str(tmp_path / "mcp-policy.yaml"),
        "--format",
        "json",
    )

    assert result.returncode == (1 if expected_latest else 0), result.stdout
    payload = json.loads(result.stdout)
    assert payload["mcp_config"]["status"] == ("violation" if expected_latest else "ok")
    assert payload["mcp_config"]["policy"]["forbidden_risky_patterns"] == ["latest_package"]
    findings = {
        (item["server_name"], item["reason"])
        for item in payload["mcp_config"]["findings"]
    }
    assert findings == ({("package-manager", "latest_package")} if expected_latest else set())
    assert str(tmp_path) not in result.stdout


def test_report_cli_markdown_mcp_config_findings_are_sanitized(tmp_path: Path) -> None:
    context_policy = tmp_path / "context_policy.yaml"
    context_policy.write_text("{}\n", encoding="utf-8")
    secret_server = "github_pat_" + ("0" * 20)
    raw_command = "npx -y @vendor/browser-mcp --token sk-exampleSecretValue123 --root /home/alice/private"
    write(tmp_path / "AGENTS.md", "Require approval before shell writes.\n")
    write(
        tmp_path / ".mcp.json",
        json.dumps(
            {
                "mcpServers": {
                    secret_server: {
                        "command": raw_command,
                        "args": ["@vendor/browser-mcp@latest"],
                    }
                }
            }
        ),
    )

    result = run_cli(
        "report",
        "--root",
        str(tmp_path),
        "--context-policy",
        str(context_policy),
        "--mcp-config-check",
    )

    assert result.returncode == 1
    assert "## MCP Configuration Evidence" in result.stdout
    assert "&lt;redacted-server&gt;" in result.stdout
    assert "secret_shaped_inline_value" in result.stdout
    assert secret_server not in result.stdout
    assert raw_command not in result.stdout
    assert "sk-exampleSecretValue123" not in result.stdout
    assert "/home/alice/private" not in result.stdout
    assert str(tmp_path) not in result.stdout
