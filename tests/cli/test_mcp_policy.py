# Where: tests/cli/test_mcp_policy.py
# What: focused subprocess tests for MCP policy path handling.
# Why: keep extracted MCP policy coverage close to its module.

from __future__ import annotations

import json
from pathlib import Path

from tests.cli.helpers import mcp_policy_text, run_cli, run_cli_from, write

def test_mcp_check_cli_respects_reviewed_policy_forbidden_patterns(tmp_path: Path) -> None:
    raw_command = "npx -y @vendor/browser-mcp --token sk-exampleSecretValue123 --root /home/alice/private"
    write(
        tmp_path / ".mcp.json",
        json.dumps(
            {
                "mcpServers": {
                    "browser": {
                        "command": raw_command,
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
        "  fail_on_parse_error: true\n"
        "  forbidden_risky_patterns:\n"
        "    - inline_authorization_value\n",
    )

    result = run_cli(
        "mcp",
        "check",
        "--root",
        str(tmp_path),
        "--policy",
        str(tmp_path / "mcp-policy.yaml"),
        "--json",
    )

    assert result.returncode == 1
    payload = json.loads(result.stdout)
    assert payload["policy"] == {"path": "mcp-policy.yaml"}
    assert payload["mcp_config"]["policy"]["path"] == "mcp-policy.yaml"
    assert payload["mcp_config"]["policy"]["forbidden_risky_patterns"] == ["inline_authorization_value"]
    assert {item["reason"] for item in payload["mcp_config"]["findings"]} == {"inline_authorization_value"}
    server = next(item for item in payload["mcp_config"]["surfaces"] if item["surface"] == "mcp_server_reference")
    assert set(server["risky_patterns"]) == {
        "filesystem_root_reference",
        "inline_authorization_value",
        "secret_shaped_inline_value",
        "unpinned_package",
    }
    assert raw_command not in result.stdout
    assert "sk-exampleSecretValue123" not in result.stdout
    assert "/home/alice/private" not in result.stdout
    assert str(tmp_path) not in result.stdout

def test_mcp_check_cli_policy_rejects_invalid_npm_semver_boundaries(tmp_path: Path) -> None:
    max_length_version = "1.2.3+" + ("a" * (256 - len("1.2.3+")))
    over_length_version = max_length_version + "a"
    write(
        tmp_path / ".mcp.json",
        json.dumps(
            {
                "mcpServers": {
                    "safe-boundary": {"command": "npx", "args": [f"pkg@{max_length_version}"]},
                    "unsafe-integer": {"command": "npx", "args": ["pkg@9007199254740992.0.0"]},
                    "over-length": {"command": "npx", "args": [f"pkg@{over_length_version}"]},
                }
            }
        ),
    )
    write(tmp_path / "mcp-policy.yaml", mcp_policy_text(["unpinned_package"]))

    result = run_cli(
        "mcp",
        "check",
        "--root",
        str(tmp_path),
        "--policy",
        str(tmp_path / "mcp-policy.yaml"),
        "--json",
    )

    assert result.returncode == 1, result.stdout
    payload = json.loads(result.stdout)
    findings = {
        (item["server_name"], item["reason"])
        for item in payload["mcp_config"]["findings"]
    }
    assert findings == {
        ("unsafe-integer", "unpinned_package"),
        ("over-length", "unpinned_package"),
    }
    servers = {
        item["server_name"]: item
        for item in payload["mcp_config"]["surfaces"]
        if item["surface"] == "mcp_server_reference"
    }
    assert servers["safe-boundary"]["version_pinned"] is True
    assert servers["unsafe-integer"]["version_pinned"] is False
    assert servers["over-length"]["version_pinned"] is False
    assert str(tmp_path) not in result.stdout


def test_mcp_policy_is_resolved_relative_to_root_from_external_cwd(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    outside_cwd = tmp_path / "outside-cwd"
    outside_cwd.mkdir()
    write(
        repo / "AGENTS.md",
        "Require approval before shell writes.\n"
        "Keep credentials redacted in public evidence.\n",
    )
    write(repo / ".agent-guard" / "context-policy.yaml", "{}\n")
    write(repo / ".mcp.json", json.dumps({"mcpServers": {}}))
    write(repo / ".agent-guard" / "mcp-policy.yaml", mcp_policy_text())

    result = run_cli_from(
        outside_cwd,
        "mcp",
        "check",
        "--root",
        str(repo),
        "--policy",
        ".agent-guard/mcp-policy.yaml",
        "--json",
    )

    assert result.returncode == 0, result.stdout
    payload = json.loads(result.stdout)
    assert payload["policy"] == {"path": ".agent-guard/mcp-policy.yaml"}
    assert payload["mcp_config"]["policy"]["path"] == ".agent-guard/mcp-policy.yaml"
    assert str(tmp_path) not in result.stdout

    report = run_cli_from(
        outside_cwd,
        "report",
        "--root",
        str(repo),
        "--context-policy",
        str(repo / ".agent-guard" / "context-policy.yaml"),
        "--mcp-policy",
        ".agent-guard/mcp-policy.yaml",
        "--format",
        "json",
    )

    assert report.returncode == 0, report.stdout
    report_payload = json.loads(report.stdout)
    assert report_payload["mcp_config"]["policy"]["path"] == ".agent-guard/mcp-policy.yaml"
    assert str(tmp_path) not in report.stdout

def test_mcp_external_policy_path_is_sanitized(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    external = tmp_path / "outside" / "sk-examplePolicyName12345.yaml"
    write(repo / ".mcp.json", json.dumps({"mcpServers": {}}))
    write(external, mcp_policy_text())

    result = run_cli_from(
        repo,
        "mcp",
        "check",
        "--root",
        str(repo),
        "--policy",
        "../outside/sk-examplePolicyName12345.yaml",
        "--json",
    )

    assert result.returncode == 0, result.stdout
    payload = json.loads(result.stdout)
    assert payload["policy"] == {"path": "<external-policy>"}
    assert payload["mcp_config"]["policy"]["path"] == "<external-policy>"
    assert "sk-examplePolicyName12345" not in result.stdout
    assert "../outside" not in result.stdout
    assert str(tmp_path) not in result.stdout

def test_mcp_url_like_policy_path_is_sanitized(tmp_path: Path) -> None:
    url_policy = "https://policy.example.invalid/reviewed/mcp-policy.yaml"
    write(tmp_path / ".mcp.json", json.dumps({"mcpServers": {}}))

    result = run_cli(
        "mcp",
        "check",
        "--root",
        str(tmp_path),
        "--policy",
        url_policy,
        "--json",
    )

    assert result.returncode == 2
    payload = json.loads(result.stdout)
    assert payload["policy"] == {"path": "<external-policy>"}
    assert "policy.example.invalid" not in result.stdout
    assert "reviewed/mcp-policy" not in result.stdout
    assert str(tmp_path) not in result.stdout

def test_mcp_check_cli_rejects_bad_policy_without_path_leak(tmp_path: Path) -> None:
    write(tmp_path / ".mcp.json", json.dumps({"mcpServers": {}}))
    secret_like_unknown_label = "sk-exampleUnknownPolicyValue12345"
    write(
        tmp_path / "mcp-policy.yaml",
        "schema_version: agent-guard.mcp_policy.v1\n"
        "policy:\n"
        "  forbidden_risky_patterns:\n"
        f"    - {secret_like_unknown_label}\n",
    )

    result = run_cli(
        "mcp",
        "check",
        "--root",
        str(tmp_path),
        "--policy",
        str(tmp_path / "mcp-policy.yaml"),
        "--json",
    )

    assert result.returncode == 2
    payload = json.loads(result.stdout)
    assert payload["status"] == "error"
    assert payload["policy"] == {"path": "mcp-policy.yaml"}
    assert "unknown MCP risk pattern" in payload["error"]
    assert secret_like_unknown_label not in result.stdout
    assert str(tmp_path) not in result.stdout

def test_mcp_check_cli_rejects_malformed_policy_without_yaml_content_leak(tmp_path: Path) -> None:
    secret_like_yaml_tag = "sk-exampleYamlTagLeak12345"
    write(tmp_path / ".mcp.json", json.dumps({"mcpServers": {}}))
    write(
        tmp_path / "mcp-policy.yaml",
        f"schema_version: !{secret_like_yaml_tag} agent-guard.mcp_policy.v1\n",
    )

    result = run_cli(
        "mcp",
        "check",
        "--root",
        str(tmp_path),
        "--policy",
        str(tmp_path / "mcp-policy.yaml"),
        "--json",
    )

    assert result.returncode == 2
    payload = json.loads(result.stdout)
    assert payload["status"] == "error"
    assert payload["error"] == "MCP policy YAML is not parseable"
    assert secret_like_yaml_tag not in result.stdout
    assert str(tmp_path) not in result.stdout
