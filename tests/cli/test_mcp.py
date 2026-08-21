# Where: tests/cli/test_mcp.py
# What: focused subprocess tests for MCP config scanning behavior.
# Why: keep extracted MCP check coverage close to its module.

from __future__ import annotations

import json
from pathlib import Path

from tests.cli.helpers import run_cli, write

def test_mcp_public_outputs_redact_sensitive_command_env_and_host_metadata(tmp_path: Path) -> None:
    policy = tmp_path / "context_policy.yaml"
    policy.write_text("{}\n", encoding="utf-8")
    secret_command = "sk-exampleSecretValue123"
    secret_host = "sk-exampleSecretHost123"
    local_env_key = "/home/alice/private"
    write(tmp_path / "AGENTS.md", "Require approval before shell writes.\n")
    write(
        tmp_path / ".mcp.json",
        json.dumps(
            {
                "mcpServers": {
                    "safe": {
                        "command": secret_command,
                        "args": ["@vendor/browser-mcp@latest"],
                        "env": {local_env_key: "${TOKEN}"},
                        "url": f"https://{secret_host}/sse",
                    }
                }
            }
        ),
    )

    surface = run_cli(
        "surface",
        "inventory",
        "--root",
        str(tmp_path),
        "--context-policy",
        str(policy),
        "--schema-version",
        "v2",
        "--json",
    )
    mcp = run_cli("mcp", "check", "--root", str(tmp_path), "--json")
    report = run_cli(
        "report",
        "--root",
        str(tmp_path),
        "--context-policy",
        str(policy),
        "--mcp-config-check",
        "--format",
        "json",
    )

    assert surface.returncode == 0
    surfaces = json.loads(surface.stdout)["surface_inventory"]["surfaces"]
    server = next(item for item in surfaces if item["surface"] == "mcp_server_reference")
    assert server["command_basename"] == "<redacted-command>"
    assert server["env_vars"] == ["<redacted-env>"]
    assert server["remote_host"] == "<redacted-host>"
    assert mcp.returncode == 0
    assert report.returncode == 0
    combined = surface.stdout + mcp.stdout + report.stdout
    for forbidden in (
        secret_command,
        secret_host,
        secret_host.lower(),
        local_env_key,
        str(tmp_path),
    ):
        assert forbidden not in combined

def test_mcp_check_cli_flags_sanitized_mcp_risky_patterns(tmp_path: Path) -> None:
    fake_token = "github_pat_" + ("0" * 20)
    raw_command = "npx -y @vendor/browser-mcp --token sk-exampleSecretValue123 --root /home/alice/private"
    write(
        tmp_path / ".mcp.json",
        json.dumps(
            {
                "mcpServers": {
                    "browser": {
                        "command": raw_command,
                        "args": ["@vendor/browser-mcp@latest"],
                        "env": {"GITHUB_TOKEN": fake_token},
                    }
                }
            }
        ),
    )

    result = run_cli("mcp", "check", "--root", str(tmp_path), "--json")

    assert result.returncode == 1
    payload = json.loads(result.stdout)
    assert payload["scanner"] == "mcp"
    assert payload["mcp_config"]["status"] == "violation"
    assert payload["mcp_config"]["checked_count"] == 2
    reasons = {item["reason"] for item in payload["mcp_config"]["findings"]}
    assert reasons == {
        "filesystem_root_reference",
        "inline_authorization_value",
        "secret_shaped_inline_value",
        "unpinned_package",
    }
    assert payload["mcp_config"]["findings"][0]["owasp_agentic_risk_themes"]
    assert raw_command not in result.stdout
    assert "sk-exampleSecretValue123" not in result.stdout
    assert fake_token not in result.stdout
    assert "/home/alice/private" not in result.stdout
    assert str(tmp_path) not in result.stdout

def test_mcp_check_cli_flags_static_auth_scope_and_url_scheme_without_raw_values(tmp_path: Path) -> None:
    raw_url = "javascript:alert('private-host')"
    raw_token = "literal-admin-token"
    raw_query_token = "query-admin-token"
    raw_scope = "repo admin"
    write(
        tmp_path / ".mcp.json",
        json.dumps(
            {
                "mcpServers": {
                    "auth-review": {
                        "type": "http",
                        "url": raw_url,
                        "accessToken": raw_token,
                        "oauthScopes": [raw_scope],
                    },
                    "query-auth": {
                        "type": "http",
                        "url": f"https://mcp.example.test/sse?accessToken={raw_query_token}",
                    }
                }
            }
        ),
    )

    result = run_cli("mcp", "check", "--root", str(tmp_path), "--json")

    assert result.returncode == 1
    payload = json.loads(result.stdout)
    reasons = {item["reason"] for item in payload["mcp_config"]["findings"]}
    assert reasons == {
        "broad_authorization_scope",
        "inline_authorization_value",
        "unsafe_url_scheme",
    }
    severities = {item["reason"]: item["severity"] for item in payload["mcp_config"]["findings"]}
    assert severities["inline_authorization_value"] == "high"
    assert any(
        item["reason"] == "inline_authorization_value" and item["server_name"] == "query-auth"
        for item in payload["mcp_config"]["findings"]
    )
    assert all(item["owasp_agentic_risk_themes"] for item in payload["mcp_config"]["findings"])
    for forbidden in (raw_url, raw_token, raw_query_token, raw_scope, "private-host", str(tmp_path)):
        assert forbidden not in result.stdout

def test_mcp_check_cli_redacts_sensitive_server_names(tmp_path: Path) -> None:
    secret_server = "github_pat_" + ("0" * 20)
    local_server = "/home/alice/private"
    write(
        tmp_path / ".mcp.json",
        json.dumps(
            {
                "mcpServers": {
                    secret_server: {"command": "npx", "args": ["secret-mcp@latest"]},
                    local_server: {"command": "npx", "args": ["local-mcp@latest"]},
                }
            }
        ),
    )

    result = run_cli("mcp", "check", "--root", str(tmp_path), "--json")

    assert result.returncode == 1
    payload = json.loads(result.stdout)
    server_names = {item.get("server_name") for item in payload["mcp_config"]["findings"]}
    assert server_names == {"<redacted-server>"}
    assert secret_server not in result.stdout
    assert local_server not in result.stdout
    assert str(tmp_path) not in result.stdout

def test_mcp_check_cli_flags_parse_errors(tmp_path: Path) -> None:
    write(tmp_path / ".mcp.json", "{not json")

    result = run_cli("mcp", "check", "--root", str(tmp_path), "--json")

    assert result.returncode == 1
    payload = json.loads(result.stdout)
    finding = payload["mcp_config"]["findings"][0]
    assert finding["reason"] == "parse_error"
    assert finding["surface"] == "mcp_config"
    assert finding["path"] == ".mcp.json"
    assert finding["owasp_agentic_risk_themes"] == [
        {"id": "ASI04", "name": "Agentic Supply Chain Vulnerabilities"}
    ]
    assert "{not json" not in result.stdout
    assert str(tmp_path) not in result.stdout
