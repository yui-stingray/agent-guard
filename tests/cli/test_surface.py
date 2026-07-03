# Where: tests/cli/test_surface.py
# What: focused subprocess tests for the surface CLI group.
# Why: keep extracted surface subcommand coverage close to its module.

from __future__ import annotations

import json
from pathlib import Path

from tests.cli.helpers import assert_shared_envelope, run_cli, write


def test_surface_inventory_cli_json_omits_raw_context_and_workflow_commands(tmp_path: Path) -> None:
    policy = tmp_path / "context_policy.yaml"
    policy.write_text("{}\n", encoding="utf-8")
    raw_context = "Require approval before shell writes. fixture marker surface\n"
    raw_command = "python -m agent_guard.cli report --root . --context-policy context_policy.yaml --format json"
    write(tmp_path / "AGENTS.md", raw_context)
    write(tmp_path / ".agent-guard" / "workflow-policy.yaml", "schema_version: agent-guard.workflow_policy.v1\n")
    write(
        tmp_path / ".github" / "workflows" / "ci.yml",
        "name: ci\n"
        "jobs:\n"
        "  test:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        f"      - run: {raw_command}\n",
    )

    result = run_cli(
        "surface",
        "inventory",
        "--root",
        str(tmp_path),
        "--context-policy",
        str(policy),
        "--json",
    )

    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert_shared_envelope(
        payload,
        scanner="surface",
        status="ok",
        exit_code=0,
        finding_count=0,
        scanned_unit="surfaces",
    )
    inventory = payload["surface_inventory"]
    assert inventory["schema_version"] == "agent-guard.agent_surface_inventory.v1"
    surfaces = inventory["surfaces"]
    assert {"surface": "agent_context", "path": "AGENTS.md", "kind": "agents_md", "status": "scanned", "size_bytes": len(raw_context.encode("utf-8")), "line_count": 1} in surfaces
    workflow_refs = [item for item in surfaces if item["surface"] == "workflow_reference"]
    assert workflow_refs == [
        {
            "surface": "workflow_reference",
            "path": ".github/workflows/ci.yml",
            "kind": "agent_guard_command",
            "status": "referenced",
            "job_id": "test",
            "step_index": 1,
            "command": {"scanner": "report", "command": ""},
        }
    ]
    assert raw_context.strip() not in result.stdout
    assert raw_command not in result.stdout
    assert "fixture marker surface" not in result.stdout
    assert str(tmp_path) not in result.stdout


def test_surface_inventory_cli_v2_adds_documented_and_artifact_metadata(tmp_path: Path) -> None:
    policy = tmp_path / "context_policy.yaml"
    policy.write_text("{}\n", encoding="utf-8")
    raw_command = (
        "agent-guard report --root . --context-policy .agent-guard/context-policy.yaml "
        "--format json --output .agent-guard/evidence/agent-guard-report.json"
    )
    raw_windows_command = (
        "agent-guard report --root . --context-policy .agent-guard/context-policy.yaml "
        r"--format json --output C:\Users\alice\secret\agent-guard-report.json"
    )
    write(tmp_path / "AGENTS.md", "Require approval before shell writes.\n")
    write(tmp_path / "README.md", "agent-guard drift check --root . --json\n")
    write(
        tmp_path / ".github" / "workflows" / "ci.yml",
        "name: ci\n"
        "jobs:\n"
        "  test:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        f"      - run: {raw_command}\n"
        f"      - run: {raw_windows_command}\n"
        "      - uses: actions/upload-artifact@v7\n"
        "        with:\n"
        "          path: .agent-guard/evidence/\n",
    )

    result = run_cli(
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

    assert result.returncode == 0
    payload = json.loads(result.stdout)
    inventory = payload["surface_inventory"]
    assert inventory["schema_version"] == "agent-guard.agent_surface_inventory.v2"
    surfaces = inventory["surfaces"]
    assert any(item["surface"] == "documented_guard_command" for item in surfaces)
    artifact_refs = [item for item in surfaces if item["surface"] == "evidence_artifact_reference"]
    assert {item["artifact_path"] for item in artifact_refs} == {
        ".agent-guard/evidence",
        ".agent-guard/evidence/agent-guard-report.json",
        "agent-guard-report.json",
    }
    assert raw_command not in result.stdout
    assert raw_windows_command not in result.stdout
    assert r"C:\Users\alice" not in result.stdout
    assert str(tmp_path) not in result.stdout


def test_surface_inventory_cli_v2_ignores_prose_agent_guard_comparison(tmp_path: Path) -> None:
    policy = tmp_path / "context_policy.yaml"
    policy.write_text("{}\n", encoding="utf-8")
    write(tmp_path / "AGENTS.md", "Require approval before shell writes.\n")
    write(
        tmp_path / "README.md",
        "between agent-guard and agent-audit tools\n"
        "agent-guard context check --root .\n",
    )

    result = run_cli(
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

    assert result.returncode == 0
    surfaces = json.loads(result.stdout)["surface_inventory"]["surfaces"]
    documented_commands = [
        item["command"] for item in surfaces if item["surface"] == "documented_guard_command"
    ]
    assert documented_commands == [{"scanner": "context", "command": "check"}]
    assert {"scanner": "and", "command": "agent-audit"} not in documented_commands


def test_surface_inventory_cli_v2_adds_agent_config_and_mcp_metadata(tmp_path: Path) -> None:
    policy = tmp_path / "context_policy.yaml"
    policy.write_text("{}\n", encoding="utf-8")
    fake_token = "github_pat_" + ("0" * 20)
    write(tmp_path / "AGENTS.md", "Require approval before shell writes.\n")
    write(tmp_path / ".github" / "skills" / "repo-review" / "SKILL.md", "secret skill body marker\n")
    write(tmp_path / ".claude" / "agents" / "reviewer.md", "agent prompt marker\n")
    write(tmp_path / ".claude" / "commands" / "review.md", "command prompt marker\n")
    write(tmp_path / ".cursor" / "hooks.json", '{"hook": "private hook marker"}\n')
    write(
        tmp_path / ".mcp.json",
        json.dumps(
            {
                "mcpServers": {
                    "browser": {
                        "command": "npx -y @vendor/browser-mcp --token sk-exampleSecretValue123 --root /home/alice/private",
                        "args": ["@vendor/browser-mcp@latest"],
                        "env": {"GITHUB_TOKEN": fake_token},
                    }
                }
            }
        ),
    )
    write(
        tmp_path / ".codex" / "config.toml",
        "[mcp_servers.docs]\n"
        'command = "uvx"\n'
        'args = ["docs-server==1.2.3"]\n'
        'env = { API_KEY = "${API_KEY}" }\n',
    )
    write(
        tmp_path / ".vscode" / "mcp.json",
        json.dumps({"servers": {"remote": {"type": "http", "url": "https://mcp.example.com/sse"}}}),
    )

    result = run_cli(
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

    assert result.returncode == 0, result.stdout + result.stderr
    payload = json.loads(result.stdout)
    surfaces = payload["surface_inventory"]["surfaces"]
    by_surface = payload["surface_inventory"]["summary"]["by_surface"]
    assert by_surface["agent_skill"] == 1
    assert by_surface["agent_profile"] == 1
    assert by_surface["agent_command"] == 1
    assert by_surface["agent_hook_config"] == 1
    assert by_surface["mcp_config"] == 3
    assert by_surface["mcp_server_reference"] == 3
    assert {
        "surface": "agent_skill",
        "path": ".github/skills/repo-review",
        "kind": "github_copilot_skill",
        "status": "present",
        "file_count": 1,
    } in surfaces

    servers = {item["server_name"]: item for item in surfaces if item["surface"] == "mcp_server_reference"}
    assert servers["browser"]["transport"] == "stdio"
    assert servers["browser"]["command_basename"] == "npx"
    assert servers["browser"]["package_manager"] == "npx"
    assert servers["browser"]["version_pinned"] is False
    assert servers["browser"]["env_vars"] == ["GITHUB_TOKEN"]
    assert servers["browser"]["filesystem_root"] is True
    assert set(servers["browser"]["risky_patterns"]) == {
        "filesystem_root_reference",
        "inline_authorization_value",
        "latest_package",
        "secret_shaped_inline_value",
        "unpinned_package",
    }
    assert servers["docs"]["command_basename"] == "uvx"
    assert servers["docs"]["version_pinned"] is True
    assert servers["docs"]["env_vars"] == ["API_KEY"]
    assert "risky_patterns" not in servers["docs"]
    assert servers["remote"]["transport"] == "http"
    assert servers["remote"]["remote_host"] == "mcp.example.com"

    for forbidden in (
        fake_token,
        "/home/alice/private",
        "sk-exampleSecretValue123",
        "@vendor/browser-mcp --token",
        "secret skill body marker",
        "agent prompt marker",
        "command prompt marker",
        "private hook marker",
        "https://mcp.example.com/sse",
        str(tmp_path),
    ):
        assert forbidden not in result.stdout

def test_surface_inventory_cli_v2_redacts_sensitive_mcp_server_names(tmp_path: Path) -> None:
    policy = tmp_path / "context_policy.yaml"
    policy.write_text("{}\n", encoding="utf-8")
    secret_server = "github_pat_" + ("0" * 20)
    local_server = "/home/alice/private"
    write(tmp_path / "AGENTS.md", "Require approval before shell writes.\n")
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

    result = run_cli(
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

    assert result.returncode == 0
    surfaces = json.loads(result.stdout)["surface_inventory"]["surfaces"]
    server_names = [item["server_name"] for item in surfaces if item["surface"] == "mcp_server_reference"]
    assert server_names == ["<redacted-server>", "<redacted-server>"]
    assert secret_server not in result.stdout
    assert local_server not in result.stdout
    assert str(tmp_path) not in result.stdout
