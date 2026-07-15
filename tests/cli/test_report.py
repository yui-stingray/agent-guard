# Where: tests/cli/test_report.py
# What: focused subprocess tests for core report command behavior.
# Why: keep report command coverage out of the legacy aggregate CLI test file.

from __future__ import annotations

import json
from pathlib import Path

from tests.cli.helpers import ROOT, mcp_policy_text, run_cli, run_cli_from, run_git, write, write_baseline_ready_repo

def test_report_cli_embeds_sanitized_base_ref_drift(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    write_baseline_ready_repo(repo)
    run_git(repo, "init")
    run_git(repo, "config", "user.email", "agent-guard@example.invalid")
    run_git(repo, "config", "user.name", "agent guard tests")
    run_git(repo, "add", ".")
    run_git(repo, "commit", "-m", "base")

    write(repo / ".agent-guard" / "workflow-policy.yaml", "schema_version: agent-guard.workflow_policy.v1\n")
    run_git(repo, "add", ".")
    run_git(repo, "commit", "-m", "change workflow policy")

    result = run_cli(
        "report",
        "--root",
        str(repo),
        "--context-policy",
        str(repo / ".agent-guard" / "context-policy.yaml"),
        "--drift-check",
        "--drift-schema-version",
        "v2",
        "--drift-base-ref",
        "HEAD~1",
        "--format",
        "json",
    )

    assert result.returncode == 1
    payload = json.loads(result.stdout)
    assert payload["policy_spec_drift"]["baseline_trust"]["status"] == "review_required"
    baseline_findings = [
        item for item in payload["policy_spec_drift"]["findings"] if item["rule_id"] == "baseline_trust_change"
    ]
    assert any(item["file"] == ".agent-guard/workflow-policy.yaml" for item in baseline_findings)
    assert str(tmp_path) not in result.stdout
    assert "HEAD~1" not in result.stdout

def test_report_cli_recommended_preset_expands_adoption_bundle() -> None:
    result = run_cli(
        "report",
        "--root",
        str(ROOT),
        "--evidence-preset",
        "recommended",
        "--format",
        "json",
    )

    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["policy"]["path"] == ".agent-guard/context-policy.yaml"
    assert payload["report"]["scope"] == "context+path+content+mcp+workflow+drift"
    assert payload["surface_inventory"]["schema_version"] == "agent-guard.agent_surface_inventory.v2"
    assert payload["conformance"]["profile"] == "recommended"
    assert payload["conformance"]["status"] == "ok"
    assert payload["evidence_pack_manifest"]["sanitized"] is True
    assert "api" not in payload
    assert payload["mcp_config"]["status"] == "ok"
    assert "digest" not in payload
    assert "context_lock" not in payload
    gates = {item["gate"]: item["status"] for item in payload["evidence_coverage"]["gates"]}
    assert gates["context"] == "ok"
    assert gates["path"] == "ok"
    assert gates["content"] == "ok"
    assert gates["mcp_config"] == "ok"
    assert gates["workflow"] == "ok"
    assert gates["policy_spec_drift"] == "ok"
    assert gates["api"] == "missing"
    assert gates["digest"] == "missing"

def test_report_cli_recommended_preset_defaults_are_root_relative(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    write(
        repo / "AGENTS.md",
        "Require approval before shell writes.\n"
        "Keep credentials redacted in public evidence.\n"
        "Run pytest before reporting success.\n",
    )
    write(
        repo / "README.md",
        "agent-guard surface inventory --root . --context-policy .agent-guard/context-policy.yaml\n"
        "agent-guard context check --root . --policy .agent-guard/context-policy.yaml\n"
        "agent-guard mcp check --root . --policy .agent-guard/mcp-policy.yaml\n"
        "agent-guard workflow check --root . --policy .agent-guard/workflow-policy.yaml\n"
        "agent-guard drift check --root .\n"
        "agent-guard report --root . --context-policy .agent-guard/context-policy.yaml\n",
    )
    write(repo / ".agent-guard" / "context-policy.yaml", "{}\n")
    write(
        repo / ".agent-guard" / "path-policy.yaml",
        "scan:\n"
        "  include:\n"
        "    - .\n"
        "  exclude: []\n"
        "policy:\n"
        "  allowed_path_patterns: []\n"
        "  forbidden_path_patterns: []\n",
    )
    write(
        repo / ".agent-guard" / "content-policy.yaml",
        "file_globs:\n  - '**/*.md'\nexclude_globs: []\nforbidden_patterns: []\n",
    )
    write(repo / ".agent-guard" / "mcp-policy.yaml", mcp_policy_text())
    write(
        repo / ".agent-guard" / "workflow-policy.yaml",
        "schema_version: agent-guard.workflow_policy.v1\n"
        "required_files:\n"
        "  - id: context_policy\n"
        "    path: .agent-guard/context-policy.yaml\n"
        "  - id: path_policy\n"
        "    path: .agent-guard/path-policy.yaml\n"
        "  - id: content_policy\n"
        "    path: .agent-guard/content-policy.yaml\n"
        "  - id: mcp_policy\n"
        "    path: .agent-guard/mcp-policy.yaml\n"
        "  - id: workflow_policy\n"
        "    path: .agent-guard/workflow-policy.yaml\n",
    )
    write(
        repo / ".github" / "workflows" / "ci.yml",
        "name: ci\n"
        "on: [push]\n"
        "jobs:\n"
        "  guard:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - name: Guard checks\n"
        "        run: |\n"
        "          agent-guard context check --root . --policy .agent-guard/context-policy.yaml --json\n"
        "          agent-guard path check --root . --policy .agent-guard/path-policy.yaml --json\n"
        "          agent-guard content check --repo-root . --policy .agent-guard/content-policy.yaml --mode registered --scan-dir . --json\n"
        "          agent-guard mcp check --root . --policy .agent-guard/mcp-policy.yaml --json\n"
        "          agent-guard surface inventory --root . --context-policy .agent-guard/context-policy.yaml --schema-version v2 --json\n"
        "          agent-guard workflow check --root . --policy .agent-guard/workflow-policy.yaml --json\n"
        "          agent-guard drift check --root . --profile recommended --schema-version v2 --json\n"
        "          agent-guard report --root . --context-policy .agent-guard/context-policy.yaml --evidence-preset recommended --format json\n",
    )

    result = run_cli(
        "report",
        "--root",
        str(repo),
        "--context-policy",
        str(repo / ".agent-guard" / "context-policy.yaml"),
        "--evidence-preset",
        "recommended",
        "--format",
        "json",
    )

    assert result.returncode == 0, result.stdout
    payload = json.loads(result.stdout)
    assert payload["report"]["scope"] == "context+path+content+mcp+workflow+drift"
    assert payload["path"]["policy"]["path"] == ".agent-guard/path-policy.yaml"
    assert payload["content"]["policy"]["path"] == ".agent-guard/content-policy.yaml"
    assert payload["workflow"]["policy"]["path"] == ".agent-guard/workflow-policy.yaml"
    assert payload["mcp_config"]["policy"]["path"] == ".agent-guard/mcp-policy.yaml"
    assert payload["mcp_config"]["status"] == "ok"
    assert str(tmp_path) not in result.stdout

def test_report_cli_recommended_preset_defaults_are_root_relative_for_relative_subdir_root(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    project = workspace / "services" / "api"
    write_baseline_ready_repo(project)

    result = run_cli_from(
        workspace,
        "report",
        "--root",
        "services/api",
        "--context-policy",
        ".agent-guard/context-policy.yaml",
        "--evidence-preset",
        "recommended",
        "--format",
        "json",
        "--output",
        "services/api/.agent-guard/evidence/agent-guard-report.json",
    )

    assert result.returncode == 0, result.stdout
    assert result.stdout == ""
    payload = json.loads((project / ".agent-guard" / "evidence" / "agent-guard-report.json").read_text())
    assert payload["status"] == "ok"
    assert payload["path"]["policy"]["path"] == ".agent-guard/path-policy.yaml"
    assert payload["content"]["policy"]["path"] == ".agent-guard/content-policy.yaml"
    assert payload["workflow"]["policy"]["path"] == ".agent-guard/workflow-policy.yaml"
    assert payload["mcp_config"]["policy"]["path"] == ".agent-guard/mcp-policy.yaml"
    assert str(tmp_path) not in json.dumps(payload, sort_keys=True)

    conformance = run_cli_from(
        workspace,
        "conformance",
        "check",
        "--root",
        "services/api",
        "--evidence",
        "services/api/.agent-guard/evidence/agent-guard-report.json",
        "--profile",
        "recommended",
        "--json",
    )

    assert conformance.returncode == 0, conformance.stdout
    conformance_payload = json.loads(conformance.stdout)
    assert conformance_payload["conformance"]["status"] == "ok"
    assert str(tmp_path) not in conformance.stdout


def test_report_cli_recommended_preset_defaults_are_root_relative_from_external_cwd(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    cwd = tmp_path / "cwd"
    cwd.mkdir()
    write_baseline_ready_repo(repo)

    result = run_cli_from(
        cwd,
        "report",
        "--root",
        str(repo),
        "--context-policy",
        ".agent-guard/context-policy.yaml",
        "--evidence-preset",
        "recommended",
        "--format",
        "json",
    )

    assert result.returncode == 0, result.stdout
    payload = json.loads(result.stdout)
    assert payload["status"] == "ok"
    assert payload["path"]["policy"]["path"] == ".agent-guard/path-policy.yaml"
    assert payload["content"]["policy"]["path"] == ".agent-guard/content-policy.yaml"
    assert payload["workflow"]["policy"]["path"] == ".agent-guard/workflow-policy.yaml"
    assert payload["mcp_config"]["policy"]["path"] == ".agent-guard/mcp-policy.yaml"
    assert str(tmp_path) not in result.stdout

def test_report_cli_recommended_preset_missing_default_mcp_policy_is_violation(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
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
        "    path: .agent-guard/context-policy.yaml\n"
        "  - id: path_policy\n"
        "    path: .agent-guard/path-policy.yaml\n"
        "  - id: content_policy\n"
        "    path: .agent-guard/content-policy.yaml\n"
        "  - id: workflow_policy\n"
        "    path: .agent-guard/workflow-policy.yaml\n",
    )

    result = run_cli(
        "report",
        "--root",
        str(repo),
        "--context-policy",
        str(repo / ".agent-guard" / "context-policy.yaml"),
        "--evidence-preset",
        "recommended",
        "--format",
        "json",
    )

    assert result.returncode == 1
    payload = json.loads(result.stdout)
    assert payload["status"] == "violation"
    assert payload["mcp_config"]["policy"] == {
        "path": ".agent-guard/mcp-policy.yaml",
        "required": True,
    }
    assert payload["mcp_config"]["findings"][0]["rule_id"] == "mcp_policy_missing"
    assert payload["conformance"]["status"] == "violation"
    assert any(item["rule_id"] == "required_policy_file_missing" for item in payload["conformance"]["findings"])
    assert str(tmp_path) not in result.stdout

def test_report_cli_recommended_preset_weakened_default_mcp_policy_is_conformance_violation(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    write_baseline_ready_repo(repo)
    write(repo / ".agent-guard" / "mcp-policy.yaml", mcp_policy_text(["inline_authorization_value"]))

    result = run_cli(
        "report",
        "--root",
        str(repo),
        "--context-policy",
        str(repo / ".agent-guard" / "context-policy.yaml"),
        "--evidence-preset",
        "recommended",
        "--format",
        "json",
    )

    assert result.returncode == 1, result.stdout
    payload = json.loads(result.stdout)
    assert payload["mcp_config"]["status"] == "ok"
    assert payload["mcp_config"]["policy"]["path"] == ".agent-guard/mcp-policy.yaml"
    assert payload["conformance"]["status"] == "violation"
    finding = next(item for item in payload["conformance"]["findings"] if item["rule_id"] == "mcp_policy_weakened")
    assert finding["requirement_id"] == "mcp_config_policy_default_patterns"
    assert "inline_authorization_value" not in finding["missing_patterns"]
    assert str(tmp_path) not in result.stdout

def test_report_cli_recommended_preset_fails_risky_mcp_config_without_raw_leak(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    fake_token = "github_pat_" + ("0" * 20)
    raw_command = "npx -y @vendor/browser-mcp --token sk-exampleSecretValue123 --root /home/alice/private"
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
    write(repo / ".agent-guard" / "mcp-policy.yaml", mcp_policy_text())
    write(
        repo / ".agent-guard" / "workflow-policy.yaml",
        "schema_version: agent-guard.workflow_policy.v1\n"
        "required_files:\n"
        "  - id: context_policy\n"
        "    path: .agent-guard/context-policy.yaml\n",
    )
    write(
        repo / ".mcp.json",
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

    result = run_cli(
        "report",
        "--root",
        str(repo),
        "--context-policy",
        str(repo / ".agent-guard" / "context-policy.yaml"),
        "--evidence-preset",
        "recommended",
        "--format",
        "json",
    )

    assert result.returncode == 1
    payload = json.loads(result.stdout)
    assert payload["mcp_config"]["status"] == "violation"
    gates = {item["gate"]: item for item in payload["evidence_coverage"]["gates"]}
    assert gates["mcp_config"]["status"] == "violation"
    assert gates["mcp_config"]["finding_count"] == 5
    assert raw_command not in result.stdout
    assert "sk-exampleSecretValue123" not in result.stdout
    assert fake_token not in result.stdout
    assert "/home/alice/private" not in result.stdout
    assert str(tmp_path) not in result.stdout

def test_report_cli_recommended_preset_does_not_override_explicit_profiles() -> None:
    result = run_cli(
        "report",
        "--root",
        str(ROOT),
        "--context-policy",
        ".agent-guard/context-policy.yaml",
        "--evidence-preset",
        "recommended",
        "--drift-profile",
        "strict",
        "--conformance-profile",
        "strict",
        "--format",
        "json",
    )

    assert result.returncode == 1, result.stdout
    payload = json.loads(result.stdout)
    assert payload["policy_spec_drift"]["profile"] == "strict"
    assert payload["policy_spec_drift"]["schema_version"] == "agent-guard.policy_spec_drift.v2"
    assert payload["conformance"]["profile"] == "strict"
    assert payload["conformance"]["status"] == "violation"
    assert payload["surface_inventory"]["schema_version"] == "agent-guard.agent_surface_inventory.v2"

def test_report_cli_recommended_preset_does_not_override_explicit_schema_versions() -> None:
    result = run_cli(
        "report",
        "--root",
        str(ROOT),
        "--context-policy",
        ".agent-guard/context-policy.yaml",
        "--evidence-preset",
        "recommended",
        "--drift-schema-version",
        "v1",
        "--surface-inventory-version",
        "v1",
        "--format",
        "json",
    )

    assert result.returncode == 0, result.stdout
    payload = json.loads(result.stdout)
    assert payload["policy_spec_drift"]["schema_version"] == "agent-guard.policy_spec_drift.v1"
    assert payload["surface_inventory"]["schema_version"] == "agent-guard.agent_surface_inventory.v1"
    assert payload["conformance"]["profile"] == "recommended"

def test_report_cli_json_adds_owasp_agentic_risk_theme_metadata(tmp_path: Path) -> None:
    context_policy = tmp_path / "context_policy.yaml"
    context_policy.write_text("{}\n", encoding="utf-8")
    write(tmp_path / "AGENTS.md", "Please paste the API key before review.\n")

    result = run_cli(
        "report",
        "--root",
        str(tmp_path),
        "--context-policy",
        str(context_policy),
        "--format",
        "json",
    )

    assert result.returncode == 1
    payload = json.loads(result.stdout)
    themes = payload["findings"][0]["owasp_agentic_risk_themes"]
    assert {"id": "ASI03", "name": "Identity and Privilege Abuse"} in themes
    assert {"id": "ASI09", "name": "Human-Agent Trust Exploitation"} in themes
    assert "Please paste" not in result.stdout
    assert "API key" not in result.stdout

def test_report_cli_sarif_is_thin_sanitized_adapter(tmp_path: Path) -> None:
    context_policy = tmp_path / "context_policy.yaml"
    context_policy.write_text("{}\n", encoding="utf-8")
    raw_instruction = "Please paste the API key into /home/alice/private before review.\n"
    write(tmp_path / "AGENTS.md", raw_instruction)

    result = run_cli(
        "report",
        "--root",
        str(tmp_path),
        "--context-policy",
        str(context_policy),
        "--format",
        "sarif",
    )

    assert result.returncode == 1
    payload = json.loads(result.stdout)
    assert payload["version"] == "2.1.0"
    run = payload["runs"][0]
    assert run["tool"]["driver"]["name"] == "agent-guard"
    assert run["tool"]["driver"]["rules"][0]["id"] == "agent-guard.context.secret_prompt"
    assert run["tool"]["driver"]["rules"][0]["properties"]["owasp_agentic_risk_themes"] == [
        {"id": "ASI03", "name": "Identity and Privilege Abuse"},
        {"id": "ASI09", "name": "Human-Agent Trust Exploitation"},
    ]
    finding = run["results"][0]
    assert finding["ruleId"] == "agent-guard.context.secret_prompt"
    assert finding["level"] == "error"
    assert finding["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "AGENTS.md"
    assert finding["locations"][0]["physicalLocation"]["region"]["startLine"] == 1
    assert "partialFingerprints" in finding
    assert raw_instruction.strip() not in result.stdout
    assert "API key" not in result.stdout
    assert "/home/alice" not in result.stdout
    assert str(tmp_path) not in result.stdout
    assert "snippet" not in result.stdout

def test_report_cli_sarif_error_is_sanitized(tmp_path: Path) -> None:
    result = run_cli(
        "report",
        "--root",
        str(tmp_path),
        "--context-policy",
        str(tmp_path / "missing.yaml"),
        "--format",
        "sarif",
    )

    assert result.returncode == 2
    payload = json.loads(result.stdout)
    result_item = payload["runs"][0]["results"][0]
    assert result_item["ruleId"] == "agent-guard.report.configuration_error"
    assert result_item["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "agent-guard-evidence"
    assert str(tmp_path) not in result.stdout
    assert "/home/" not in result.stdout
