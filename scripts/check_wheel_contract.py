"""Where: scripts/check_wheel_contract.py
What: install the built wheel into an isolated venv and verify the public contract.
Why: editable installs can hide packaging mistakes; releases must prove the wheel works.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import tempfile
import textwrap
import tomllib
import venv
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DIST = ROOT / "dist"
EXPECTED_EXPORTS = {
    "scan_urls",
    "ApiGuardFinding",
    "scan_context_files",
    "ContextGuardFinding",
    "scan_paths",
    "scan_content_paths",
    "ContentGuardFinding",
    "scan_repo_paths",
    "PathGuardFinding",
    "scan_digests",
    "DigestGuardFinding",
    "build_mcp_config_report",
    "scan_workflow_policy",
    "WorkflowGuardFinding",
}


def project_version() -> str:
    """Return pyproject.toml [project].version."""
    with (ROOT / "pyproject.toml").open("rb") as handle:
        return str(tomllib.load(handle)["project"]["version"])


def project_requires_python() -> str:
    """Return pyproject.toml [project].requires-python."""
    with (ROOT / "pyproject.toml").open("rb") as handle:
        return str(tomllib.load(handle)["project"]["requires-python"])


def find_wheel(version: str) -> Path:
    """Return the built wheel for the current project version."""
    wheels = sorted(DIST.glob(f"yui_agent_guard-{version}-*.whl"))
    if len(wheels) != 1:
        raise RuntimeError(
            f"expected exactly one yui_agent_guard {version} wheel in {DIST}, got {len(wheels)}"
        )
    return wheels[0]


def run(command: list[str], *, cwd: Path) -> subprocess.CompletedProcess[str]:
    """Run a subprocess and return its completed process."""
    result = subprocess.run(command, cwd=cwd, check=False, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode != 0:
        raise RuntimeError(
            f"command failed with exit {result.returncode}: {command!r}\n"
            f"stdout={result.stdout!r}\nstderr={result.stderr!r}"
        )
    return result


def main() -> int:
    version = project_version()
    requires_python = project_requires_python()
    wheel = find_wheel(version)
    with tempfile.TemporaryDirectory(prefix="agent-guard-wheel-") as temp_dir:
        temp = Path(temp_dir)
        venv_dir = temp / "venv"
        venv.EnvBuilder(with_pip=True).create(venv_dir)
        python = venv_dir / "bin" / "python"
        run([str(python), "-m", "pip", "install", "--quiet", str(wheel)], cwd=temp)
        smoke = textwrap.dedent(
            f"""
            import json
            import agent_guard
            from importlib import resources
            from importlib.metadata import metadata

            expected_exports = {sorted(EXPECTED_EXPORTS)!r}
            assert sorted(agent_guard.__all__) == expected_exports
            assert agent_guard.__version__ == {version!r}
            assert metadata("yui-agent-guard")["Requires-Python"] == {requires_python!r}
            assert agent_guard.scan_paths is agent_guard.scan_content_paths
            for name in expected_exports:
                assert getattr(agent_guard, name) is not None

            schema_names = {{
                "agent-guard.result.v1.schema.json": "agent-guard.result.v1",
                "agent-guard.context_inventory.v1.schema.json": "agent-guard.context_inventory.v1",
                "agent-guard.context_lock_coverage.v1.schema.json": "agent-guard.context_lock_coverage.v1",
                "agent-guard.report_evidence.v1.schema.json": "agent-guard.report_evidence.v1",
                "agent-guard.conformance.v1.schema.json": "agent-guard.conformance.v1",
                "agent-guard.evidence_pack_manifest.v1.schema.json": "agent-guard.evidence_pack_manifest.v1",
                "agent-guard.surface_delta.v1.schema.json": "agent-guard.surface_delta.v1",
            }}
            schema_dir = resources.files("agent_guard.schemas")
            for filename, schema_version in schema_names.items():
                schema = json.loads((schema_dir / filename).read_text(encoding="utf-8"))
                assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
                if filename == "agent-guard.report_evidence.v1.schema.json":
                    assert schema["properties"]["report"]["properties"]["schema_version"]["const"] == schema_version
                    assert "surface_inventory" in schema["allOf"][0]["then"]["required"]
                    assert "evidence_coverage" in schema["allOf"][0]["then"]["required"]
                    assert "conformance" in schema["properties"]
                    assert "evidence_pack_manifest" in schema["properties"]
                    assert schema["properties"]["conformance"]["properties"]["profile"]["enum"] == [
                        "minimal",
                        "recommended",
                        "strict",
                    ]
                    artifact_role = schema["properties"]["evidence_pack_manifest"]["properties"]["artifacts"]["items"]["properties"]["role"]
                    assert "agent-policy-audit-event" in artifact_role["enum"]
                    surface_schema = schema["properties"]["surface_inventory"]["properties"]["schema_version"]
                    assert "agent-guard.agent_surface_inventory.v2" in surface_schema["enum"]
                else:
                    assert schema["properties"]["schema_version"]["const"] == schema_version
            """
        )
        run([str(python), "-c", smoke], cwd=temp)

        repo = temp / "repo"
        repo.mkdir()
        policy = repo / "path-policy.yaml"
        policy.write_text(
            "scan:\n"
            "  include:\n"
            "    - .\n"
            "  exclude: []\n"
            "policy:\n"
            "  allowed_path_patterns:\n"
            "    - '(^|/)\\.env\\.example$'\n"
            "  forbidden_path_patterns:\n"
            "    - id: env_file\n"
            "      severity: high\n"
            "      pattern: '(^|/)\\.env(\\..+)?$'\n"
            "      message: 'env files are forbidden except .env.example'\n",
            encoding="utf-8",
        )
        (repo / ".env.example").write_text("TOKEN=\n", encoding="utf-8")
        cli = run(
            [
                str(python),
                "-m",
                "agent_guard.cli",
                "path",
                "check",
                "--root",
                str(repo),
                "--policy",
                str(policy),
                "--json",
            ],
            cwd=temp,
        )
        payload = json.loads(cli.stdout)
        assert payload["status"] == "ok"
        assert payload["scanner"] == "path"
        assert payload["finding_count"] == 0

        context_policy = repo / "context-policy.yaml"
        context_policy.write_text("{}\n", encoding="utf-8")
        agent_context = (
            "Require approval before shell writes.\n"
            "Keep credentials redacted in public evidence.\n"
            "Run pytest before reporting success.\n"
        )
        (repo / "AGENTS.md").write_text(agent_context, encoding="utf-8")
        init_cli = run(
            [
                str(python),
                "-m",
                "agent_guard.cli",
                "init",
                "--root",
                str(repo / "init-preview"),
                "--json",
            ],
            cwd=temp,
        )
        init_payload = json.loads(init_cli.stdout)
        assert init_payload["schema_version"] == "agent-guard.init_plan.v1"
        assert init_payload["mode"] == "print"
        assert not (repo / "init-preview" / ".agent-guard").exists()

        context_cli = run(
            [
                str(python),
                "-m",
                "agent_guard.cli",
                "context",
                "check",
                "--root",
                str(repo),
                "--policy",
                str(context_policy),
                "--json",
            ],
            cwd=temp,
        )
        context_payload = json.loads(context_cli.stdout)
        assert context_payload["status"] == "ok"
        assert context_payload["scanner"] == "context"
        assert context_payload["finding_count"] == 0

        digest_policy = repo / "digest-policy.yaml"
        agent_context_sha256 = hashlib.sha256(agent_context.encode("utf-8")).hexdigest()
        digest_policy.write_text(
            "checks:\n"
            "  - id: agent_context_pin\n"
            "    path: AGENTS.md\n"
            f"    sha256: '{agent_context_sha256}'\n",
            encoding="utf-8",
        )
        workflow_file = repo / ".github" / "workflows" / "ci.yml"
        workflow_file.parent.mkdir(parents=True, exist_ok=True)
        workflow_file.write_text(
            "name: ci\n"
            "jobs:\n"
            "  test:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - name: Run guard checks\n"
            "        run: |\n"
            "          python -m agent_guard.cli context check --root . --policy context-policy.yaml --json\n"
            "          python -m agent_guard.cli digest check --root . --policy digest-policy.yaml --json\n"
            "          python -m agent_guard.cli mcp check --root . --json\n",
            encoding="utf-8",
        )
        workflow_policy = repo / "workflow-policy.yaml"
        workflow_policy.write_text(
            "schema_version: agent-guard.workflow_policy.v1\n"
            "required_files:\n"
            "  - id: context_policy\n"
            "    path: context-policy.yaml\n"
            "  - id: digest_policy\n"
            "    path: digest-policy.yaml\n"
            "workflow_checks:\n"
            "  - id: ci_guard_smoke\n"
            "    path: .github/workflows/ci.yml\n"
            "    required_commands:\n"
            "      - id: context_guard\n"
            "        command: python -m agent_guard.cli context check\n"
            "      - id: digest_guard\n"
            "        command: python -m agent_guard.cli digest check\n"
            "      - id: mcp_config_guard\n"
            "        command: python -m agent_guard.cli mcp check\n",
            encoding="utf-8",
        )
        workflow_cli = run(
            [
                str(python),
                "-m",
                "agent_guard.cli",
                "workflow",
                "check",
                "--root",
                str(repo),
                "--policy",
                str(workflow_policy),
                "--json",
            ],
            cwd=temp,
        )
        workflow_payload = json.loads(workflow_cli.stdout)
        assert workflow_payload["status"] == "ok"
        assert workflow_payload["scanner"] == "workflow"
        assert workflow_payload["finding_count"] == 0

        surface_cli = run(
            [
                str(python),
                "-m",
                "agent_guard.cli",
                "surface",
                "inventory",
                "--root",
                str(repo),
                "--context-policy",
                str(context_policy),
                "--json",
            ],
            cwd=temp,
        )
        surface_payload = json.loads(surface_cli.stdout)
        assert surface_payload["status"] == "ok"
        assert surface_payload["scanner"] == "surface"
        assert surface_payload["surface_inventory"]["schema_version"] == "agent-guard.agent_surface_inventory.v1"
        surface_v2_cli = run(
            [
                str(python),
                "-m",
                "agent_guard.cli",
                "surface",
                "inventory",
                "--root",
                str(repo),
                "--context-policy",
                str(context_policy),
                "--schema-version",
                "v2",
                "--json",
            ],
            cwd=temp,
        )
        surface_v2_payload = json.loads(surface_v2_cli.stdout)
        assert surface_v2_payload["status"] == "ok"
        assert surface_v2_payload["surface_inventory"]["schema_version"] == "agent-guard.agent_surface_inventory.v2"

        (repo / "README.md").write_text(
            "agent-guard surface inventory --root . --context-policy .agent-guard/context-policy.yaml\n"
            "agent-guard context check --root . --policy .agent-guard/context-policy.yaml\n"
            "agent-guard context lock --root . --policy .agent-guard/context-policy.yaml --check --digest-policy .agent-guard/context-digest-policy.yaml\n"
            "agent-guard mcp check --root . --policy .agent-guard/mcp-policy.yaml\n"
            "agent-guard workflow check --root . --policy .agent-guard/workflow-policy.yaml\n"
            "agent-guard drift check --root .\n"
            "agent-guard report --root . --context-policy .agent-guard/context-policy.yaml --mcp-policy .agent-guard/mcp-policy.yaml\n",
            encoding="utf-8",
        )
        drift_policy_dir = repo / ".agent-guard"
        drift_policy_dir.mkdir(exist_ok=True)
        for source, destination in (
            (context_policy, drift_policy_dir / "context-policy.yaml"),
            (policy, drift_policy_dir / "path-policy.yaml"),
            (digest_policy, drift_policy_dir / "context-digest-policy.yaml"),
        ):
            destination.write_text(source.read_text(encoding="utf-8"), encoding="utf-8")
        (drift_policy_dir / "content-policy.yaml").write_text(
            "file_globs:\n  - '**/*.md'\nexclude_globs: []\nforbidden_patterns: []\n",
            encoding="utf-8",
        )
        (drift_policy_dir / "mcp-policy.yaml").write_text(
            "schema_version: agent-guard.mcp_policy.v1\n"
            "policy:\n"
            "  fail_on_parse_error: true\n"
            "  forbidden_risky_patterns:\n"
            "    - broad_authorization_scope\n"
            "    - filesystem_root_reference\n"
            "    - inline_authorization_value\n"
            "    - inline_env_value\n"
            "    - instruction_like_description\n"
            "    - latest_package\n"
            "    - secret_shaped_inline_value\n"
            "    - unsafe_url_scheme\n"
            "    - unpinned_package\n",
            encoding="utf-8",
        )
        (drift_policy_dir / "workflow-policy.yaml").write_text(
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
            encoding="utf-8",
        )
        drift_cli = run(
            [
                str(python),
                "-m",
                "agent_guard.cli",
                "drift",
                "check",
                "--root",
                str(repo),
                "--json",
            ],
            cwd=temp,
        )
        drift_payload = json.loads(drift_cli.stdout)
        assert drift_payload["status"] == "ok"
        assert drift_payload["scanner"] == "drift"

        report_cli = run(
            [
                str(python),
                "-m",
                "agent_guard.cli",
                "report",
                "--root",
                str(repo),
                "--context-policy",
                str(context_policy),
                "--digest-policy",
                str(digest_policy),
                "--workflow-policy",
                str(workflow_policy),
                "--drift-check",
            ],
            cwd=temp,
        )
        assert report_cli.stdout.startswith("# Agent Guard Evidence Report\n")
        assert "| Status | ok |" in report_cli.stdout
        assert "| Policy | context-policy.yaml |" in report_cli.stdout
        assert "| Digest policy | digest-policy.yaml |" in report_cli.stdout
        assert "| Digest checks | 1 |" in report_cli.stdout
        assert "| Workflow policy | workflow-policy.yaml |" in report_cli.stdout
        assert "| Workflow checks | 5 |" in report_cli.stdout
        assert "| Workflow drift findings | 0 |" in report_cli.stdout
        assert "| Policy/spec drift findings | 0 |" in report_cli.stdout
        assert agent_context_sha256 not in report_cli.stdout
        assert str(temp) not in report_cli.stdout

        report_output = repo / ".agent-guard" / "evidence" / "agent-guard-report.json"
        report_output_cli = run(
            [
                str(python),
                "-m",
                "agent_guard.cli",
                "report",
                "--root",
                str(repo),
                "--context-policy",
                str(context_policy),
                "--digest-policy",
                str(digest_policy),
                "--workflow-policy",
                str(workflow_policy),
                "--drift-check",
                "--format",
                "json",
                "--output",
                str(report_output),
            ],
            cwd=temp,
        )
        assert report_output_cli.stdout == ""
        report_payload = json.loads(report_output.read_text(encoding="utf-8"))
        assert report_payload["schema_version"] == "agent-guard.result.v1"
        assert report_payload["report"]["schema_version"] == "agent-guard.report_evidence.v1"
        assert report_payload["report"]["format"] == "json"
        assert report_payload["surface_inventory"]["schema_version"] == "agent-guard.agent_surface_inventory.v1"
        assert report_payload["evidence_coverage"]["schema_version"] == "agent-guard.evidence_coverage.v1"
        assert report_payload["policy_spec_drift"]["schema_version"] == "agent-guard.policy_spec_drift.v1"
        assert report_payload["context_lock"]["covered"] == [
            {
                "path": "AGENTS.md",
                "kind": "agents_md",
                "status": "covered",
                "check_id": "agent_context_pin",
            }
        ]
        assert agent_context_sha256 not in report_output.read_text(encoding="utf-8")
        assert str(temp) not in report_output.read_text(encoding="utf-8")

        sarif_output = repo / ".agent-guard" / "evidence" / "agent-guard-results.sarif"
        sarif_cli = run(
            [
                str(python),
                "-m",
                "agent_guard.cli",
                "report",
                "--root",
                str(repo),
                "--context-policy",
                str(context_policy),
                "--digest-policy",
                str(digest_policy),
                "--workflow-policy",
                str(workflow_policy),
                "--drift-check",
                "--format",
                "sarif",
                "--output",
                str(sarif_output),
            ],
            cwd=temp,
        )
        assert sarif_cli.stdout == ""
        sarif_payload = json.loads(sarif_output.read_text(encoding="utf-8"))
        assert sarif_payload["version"] == "2.1.0"
        assert sarif_payload["runs"][0]["tool"]["driver"]["name"] == "agent-guard"
        assert sarif_payload["runs"][0]["results"] == []
        assert agent_context_sha256 not in sarif_output.read_text(encoding="utf-8")
        assert str(temp) not in sarif_output.read_text(encoding="utf-8")

        preset_cli = run(
            [
                str(python),
                "-m",
                "agent_guard.cli",
                "report",
                "--root",
                str(repo),
                "--context-policy",
                str(drift_policy_dir / "context-policy.yaml"),
                "--evidence-preset",
                "recommended",
                "--format",
                "json",
            ],
            cwd=temp,
        )
        preset_payload = json.loads(preset_cli.stdout)
        assert preset_payload["report"]["scope"] == "context+path+content+mcp+workflow+drift"
        assert preset_payload["surface_inventory"]["schema_version"] == "agent-guard.agent_surface_inventory.v2"
        assert preset_payload["conformance"]["profile"] == "recommended"
        assert preset_payload["evidence_pack_manifest"]["sanitized"] is True

        conformance_input = repo / ".agent-guard" / "evidence" / "minimal-conformance.json"
        conformance_input.write_text(
            json.dumps(
                {
                    "evidence_coverage": {
                        "gates": [
                            {"gate": "context", "status": "ok", "checked_count": 1, "finding_count": 0},
                            {"gate": "surface_inventory", "status": "ok", "checked_count": 1, "finding_count": 0},
                        ]
                    },
                    "surface_inventory": {
                        "summary": {"by_surface": {"agent_context": 1, "policy_file": 2}},
                        "surfaces": [
                            {
                                "surface": "policy_file",
                                "path": ".agent-guard/context-policy.yaml",
                                "kind": "context_policy",
                                "status": "present",
                            },
                            {
                                "surface": "policy_file",
                                "path": ".agent-guard/workflow-policy.yaml",
                                "kind": "workflow_policy",
                                "status": "present",
                            },
                        ],
                    },
                }
            ),
            encoding="utf-8",
        )
        conformance_cli = run(
            [
                str(python),
                "-m",
                "agent_guard.cli",
                "conformance",
                "check",
                "--root",
                str(repo),
                "--evidence",
                str(conformance_input),
                "--profile",
                "minimal",
                "--json",
            ],
            cwd=temp,
        )
        conformance_payload = json.loads(conformance_cli.stdout)
        assert conformance_payload["status"] == "ok"
        assert conformance_payload["conformance"]["schema_version"] == "agent-guard.conformance.v1"

        manifest_cli = run(
            [
                str(python),
                "-m",
                "agent_guard.cli",
                "evidence-pack",
                "manifest",
                "--root",
                str(repo),
                "--report",
                str(report_output),
                "--artifact",
                str(report_output),
                "--artifact",
                r"C:\Users\alice\secret\agent-guard-report.json",
                "--agent-policy-audit-event",
                str(repo / ".agent-guard" / "evidence" / "policy-admission-event.json"),
                "--json",
            ],
            cwd=temp,
        )
        manifest_payload = json.loads(manifest_cli.stdout)
        assert manifest_payload["status"] == "ok"
        assert manifest_payload["evidence_pack_manifest"]["schema_version"] == "agent-guard.evidence_pack_manifest.v1"
        assert manifest_payload["evidence_pack_manifest"]["artifacts"] == [
            {"path": ".agent-guard/evidence/agent-guard-report.json", "role": "report"},
            {"path": "agent-guard-report.json", "role": "report"},
            {"path": ".agent-guard/evidence/policy-admission-event.json", "role": "agent-policy-audit-event"},
        ]
        assert r"C:\Users\alice" not in manifest_cli.stdout
        assert str(temp) not in manifest_cli.stdout

    print(f"wheel contract OK: {wheel.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
