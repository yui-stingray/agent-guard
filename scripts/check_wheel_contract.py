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
    "scan_workflow_policy",
    "WorkflowGuardFinding",
}


def project_version() -> str:
    """Return pyproject.toml [project].version."""
    with (ROOT / "pyproject.toml").open("rb") as handle:
        return str(tomllib.load(handle)["project"]["version"])


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
    wheel = find_wheel(version)
    with tempfile.TemporaryDirectory(prefix="agent-guard-wheel-") as temp_dir:
        temp = Path(temp_dir)
        venv_dir = temp / "venv"
        venv.EnvBuilder(with_pip=True).create(venv_dir)
        python = venv_dir / "bin" / "python"
        run([str(python), "-m", "pip", "install", "--quiet", str(wheel)], cwd=temp)
        smoke = textwrap.dedent(
            f"""
            import agent_guard

            expected_exports = {sorted(EXPECTED_EXPORTS)!r}
            assert sorted(agent_guard.__all__) == expected_exports
            assert agent_guard.__version__ == {version!r}
            assert agent_guard.scan_paths is agent_guard.scan_content_paths
            for name in expected_exports:
                assert getattr(agent_guard, name) is not None
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
        agent_context = "Use project tests before reporting success.\n"
        (repo / "AGENTS.md").write_text(agent_context, encoding="utf-8")
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
            "          python -m agent_guard.cli digest check --root . --policy digest-policy.yaml --json\n",
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
            "        command: python -m agent_guard.cli digest check\n",
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
            ],
            cwd=temp,
        )
        assert report_cli.stdout.startswith("# Agent Guard Evidence Report\n")
        assert "| Status | ok |" in report_cli.stdout
        assert "| Policy | context-policy.yaml |" in report_cli.stdout
        assert "| Digest policy | digest-policy.yaml |" in report_cli.stdout
        assert "| Digest checks | 1 |" in report_cli.stdout
        assert "| Workflow policy | workflow-policy.yaml |" in report_cli.stdout
        assert "| Workflow checks | 4 |" in report_cli.stdout
        assert "| Workflow drift findings | 0 |" in report_cli.stdout
        assert agent_context_sha256 not in report_cli.stdout
        assert str(temp) not in report_cli.stdout

    print(f"wheel contract OK: {wheel.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
