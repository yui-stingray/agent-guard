"""Where: scripts/check_wheel_contract.py
What: install the built wheel into an isolated venv and verify the public contract.
Why: editable installs can hide packaging mistakes; releases must prove the wheel works.
"""

from __future__ import annotations

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
        (repo / "AGENTS.md").write_text("Use project tests before reporting success.\n", encoding="utf-8")
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

    print(f"wheel contract OK: {wheel.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
