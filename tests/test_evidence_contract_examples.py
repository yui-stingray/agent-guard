"""Where: tests/test_evidence_contract_examples.py
What: smoke tests for copyable evidence consumer contract examples.
Why: keep S4 downstream CI examples wired to real agent-guard code paths.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

from tests.cli.helpers import mcp_policy_text, run_cli_from, sha256_text, write


REPO_ROOT = Path(__file__).resolve().parents[1]
SRC = REPO_ROOT / "src"
SCRIPT = REPO_ROOT / "examples" / "evidence_contracts_ci.sh"
SAMPLE = REPO_ROOT / "docs" / "evidence-samples" / "agent-guard-report.json"


STRICT_README_COMMANDS = """
agent-guard surface inventory --root . --context-policy .agent-guard/context-policy.yaml
agent-guard context check --root . --policy .agent-guard/context-policy.yaml
agent-guard context lock --root . --policy .agent-guard/context-policy.yaml --check --digest-policy .agent-guard/context-digest-policy.yaml
agent-guard digest check --root . --policy .agent-guard/context-digest-policy.yaml
agent-guard workflow check --root . --policy .agent-guard/workflow-policy.yaml
agent-guard mcp check --root . --policy .agent-guard/mcp-policy.yaml
agent-guard drift check --root .
agent-guard report --root . --context-policy .agent-guard/context-policy.yaml
""".strip()


STRICT_WORKFLOW_RUN = """
agent-guard context check --root . --policy .agent-guard/context-policy.yaml --json
agent-guard context lock --root . --policy .agent-guard/context-policy.yaml --check --digest-policy .agent-guard/context-digest-policy.yaml --json
agent-guard digest check --root . --policy .agent-guard/context-digest-policy.yaml --json
agent-guard path check --root . --policy .agent-guard/path-policy.yaml --json
agent-guard content check --repo-root . --policy .agent-guard/content-policy.yaml --mode registered --scan-dir . --json
agent-guard mcp check --root . --policy .agent-guard/mcp-policy.yaml --json
agent-guard surface inventory --root . --context-policy .agent-guard/context-policy.yaml --schema-version v2 --json
agent-guard workflow check --root . --policy .agent-guard/workflow-policy.yaml --json
agent-guard drift check --root . --profile recommended --schema-version v2 --json
agent-guard report --root . --context-policy .agent-guard/context-policy.yaml --evidence-preset recommended --mcp-policy .agent-guard/mcp-policy.yaml --digest-policy .agent-guard/context-digest-policy.yaml --format json --output .agent-guard/evidence/agent-guard-report.json
""".strip()


def example_env() -> dict[str, str]:
    env = os.environ.copy()
    env["PYTHONPATH"] = f"{SRC}{os.pathsep}{env['PYTHONPATH']}" if env.get("PYTHONPATH") else str(SRC)
    env["PYTHON_BIN"] = sys.executable
    env["AGENT_GUARD_BIN"] = f"{sys.executable} -m agent_guard.cli"
    return env


def run_example(repo: Path, mode: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["sh", str(SCRIPT), mode],
        cwd=repo,
        env=example_env(),
        capture_output=True,
        text=True,
        check=False,
    )


def write_contract_repo(repo: Path) -> None:
    agent_context = (
        "# Agent Instructions\n"
        "Maintainer approval is required before shell writes and destructive actions.\n"
        "Tool permissions must stay scoped to the current task.\n"
        "Network access requires a documented reason and approval where configured.\n"
        "Secrets, tokens, passwords, and credentials must stay private.\n"
        "Run tests and lint verification before reporting completion.\n"
    )
    write(repo / "AGENTS.md", agent_context)
    write(
        repo / "README.md",
        "# Consumer Contract Fixture\n\n"
        f"{STRICT_README_COMMANDS}\n\n"
        "Public evidence lives at .agent-guard/evidence/agent-guard-report.json.\n",
    )
    write(repo / ".agent-guard" / "context-policy.yaml", "{}\n")
    write(repo / ".agent-guard" / "path-policy.yaml", "{}\n")
    write(repo / ".agent-guard" / "content-policy.yaml", "{}\n")
    write(repo / ".agent-guard" / "mcp-policy.yaml", mcp_policy_text())
    write(
        repo / ".agent-guard" / "context-digest-policy.yaml",
        "checks:\n"
        "  - id: root_agents_md_reviewed\n"
        "    path: AGENTS.md\n"
        f"    sha256: '{sha256_text(agent_context)}'\n",
    )
    write(
        repo / ".agent-guard" / "workflow-policy.yaml",
        "schema_version: agent-guard.workflow_policy.v1\n"
        "required_files:\n"
        "  - .agent-guard/context-policy.yaml\n"
        "  - .agent-guard/path-policy.yaml\n"
        "  - .agent-guard/content-policy.yaml\n"
        "  - .agent-guard/context-digest-policy.yaml\n"
        "  - .agent-guard/mcp-policy.yaml\n"
        "  - .agent-guard/workflow-policy.yaml\n"
        "workflow_checks:\n"
        "  - id: strict_release_gate\n"
        "    path: .github/workflows/agent-guard.yml\n"
        "    required_commands:\n"
        "      - agent-guard context check\n"
        "      - agent-guard context lock\n"
        "      - agent-guard digest check\n"
        "      - agent-guard path check\n"
        "      - agent-guard content check\n"
        "      - agent-guard mcp check\n"
        "      - agent-guard surface inventory\n"
        "      - agent-guard workflow check\n"
        "      - agent-guard drift check\n"
        "      - agent-guard report\n",
    )
    write(
        repo / ".github" / "workflows" / "agent-guard.yml",
        "name: agent-guard\n"
        "on: [push]\n"
        "jobs:\n"
        "  guard:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@v7\n"
        "      - name: Guard checks\n"
        "        run: |\n"
        + "".join(f"          {line}\n" for line in STRICT_WORKFLOW_RUN.splitlines())
        + "      - uses: actions/upload-artifact@v7\n"
        "        if: always()\n"
        "        with:\n"
        "          name: agent-guard-evidence\n"
        "          path: .agent-guard/evidence/\n"
        "          if-no-files-found: error\n",
    )


def generate_recommended_report(repo: Path) -> Path:
    report = repo / ".agent-guard" / "evidence" / "agent-guard-report.json"
    result = run_cli_from(
        repo,
        "report",
        "--root",
        ".",
        "--context-policy",
        ".agent-guard/context-policy.yaml",
        "--evidence-preset",
        "recommended",
        "--mcp-policy",
        ".agent-guard/mcp-policy.yaml",
        "--format",
        "json",
        "--output",
        str(report),
    )
    assert result.returncode == 0, result.stdout + result.stderr
    return report


def test_packaged_consumer_module_entrypoint_accepts_public_sample() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "agent_guard.consumer", str(SAMPLE)],
        cwd=REPO_ROOT,
        env=example_env(),
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert json.loads(result.stdout)["schema_version"] == "agent-guard.result.v1"


def test_fail_closed_consumer_example_rejects_missing_invalid_and_stale_report(tmp_path: Path) -> None:
    write_contract_repo(tmp_path)
    report = generate_recommended_report(tmp_path)

    green = run_example(tmp_path, "consume")
    assert green.returncode == 0, green.stdout + green.stderr

    report.unlink()
    missing = run_example(tmp_path, "consume")
    assert missing.returncode == 1
    assert "agent-guard evidence invalid" in missing.stderr or "No such file" in missing.stderr

    report.write_text("{}", encoding="utf-8")
    invalid = run_example(tmp_path, "consume")
    assert invalid.returncode == 1
    assert "agent-guard evidence invalid" in invalid.stderr

    report = generate_recommended_report(tmp_path)
    write(tmp_path / "docs" / "note.md", "A benign documentation-only addition.\n")
    stale = run_example(tmp_path, "consume")
    assert stale.returncode == 1
    assert "agent-guard evidence stale" in stale.stderr
    assert report.read_text(encoding="utf-8").startswith("{")


def test_public_artifact_lint_example_rejects_raw_scanner_json(tmp_path: Path) -> None:
    write_contract_repo(tmp_path)
    evidence_dir = generate_recommended_report(tmp_path).parent

    clean = run_example(tmp_path, "lint-public")
    assert clean.returncode == 0, clean.stdout + clean.stderr

    write(evidence_dir / "context.json", '{"scanner":"context"}\n')
    raw_artifact = run_example(tmp_path, "lint-public")
    assert raw_artifact.returncode == 1
    assert "not a public agent-guard evidence artifact" in raw_artifact.stderr


def test_strict_release_gate_example_generates_strict_conformance(tmp_path: Path) -> None:
    write_contract_repo(tmp_path)

    result = run_example(tmp_path, "strict-release")

    assert result.returncode == 0, result.stdout + result.stderr
    report = json.loads((tmp_path / ".agent-guard/evidence/agent-guard-report.json").read_text(encoding="utf-8"))
    conformance = json.loads(
        (tmp_path / ".agent-guard/evidence/agent-guard-conformance.json").read_text(encoding="utf-8")
    )
    assert report["conformance"]["profile"] == "strict"
    assert report["conformance"]["status"] == "ok"
    assert conformance["conformance"]["profile"] == "strict"
    assert conformance["conformance"]["status"] == "ok"
