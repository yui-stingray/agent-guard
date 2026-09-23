"""Characterize installed CLI entrypoints and the pre-refactor import surface.

The incidental shim exports below are a migration baseline, not a declaration
that every observed name is a permanently supported public API.
"""

from __future__ import annotations

import importlib
import json
import os
from pathlib import Path
import pickle
import subprocess
import sys
import sysconfig

import pytest

import agent_guard.cli as cli


FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "cli" / "entrypoint-output.json"
BASELINE = json.loads(FIXTURE.read_text(encoding="utf-8"))
OBSERVED_EXPORTS = [
    "PACKAGE_VERSION",
    "add_api_parser",
    "add_conformance_parser",
    "add_content_parser",
    "add_context_parser",
    "add_digest_parser",
    "add_drift_parser",
    "add_evidence_pack_parser",
    "add_mcp_parser",
    "add_path_parser",
    "add_render_report_parser",
    "add_report_parser",
    "add_surface_parser",
    "add_workflow_parser",
    "annotations",
    "argparse",
    "build_parser",
    "main",
    "run_api_check",
    "run_conformance_check",
    "run_content_check",
    "run_context_check",
    "run_context_inventory",
    "run_context_lock",
    "run_digest_check",
    "run_drift_check",
    "run_evidence_pack_manifest",
    "run_init",
    "run_mcp_check",
    "run_path_check",
    "run_report",
    "run_report_render",
    "run_surface_delta",
    "run_surface_inventory",
    "run_workflow_check",
    "safe_policy_path",
    "scrub_report_error_message",
]
EXPORT_ORIGINS = {
    "api": ("add_api_parser", "run_api_check"),
    "conformance": ("add_conformance_parser", "run_conformance_check"),
    "content": ("add_content_parser", "run_content_check"),
    "context": ("add_context_parser", "run_context_check", "run_context_inventory", "run_context_lock"),
    "digest": ("add_digest_parser", "run_digest_check"),
    "drift": ("add_drift_parser", "run_drift_check"),
    "evidence_pack": ("add_evidence_pack_parser", "run_evidence_pack_manifest"),
    "init": ("run_init",),
    "mcp": ("add_mcp_parser", "run_mcp_check"),
    "path": ("add_path_parser", "run_path_check"),
    "report": ("add_report_parser", "run_report"),
    "render_report": ("add_render_report_parser", "run_report_render"),
    "surface": ("add_surface_parser", "run_surface_inventory", "run_surface_delta"),
    "workflow": ("add_workflow_parser", "run_workflow_check"),
    "common": ("safe_policy_path", "scrub_report_error_message"),
}


def test_cli_observed_export_list_before_shim_migration() -> None:
    assert cli.__all__ == OBSERVED_EXPORTS


@pytest.mark.parametrize("module,names", EXPORT_ORIGINS.items())
def test_cli_reexports_original_command_functions(module: str, names: tuple[str, ...]) -> None:
    origin = importlib.import_module(f"agent_guard.cli.{module}")
    for name in names:
        assert getattr(cli, name) is getattr(origin, name)


def test_cli_entry_functions_keep_alias_and_static_owner() -> None:
    legacy = sys.modules["agent_guard._legacy_cli"]
    entry = importlib.import_module("agent_guard.cli._entry")
    assert legacy is entry
    assert cli.main is legacy.main
    assert cli.build_parser is legacy.build_parser
    assert cli.main.__module__ == "agent_guard.cli._entry"
    assert cli.build_parser.__module__ == "agent_guard.cli._entry"
    assert cli.main.__globals__["build_parser"] is cli.build_parser
    assert cli.main.__globals__ is vars(entry)


@pytest.mark.parametrize(
    "name,payload",
    (
        ("main", b"cagent_guard._legacy_cli\nmain\np0\n."),
        ("build_parser", b"cagent_guard._legacy_cli\nbuild_parser\np0\n."),
    ),
)
def test_baseline_cli_pickle_reference_restores_after_cli_import(
    name: str, payload: bytes
) -> None:
    # Generated from baseline functions with protocol 0, then restored on the
    # baseline before recording these trusted, fixed references.
    assert pickle.loads(payload) is getattr(cli, name)


@pytest.mark.parametrize("module", ("agent_guard.cli.api", "agent_guard.cli._entry"))
def test_cli_submodule_imports_before_facade_in_fresh_process(
    module: str, tmp_path: Path
) -> None:
    result = subprocess.run(
        [
            sys.executable, "-I", "-c",
            "import importlib, sys\n"
            f"module = importlib.import_module({module!r})\n"
            "import agent_guard.cli as cli\n"
            "assert callable(cli.main) and callable(cli.build_parser)\n"
            "if module.__name__ == 'agent_guard.cli.api':\n"
            "    assert module.run_api_check is cli.run_api_check\n"
            "else:\n"
            "    assert module.main is cli.main\n"
            "assert cli.main is sys.modules['agent_guard._legacy_cli'].main\n",
        ],
        cwd=tmp_path,
        capture_output=True,
        check=False,
        timeout=30,
    )
    assert (result.returncode, result.stdout, result.stderr) == (0, b"", b"")


@pytest.mark.parametrize("first", ("cli", "workflow"))
def test_cli_workflow_import_orders_in_fresh_processes(first: str, tmp_path: Path) -> None:
    imports = (
        "import agent_guard.cli as cli\nimport agent_guard.workflow_guard as workflow\n"
        if first == "cli"
        else "import agent_guard.workflow_guard as workflow\n"
        "workflow._agent_guard_cli_parser()\nimport agent_guard.cli as cli\n"
    )
    result = subprocess.run(
        [sys.executable, "-I", "-c", imports + (
            "parser = workflow._agent_guard_cli_parser()\n"
            "args = parser.parse_args(['workflow', 'check', '--policy', 'workflow.yaml'])\n"
            "assert (args.scanner, args.command, args.policy) == ('workflow', 'check', 'workflow.yaml')\n"
            "assert callable(cli.main) and callable(cli.build_parser)\n"
        )],
        cwd=tmp_path,
        capture_output=True,
        check=False,
        timeout=30,
    )
    assert (result.returncode, result.stdout, result.stderr) == (0, b"", b"")


@pytest.mark.parametrize("entrypoint", ("console", "module"))
@pytest.mark.parametrize(
    "case_index,case",
    list(enumerate(BASELINE["cases"])),
    ids=[" ".join(case["argv"]) or "missing-scanner" for case in BASELINE["cases"]],
)
def test_installed_cli_entrypoint_streams(
    entrypoint: str, case_index: int, case: dict, tmp_path: Path
) -> None:
    # Select this interpreter's installation, never an unrelated executable on PATH.
    console = Path(sysconfig.get_path("scripts")) / (
        "agent-guard.exe" if os.name == "nt" else "agent-guard"
    )
    assert console.is_file()
    command = [str(console)] if entrypoint == "console" else [
        sys.executable, "-I", "-m", "agent_guard.cli"
    ]
    env = {key: value for key, value in os.environ.items() if not key.startswith("PYTHON")}
    env.update(BASELINE["conditions"])
    result = subprocess.run(
        [*command, *case["argv"]], cwd=tmp_path, env=env,
        capture_output=True, check=False, timeout=30,
    )
    runtime = BASELINE["runtimes"][f"{sys.version_info.major}.{sys.version_info.minor}"][entrypoint]
    expected = BASELINE["outputs"][runtime["outputs"][case_index]]
    program = runtime["program"]
    if sys.version_info >= (3, 14):
        if entrypoint == "module":
            program = f"{Path(sys.executable).name} -m agent_guard.cli"
        elif os.name == "nt":
            # CPython 3.14 names a distlib ZIP launcher using its interpreter/path.
            # The installed script strips .exe from argv[0] first.
            program = f"{Path(sys.executable).name} {console.with_suffix('')}"

    def expected_bytes(stream: str) -> bytes:
        # Expand only the known program name in the expected text. Actual streams
        # are never masked or normalized. A wide fixed terminal avoids wrapping
        # differences caused solely by the installed interpreter's basename.
        lines = []
        for line in expected[stream].splitlines(keepends=True):
            if line.startswith(f"usage: {runtime['program']}"):
                line = "usage: " + program + line[len("usage: ") + len(runtime["program"]):]
            elif line.startswith(runtime["program"] + ": error:") or (
                line.startswith(runtime["program"] + " ") and ": error:" in line
            ):
                line = program + line[len(runtime["program"]):]
            lines.append(line)
        text = "".join(lines)
        if os.name == "nt":
            text = text.replace("\n", "\r\n")
        return text.encode("utf-8")

    assert result.returncode == case["returncode"]
    assert result.stdout == expected_bytes("stdout")
    assert result.stderr == expected_bytes("stderr")
