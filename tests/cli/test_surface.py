# Where: tests/cli/test_surface.py
# What: focused subprocess tests for the surface CLI group.
# Why: keep extracted surface subcommand coverage close to its module.

from __future__ import annotations

import argparse
import json
import os
import subprocess
from pathlib import Path

import pytest

from agent_guard import surface_inventory_metadata as surface_inventory_metadata_module
import agent_guard.cli.common as cli_common
import agent_guard.cli.surface as surface_cli
from agent_guard.bounded_git import (
    BoundedGitOutputLimitError,
    BoundedGitProcessError,
)
from tests.cli.helpers import assert_shared_envelope, run_cli, write


def run_git(repo: Path, *args: str) -> None:
    subprocess.run(
        ["git", *args],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    )


def add_index_stage(repo: Path, path: str, stage: int) -> None:
    object_id = subprocess.run(
        ["git", "hash-object", "-w", "--stdin"],
        cwd=repo,
        input=b'{"conflicted":true}\n',
        check=True,
        capture_output=True,
    ).stdout.strip()
    subprocess.run(
        ["git", "update-index", "--index-info"],
        cwd=repo,
        input=f"100644 {object_id.decode('ascii')} {stage}\t{path}\n",
        check=True,
        capture_output=True,
        text=True,
    )


def test_surface_inventory_plain_text_enforces_public_output_budget(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    policy = tmp_path / "context_policy.yaml"
    policy.write_text("{}\n", encoding="utf-8")
    write(tmp_path / "AGENTS.md", "Require approval before shell writes.\n")
    args = argparse.Namespace(
        root=str(tmp_path),
        context_policy=str(policy),
        schema_version="v1",
        json=False,
    )
    expected_line = "surface-inventory: OK (1 surfaces)\n"
    monkeypatch.setattr(
        cli_common,
        "MAX_PUBLIC_OUTPUT_BYTES",
        len(expected_line.encode("utf-8")) - 1,
    )

    assert surface_cli.run_surface_inventory(args) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == ""


def test_surface_inventory_plain_text_write_error_returns_exit_two(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    policy = tmp_path / "context_policy.yaml"
    policy.write_text("{}\n", encoding="utf-8")
    write(tmp_path / "AGENTS.md", "Require approval before shell writes.\n")
    args = argparse.Namespace(
        root=str(tmp_path),
        context_policy=str(policy),
        schema_version="v1",
        json=False,
    )

    def fail_emit(text: str, *, error: str) -> None:
        raise ValueError(error)

    monkeypatch.setattr(surface_cli, "emit_public_output", fail_emit)

    assert surface_cli.run_surface_inventory(args) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == ""


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


def test_surface_inventory_cli_v2_uses_index_evidence_not_generated_worktree_files(
    tmp_path: Path,
) -> None:
    policy = tmp_path / "context_policy.yaml"
    policy.write_text("{}\n", encoding="utf-8")
    write(tmp_path / "AGENTS.md", "Require approval before shell writes.\n")
    indexed_repo_evidence = b'{"source":"index"}\n'
    indexed_sample = b'{"sample":"index"}\n'
    repo_evidence = tmp_path / ".agent-guard" / "evidence" / "reviewed.json"
    sample = tmp_path / "docs" / "evidence-samples" / "sample.json"
    write(repo_evidence, indexed_repo_evidence.decode())
    write(sample, indexed_sample.decode())

    run_git(tmp_path, "init", "-q")
    run_git(
        tmp_path,
        "add",
        "AGENTS.md",
        "context_policy.yaml",
        ".agent-guard/evidence/reviewed.json",
        "docs/evidence-samples/sample.json",
    )

    write(repo_evidence, '{"source":"modified working tree with a different size"}\n')
    generated = tmp_path / ".agent-guard" / "evidence" / "agent-surface-inventory.json"
    write(generated, '{"generated":true}\n')

    first = run_cli(
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

    assert first.returncode == 0, first.stdout + first.stderr
    first_inventory = json.loads(first.stdout)["surface_inventory"]
    evidence_surfaces = [
        item
        for item in first_inventory["surfaces"]
        if item["surface"] == "evidence_artifact"
    ]
    assert evidence_surfaces == [
        {
            "surface": "evidence_artifact",
            "path": ".agent-guard/evidence/reviewed.json",
            "kind": "repo_evidence_file",
            "status": "present",
            "size_bytes": len(indexed_repo_evidence),
        },
        {
            "surface": "evidence_artifact",
            "path": "docs/evidence-samples/sample.json",
            "kind": "committed_evidence_sample",
            "status": "present",
            "size_bytes": len(indexed_sample),
        },
    ]

    write(generated, '{"generated":"changed between runs"}\n')
    second = run_cli(
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

    assert second.returncode == 0, second.stdout + second.stderr
    assert json.loads(second.stdout)["surface_inventory"] == first_inventory


def test_surface_inventory_cli_v2_ignores_replacement_objects_for_blob_metadata(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy = tmp_path / "context_policy.yaml"
    policy.write_text("{}\n", encoding="utf-8")
    write(tmp_path / "AGENTS.md", "Require approval before shell writes.\n")
    original = b'{"source":"indexed"}\n'
    replacement = b'{"source":"replacement with a different object size"}\n'
    evidence = tmp_path / "docs" / "evidence-samples" / "sample.json"
    write(evidence, original.decode("utf-8"))
    run_git(tmp_path, "init", "-q")
    run_git(tmp_path, "add", "docs/evidence-samples/sample.json")
    original_oid = subprocess.run(
        ["git", "rev-parse", ":docs/evidence-samples/sample.json"],
        cwd=tmp_path,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    replacement_oid = subprocess.run(
        ["git", "hash-object", "-w", "--stdin"],
        cwd=tmp_path,
        input=replacement,
        check=True,
        capture_output=True,
    ).stdout.decode("ascii").strip()
    run_git(tmp_path, "replace", original_oid, replacement_oid)

    replaced_size = subprocess.run(
        ["git", "cat-file", "-s", original_oid],
        cwd=tmp_path,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    assert int(replaced_size) == len(replacement)
    monkeypatch.setenv("GIT_NO_REPLACE_OBJECTS", "0")

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
    evidence_surfaces = [
        item
        for item in json.loads(result.stdout)["surface_inventory"]["surfaces"]
        if item["surface"] == "evidence_artifact"
    ]
    assert evidence_surfaces == [
        {
            "surface": "evidence_artifact",
            "path": "docs/evidence-samples/sample.json",
            "kind": "committed_evidence_sample",
            "status": "present",
            "size_bytes": len(original),
        }
    ]
    assert str(tmp_path) not in result.stdout + result.stderr


def test_surface_inventory_cli_v2_uses_requested_root_despite_hostile_git_env(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    requested = tmp_path / "requested"
    hostile = tmp_path / "hostile"
    requested.mkdir()
    hostile.mkdir()
    policy = requested / "context_policy.yaml"
    policy.write_text("{}\n", encoding="utf-8")
    write(requested / "AGENTS.md", "Require approval before shell writes.\n")
    requested_evidence = b'{"source":"requested"}\n'
    hostile_evidence = b'{"source":"hostile-index"}\n'
    write(
        requested / "docs" / "evidence-samples" / "requested.json",
        requested_evidence.decode(),
    )
    write(
        hostile / "docs" / "evidence-samples" / "hostile.json",
        hostile_evidence.decode(),
    )

    run_git(requested, "init", "-q")
    run_git(requested, "add", "docs/evidence-samples/requested.json")
    run_git(hostile, "init", "-q")
    run_git(hostile, "add", "docs/evidence-samples/hostile.json")

    hostile_git_dir = hostile / ".git"
    hostile_object_dir = hostile_git_dir / "objects"
    routing_environment = {
        "GIT_ALTERNATE_OBJECT_DIRECTORIES": str(hostile_object_dir),
        "GIT_CEILING_DIRECTORIES": str(requested),
        "GIT_COMMON_DIR": str(hostile_git_dir),
        "GIT_DIR": str(hostile_git_dir),
        "GIT_DISCOVERY_ACROSS_FILESYSTEM": "1",
        "GIT_GRAFT_FILE": str(hostile_git_dir / "info" / "grafts"),
        "GIT_IMPLICIT_WORK_TREE": "0",
        "GIT_INDEX_FILE": str(hostile_git_dir / "index"),
        "GIT_NAMESPACE": "hostile-namespace",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_OBJECT_DIRECTORY": str(hostile_object_dir),
        "GIT_PREFIX": "hostile-prefix/",
        "GIT_QUARANTINE_PATH": str(hostile_object_dir),
        "GIT_REPLACE_REF_BASE": "refs/hostile-replace/",
        "GIT_SHALLOW_FILE": str(hostile_git_dir / "shallow"),
        "GIT_WORK_TREE": str(hostile),
    }
    for variable, value in routing_environment.items():
        monkeypatch.setenv(variable, value)

    result = run_cli(
        "surface",
        "inventory",
        "--root",
        str(requested),
        "--context-policy",
        str(policy),
        "--schema-version",
        "v2",
        "--json",
    )

    assert result.returncode == 0, result.stdout + result.stderr
    evidence_surfaces = [
        item
        for item in json.loads(result.stdout)["surface_inventory"]["surfaces"]
        if item["surface"] == "evidence_artifact"
    ]
    assert evidence_surfaces == [
        {
            "surface": "evidence_artifact",
            "path": "docs/evidence-samples/requested.json",
            "kind": "committed_evidence_sample",
            "status": "present",
            "size_bytes": len(requested_evidence),
        }
    ]
    public_output = result.stdout + result.stderr
    assert str(requested) not in public_output
    assert str(hostile) not in public_output
    assert "hostile.json" not in public_output


def test_surface_inventory_cli_v2_excludes_unproven_evidence_without_git(
    tmp_path: Path,
) -> None:
    policy = tmp_path / "context_policy.yaml"
    policy.write_text("{}\n", encoding="utf-8")
    write(tmp_path / "AGENTS.md", "Require approval before shell writes.\n")
    write(
        tmp_path / ".agent-guard" / "evidence" / "agent-guard-report.json",
        '{"generated":true}\n',
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
    surfaces = json.loads(result.stdout)["surface_inventory"]["surfaces"]
    assert not any(item["surface"] == "evidence_artifact" for item in surfaces)


def test_materialized_evidence_stops_before_sorting_over_limit_candidates(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    evidence_dir = tmp_path / "docs" / "evidence-samples"
    for number in range(4):
        write(evidence_dir / f"candidate-{number}.json", "{}\n")

    maximum = 2
    candidates_seen = 0
    original_scandir = os.scandir

    class CountingEntry:
        def __init__(self, name: str, *, name_may_be_read: bool) -> None:
            self._name = name
            self._name_may_be_read = name_may_be_read

        @property
        def name(self) -> str:
            if not self._name_may_be_read:
                pytest.fail("excess evidence entry name was read before the cap failed")
            return self._name

    class CountingScan:
        def __init__(self) -> None:
            self._entries = iter([f"candidate-{number}.json" for number in range(4)])

        def __enter__(self) -> CountingScan:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def __iter__(self) -> CountingScan:
            return self

        def __next__(self):
            nonlocal candidates_seen
            name = next(self._entries)
            candidates_seen += 1
            if candidates_seen > maximum + 1:
                pytest.fail("materialized evidence enumeration did not stop early")
            return CountingEntry(name, name_may_be_read=candidates_seen <= maximum)

    def bounded_scandir(path: os.PathLike[str] | str):
        if Path(path) == evidence_dir:
            return CountingScan()
        return original_scandir(path)

    monkeypatch.setattr(
        surface_inventory_metadata_module,
        "MAX_EVIDENCE_ARTIFACT_FILES",
        maximum,
    )
    monkeypatch.setattr(surface_inventory_metadata_module.os, "scandir", bounded_scandir)
    monkeypatch.setattr(
        surface_inventory_metadata_module,
        "sorted",
        lambda *_args, **_kwargs: pytest.fail("candidates were sorted after the cap failed"),
        raising=False,
    )
    monkeypatch.setattr(
        surface_inventory_metadata_module,
        "repo_bound_glob",
        lambda *_args, **_kwargs: pytest.fail("fallback must not materialize repo_bound_glob"),
    )

    with pytest.raises(ValueError) as raised:
        surface_inventory_metadata_module._collect_materialized_evidence_surfaces(tmp_path)

    assert str(raised.value) == "committed evidence metadata could not be verified"
    assert candidates_seen == maximum + 1
    assert "candidate-" not in str(raised.value)


def test_surface_inventory_cli_v2_ignores_invalid_ancestor_git_marker(
    tmp_path: Path,
) -> None:
    ancestor = tmp_path / "ancestor"
    repo = ancestor / "materialized"
    (ancestor / ".git").mkdir(parents=True)
    repo.mkdir()
    policy = repo / "context_policy.yaml"
    policy.write_text("{}\n", encoding="utf-8")
    write(repo / "AGENTS.md", "Require approval before shell writes.\n")

    result = run_cli(
        "surface",
        "inventory",
        "--root",
        str(repo),
        "--context-policy",
        str(policy),
        "--schema-version",
        "v2",
        "--json",
    )

    assert result.returncode == 0, result.stdout + result.stderr


def test_surface_inventory_cli_v2_fails_closed_when_git_index_cannot_be_verified(
    tmp_path: Path,
) -> None:
    policy = tmp_path / "context_policy.yaml"
    policy.write_text("{}\n", encoding="utf-8")
    write(tmp_path / "AGENTS.md", "Require approval before shell writes.\n")
    run_git(tmp_path, "init", "-q")
    (tmp_path / ".git" / "index").write_bytes(b"invalid synthetic index bytes\n")

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

    assert result.returncode == 2
    payload = json.loads(result.stdout)
    assert payload["error"] == "committed evidence metadata could not be verified"
    assert str(tmp_path) not in result.stdout
    assert "invalid synthetic index bytes" not in result.stdout


@pytest.mark.parametrize("stage", (1, 2, 3))
@pytest.mark.parametrize(
    "path",
    (
        ".agent-guard/evidence/conflicted-stage.json",
        "docs/evidence-samples/conflicted-stage.json",
    ),
)
def test_surface_inventory_cli_v2_fails_closed_for_conflicted_evidence_index_stage(
    tmp_path: Path,
    path: str,
    stage: int,
) -> None:
    policy = tmp_path / "context_policy.yaml"
    policy.write_text("{}\n", encoding="utf-8")
    write(tmp_path / "AGENTS.md", "Require approval before shell writes.\n")
    run_git(tmp_path, "init", "-q")
    add_index_stage(tmp_path, path, stage)

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

    assert result.returncode == 2
    payload = json.loads(result.stdout)
    assert payload["error"] == "committed evidence metadata could not be verified"
    assert Path(path).name not in result.stdout
    assert str(tmp_path) not in result.stdout


def test_run_git_metadata_stops_reading_and_terminates_on_output_limit(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    def exceed_limit(*_args: object, **_kwargs: object) -> None:
        raise BoundedGitOutputLimitError

    monkeypatch.setattr(surface_inventory_metadata_module, "run_bounded_git", exceed_limit)

    with pytest.raises(ValueError) as raised:
        surface_inventory_metadata_module._run_git_metadata(tmp_path, ["ls-files"])

    assert str(raised.value) == "committed evidence metadata could not be verified"


def test_run_git_metadata_terminates_on_timeout(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    def time_out(*_args: object, **_kwargs: object) -> None:
        raise BoundedGitProcessError

    monkeypatch.setattr(surface_inventory_metadata_module, "run_bounded_git", time_out)

    with pytest.raises(ValueError) as raised:
        surface_inventory_metadata_module._run_git_metadata(tmp_path, ["ls-files"])

    assert str(raised.value) == "committed evidence metadata could not be verified"


def test_run_git_metadata_sanitizes_process_start_error(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    marker = "sensitive process launch detail"

    def fail_to_start(*_args: object, **_kwargs: object) -> None:
        raise BoundedGitProcessError(marker)

    monkeypatch.setattr(surface_inventory_metadata_module, "run_bounded_git", fail_to_start)

    with pytest.raises(ValueError) as raised:
        surface_inventory_metadata_module._run_git_metadata(tmp_path, ["ls-files"])

    assert str(raised.value) == "committed evidence metadata could not be verified"
    assert marker not in str(raised.value)
    assert str(tmp_path) not in str(raised.value)


def test_run_git_metadata_disables_lazy_fetch_without_mutating_caller_env(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv("AGENT_GUARD_SYNTHETIC_CALLER_ENV", "preserved")
    monkeypatch.setenv("GIT_CONFIG_COUNT", "2")
    monkeypatch.setenv("GIT_CONFIG_KEY_0", "core.fsmonitor")
    monkeypatch.setenv("GIT_CONFIG_VALUE_0", "synthetic-helper")
    monkeypatch.setenv("GIT_CONFIG_KEY_1", "core.pager")
    monkeypatch.setenv("GIT_CONFIG_VALUE_1", "synthetic-pager")
    monkeypatch.setenv("GIT_CONFIG_PARAMETERS", "'core.fsmonitor=synthetic-parameter'")
    for variable in (
        surface_inventory_metadata_module._GIT_METADATA_ROUTING_ENVIRONMENT_VARIABLES
    ):
        monkeypatch.setenv(variable, "inherited-routing-value")
    monkeypatch.setenv("GIT_NO_LAZY_FETCH", "0")
    monkeypatch.setenv("GIT_NO_REPLACE_OBJECTS", "0")

    environment = surface_inventory_metadata_module._git_metadata_environment()

    assert environment["AGENT_GUARD_SYNTHETIC_CALLER_ENV"] == "preserved"
    assert environment["GIT_NO_LAZY_FETCH"] == "1"
    assert environment["GIT_NO_REPLACE_OBJECTS"] == "1"
    assert environment["GIT_CONFIG_NOSYSTEM"] == "1"
    assert environment["GIT_CONFIG_SYSTEM"] == os.devnull
    assert environment["GIT_CONFIG_GLOBAL"] == os.devnull
    assert "GIT_CONFIG_COUNT" not in environment
    assert "GIT_CONFIG_PARAMETERS" not in environment
    assert not any(
        key.startswith(("GIT_CONFIG_KEY_", "GIT_CONFIG_VALUE_"))
        for key in environment
    )
    assert os.environ["GIT_NO_LAZY_FETCH"] == "0"
    assert os.environ["GIT_NO_REPLACE_OBJECTS"] == "0"


def test_run_git_metadata_streams_input_without_waiting_for_stdout_drain(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    captured: dict[str, object] = {}

    def run_git(root: Path, args: list[str], **kwargs: object):
        captured["root"] = root
        captured["args"] = args
        captured.update(kwargs)
        return subprocess.CompletedProcess(args, 0, b"metadata\n")

    monkeypatch.setattr(surface_inventory_metadata_module, "run_bounded_git", run_git)

    result = surface_inventory_metadata_module._run_git_metadata(
        tmp_path,
        ["cat-file", "--batch-check"],
        input_data=b"object-id\n",
    )

    assert result.stdout == b"metadata\n"
    assert captured["root"] == tmp_path
    assert captured["args"] == ["cat-file", "--batch-check"]
    assert captured["input_data"] == b"object-id\n"
    assert captured["timeout_seconds"] == surface_inventory_metadata_module.GIT_METADATA_TIMEOUT_SECONDS
    assert captured["max_output_bytes"] == surface_inventory_metadata_module.MAX_EVIDENCE_INDEX_OUTPUT_BYTES


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
    fake_inline_secret = "sk-" + "exampleSecretValue123"
    fake_local_path = "/" + "home" + "/alice/private"
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
                        "command": (
                            "npx -y @vendor/browser-mcp --token "
                            f"{fake_inline_secret} --root {fake_local_path}"
                        ),
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
        'args = ["docs-server@1.2.3"]\n'
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
        fake_local_path,
        fake_inline_secret,
        "@vendor/browser-mcp --token",
        "secret skill body marker",
        "agent prompt marker",
        "command prompt marker",
        "private hook marker",
        "https://mcp.example.com/sse",
        str(tmp_path),
    ):
        assert forbidden not in result.stdout


def test_surface_inventory_cli_normalizes_windows_launcher_paths_without_disclosure(
    tmp_path: Path,
) -> None:
    policy = tmp_path / "context_policy.yaml"
    policy.write_text("{}\n", encoding="utf-8")
    relative_launcher = r"tools\npx.cmd"
    absolute_launcher = r"C:\Program Files\nodejs\npx.cmd"
    write(
        tmp_path / ".mcp.json",
        json.dumps(
            {
                "mcpServers": {
                    "relative": {
                        "command": relative_launcher,
                        "args": ["pkg"],
                    },
                    "absolute": {
                        "command": absolute_launcher,
                        "args": ["pkg@1.2.3"],
                    },
                    "quoted-inline": {
                        "command": f'"{absolute_launcher}" --yes pkg@1.2.3',
                    },
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

    assert result.returncode == 0, result.stdout + result.stderr
    surfaces = json.loads(result.stdout)["surface_inventory"]["surfaces"]
    servers = {
        item["server_name"]: item
        for item in surfaces
        if item["surface"] == "mcp_server_reference"
    }
    assert servers["relative"]["command_basename"] == "npx.cmd"
    assert servers["relative"]["package_manager"] == "npx"
    assert servers["relative"]["version_pinned"] is False
    for name in ("absolute", "quoted-inline"):
        assert servers[name]["command_basename"] == "npx.cmd"
        assert servers[name]["package_manager"] == "npx"
        assert servers[name]["version_pinned"] is True
    for private in (relative_launcher, absolute_launcher, "Program Files", "nodejs"):
        assert private not in result.stdout
        assert private not in result.stderr


def test_surface_inventory_cli_json_redacts_secret_shaped_public_surface_payload(
    tmp_path: Path,
) -> None:
    policy = tmp_path / "context_policy.yaml"
    policy.write_text("{}\n", encoding="utf-8")
    skill_name = "ghp_" + ("A" * 24)
    profile_name = "github_pat_" + ("B" * 20)
    command_name = "sk-" + ("C" * 24)
    job_id = "AKIA" + ("D" * 16)
    artifact_name = "xoxb-" + ("E" * 16)
    output_path = f".agent-guard/evidence/{artifact_name}.json"
    write(tmp_path / "AGENTS.md", "Require approval before shell writes.\n")
    write(tmp_path / ".github" / "skills" / skill_name / "SKILL.md", "skill body\n")
    write(tmp_path / ".claude" / "agents" / profile_name / "agent.md", "profile body\n")
    write(tmp_path / ".claude" / "commands" / command_name / "command.md", "command body\n")
    write(
        tmp_path / ".github" / "workflows" / "ci.yml",
        "name: ci\n"
        "jobs:\n"
        f"  {job_id}:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - run: "
        "agent-guard report --root . --context-policy context_policy.yaml "
        f"--format json --output {output_path}\n"
        "      - uses: actions/upload-artifact@v7\n"
        "        with:\n"
        f"          path: {output_path}\n",
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
    for forbidden in (skill_name, profile_name, command_name, job_id, artifact_name, str(tmp_path)):
        assert forbidden not in result.stdout
    payload = json.loads(result.stdout)
    assert_shared_envelope(
        payload,
        scanner="surface",
        status="ok",
        exit_code=0,
        finding_count=0,
        scanned_unit="surfaces",
    )
    assert payload["surface_inventory"]["schema_version"] == "agent-guard.agent_surface_inventory.v2"
    assert payload["summary"]["surface_count"] == payload["surface_inventory"]["summary"]["surface_count"]
    assert payload["surface_inventory"]["summary"]["by_surface"]["agent_context"] == 1

    surfaces = payload["surface_inventory"]["surfaces"]
    assert {
        "surface": "agent_skill",
        "path": ".github/skills/<redacted>",
        "kind": "github_copilot_skill",
        "status": "present",
        "file_count": 1,
    } in surfaces
    assert {
        "surface": "agent_profile",
        "path": ".claude/agents/<redacted>",
        "kind": "claude_agent",
        "status": "present",
        "file_count": 1,
    } in surfaces
    assert {
        "surface": "agent_command",
        "path": ".claude/commands/<redacted>",
        "kind": "claude_command",
        "status": "present",
        "file_count": 1,
    } in surfaces
    workflow_refs = [item for item in surfaces if item["surface"] == "workflow_reference"]
    assert workflow_refs == [
        {
            "surface": "workflow_reference",
            "path": ".github/workflows/ci.yml",
            "kind": "agent_guard_command",
            "status": "referenced",
            "job_id": "<redacted>",
            "step_index": 1,
            "command": {"scanner": "report", "command": ""},
        }
    ]
    artifact_paths = {
        item["artifact_path"]
        for item in surfaces
        if item["surface"] == "evidence_artifact_reference"
    }
    assert artifact_paths == {".agent-guard/evidence/<redacted>.json"}


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


def test_surface_inventory_cli_v2_skips_repo_external_symlink_surfaces(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    outside = tmp_path / "outside"
    policy = repo / "context_policy.yaml"
    policy.parent.mkdir()
    policy.write_text("{}\n", encoding="utf-8")
    write(repo / "AGENTS.md", "Require approval before shell writes.\n")
    write(
        outside / "skills" / "outside-skill-marker" / "SKILL.md",
        "outside skill marker content\n",
    )
    write(
        outside / "workflows" / "outside-workflow-marker.yml",
        "name: outside\n"
        "jobs:\n"
        "  outside_job_marker:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - run: agent-guard context check --root .\n",
    )
    write(outside / "hooks" / "outside-hook-marker.json", '{"marker": "outside hook marker content"}\n')
    write(outside / "cursor-hooks.json", '{"marker": "outside cursor hook marker content"}\n')
    write(
        outside / "mcp.json",
        json.dumps(
            {
                "mcpServers": {
                    "outside-mcp-marker": {"command": "npx", "args": ["outside-mcp@latest"]}
                }
            }
        ),
    )
    write(outside / "codex-config.toml", '[mcp_servers.outside_codex_marker]\ncommand = "uvx"\n')
    write(outside / "path-policy.yaml", "outside policy marker content\n")

    (repo / ".github" / "skills").mkdir(parents=True)
    (repo / ".github" / "skills" / "outside-skill-marker").symlink_to(
        outside / "skills" / "outside-skill-marker",
        target_is_directory=True,
    )
    (repo / ".github" / "workflows").symlink_to(outside / "workflows", target_is_directory=True)
    (repo / ".github" / "hooks").symlink_to(outside / "hooks", target_is_directory=True)
    (repo / ".cursor").mkdir()
    (repo / ".cursor" / "hooks.json").symlink_to(outside / "cursor-hooks.json")
    (repo / ".mcp.json").symlink_to(outside / "mcp.json")
    (repo / ".codex").mkdir()
    (repo / ".codex" / "config.toml").symlink_to(outside / "codex-config.toml")
    (repo / ".agent-guard").mkdir()
    (repo / ".agent-guard" / "path-policy.yaml").symlink_to(outside / "path-policy.yaml")

    result = run_cli(
        "surface",
        "inventory",
        "--root",
        str(repo),
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
    assert by_surface == {"agent_context": 1}
    assert surfaces == [
        {
            "surface": "agent_context",
            "path": "AGENTS.md",
            "kind": "agents_md",
            "status": "scanned",
            "size_bytes": len("Require approval before shell writes.\n".encode("utf-8")),
            "line_count": 1,
        }
    ]
    for forbidden in (
        "outside-skill-marker",
        "outside skill marker content",
        "outside-workflow-marker",
        "outside_job_marker",
        "outside hook marker content",
        "outside cursor hook marker content",
        "outside-mcp-marker",
        "outside_codex_marker",
        "outside policy marker content",
        str(repo),
        str(outside),
    ):
        assert forbidden not in result.stdout
