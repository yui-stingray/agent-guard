"""Focused resource and path-boundary tests for surface inventory collectors."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from agent_guard.bounded_yaml import MAX_YAML_EXPANDED_BYTES
from agent_guard import surface_inventory_core
from agent_guard import surface_inventory_context
from agent_guard import surface_inventory_directories
from agent_guard import surface_inventory_metadata
from agent_guard import surface_inventory_workflow
from tests.cli.helpers import write


def test_repo_bound_glob_stops_at_shared_traversal_limit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for index in range(3):
        write(tmp_path / "docs" / f"guide-{index}.md", "guide\n")
    monkeypatch.setattr(surface_inventory_core, "MAX_SURFACE_INVENTORY_TRAVERSAL", 2)

    with pytest.raises(ValueError) as raised:
        surface_inventory_core.repo_bound_glob(tmp_path, "docs/*.md")

    assert str(raised.value) == surface_inventory_core.ERROR_SURFACE_INVENTORY_LIMIT
    assert "guide-" not in str(raised.value)


def test_directory_inventory_stops_at_shared_traversal_limit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for index in range(3):
        write(tmp_path / ".github" / "skills" / f"skill-{index}" / "SKILL.md", "safe\n")
    monkeypatch.setattr(surface_inventory_core, "MAX_SURFACE_INVENTORY_TRAVERSAL", 2)

    with pytest.raises(ValueError) as raised:
        surface_inventory_directories.collect_directory_surfaces(
            tmp_path,
            ((".github/skills", "github_copilot_skill"),),
            surface="agent_skill",
        )

    assert str(raised.value) == surface_inventory_core.ERROR_SURFACE_INVENTORY_LIMIT
    assert "skill-" not in str(raised.value)


def test_workflow_inventory_rejects_oversized_file_before_yaml(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workflow = tmp_path / ".github" / "workflows" / "oversized.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_bytes(
        b"name: "
        + b"x" * surface_inventory_core.MAX_SURFACE_INVENTORY_FILE_BYTES
        + b"\njobs: {}\n"
    )
    parsed = False

    def unexpected_yaml(*_args: object, **_kwargs: object) -> None:
        nonlocal parsed
        parsed = True

    monkeypatch.setattr(surface_inventory_workflow, "load_bounded_yaml", unexpected_yaml)

    with pytest.raises(ValueError) as raised:
        surface_inventory_workflow.collect_workflow_surfaces(tmp_path)

    assert str(raised.value) == surface_inventory_core.ERROR_SURFACE_INVENTORY_LIMIT
    assert not parsed


def test_workflow_inventory_rejects_bounded_yaml_merge_expansion(tmp_path: Path) -> None:
    write(
        tmp_path / ".github" / "workflows" / "merge.yml",
        "defaults: &defaults\n"
        "  runs-on: ubuntu-latest\n"
        "jobs:\n"
        "  test:\n"
        "    <<: *defaults\n"
        "    steps: []\n",
    )

    with pytest.raises(ValueError) as raised:
        surface_inventory_workflow.collect_workflow_surfaces(tmp_path)

    assert str(raised.value) == surface_inventory_core.ERROR_SURFACE_INVENTORY_LIMIT


def test_document_inventory_enforces_aggregate_distinct_input_limit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    write(tmp_path / "README.md", "12345678")
    write(tmp_path / "docs" / "guide.md", "abcdefgh")
    monkeypatch.setattr(
        surface_inventory_core,
        "MAX_SURFACE_INVENTORY_DISTINCT_INPUT_BYTES",
        15,
    )

    with pytest.raises(ValueError) as raised:
        surface_inventory_metadata.collect_documented_guard_surfaces(tmp_path)

    assert str(raised.value) == surface_inventory_core.ERROR_SURFACE_INVENTORY_LIMIT


def test_git_metadata_uses_shared_remaining_deadline(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ticks = iter((100.0, 104.0))
    monkeypatch.setattr(
        surface_inventory_core.time,
        "monotonic",
        lambda: next(ticks),
    )
    budget = surface_inventory_core.SurfaceInventoryBudget()
    captured: dict[str, float] = {}

    def bounded_git(
        _root: Path,
        _args: list[str],
        *,
        timeout_seconds: float,
        **_kwargs: object,
    ) -> subprocess.CompletedProcess[bytes]:
        captured["timeout_seconds"] = timeout_seconds
        return subprocess.CompletedProcess([], 0, b"", b"")

    monkeypatch.setattr(surface_inventory_metadata, "run_bounded_git", bounded_git)

    surface_inventory_metadata._run_git_metadata(
        tmp_path,
        ["status"],
        _budget=budget,
    )

    assert captured["timeout_seconds"] == 1.0


def test_agent_inventory_shares_distinct_input_budget_across_collectors(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    write(tmp_path / ".agent-guard" / "policy.yaml", "12345678")
    write(tmp_path / "README.md", "abcdefgh")
    monkeypatch.setattr(
        surface_inventory_core,
        "MAX_SURFACE_INVENTORY_DISTINCT_INPUT_BYTES",
        15,
    )

    assert surface_inventory_metadata.collect_policy_surfaces(tmp_path)
    assert surface_inventory_metadata.collect_documented_guard_surfaces(tmp_path) == []

    with pytest.raises(ValueError) as raised:
        surface_inventory_context.collect_agent_surface_inventory(
            root=tmp_path,
            context_policy={},
            schema_version="v2",
        )

    assert str(raised.value) == surface_inventory_core.ERROR_SURFACE_INVENTORY_LIMIT


def test_agent_inventory_shares_traversal_budget_across_collectors(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    write(tmp_path / ".agent-guard" / "policy.yaml", "safe\n")
    write(tmp_path / "docs" / "guide.md", "safe\n")
    monkeypatch.setattr(surface_inventory_core, "MAX_SURFACE_INVENTORY_TRAVERSAL", 1)

    assert surface_inventory_metadata.collect_policy_surfaces(tmp_path)
    assert surface_inventory_metadata.collect_documented_guard_surfaces(tmp_path) == []

    with pytest.raises(ValueError) as raised:
        surface_inventory_context.collect_agent_surface_inventory(
            root=tmp_path,
            context_policy={},
            schema_version="v2",
        )

    assert str(raised.value) == surface_inventory_core.ERROR_SURFACE_INVENTORY_LIMIT


def test_agent_inventory_shares_result_budget_across_collectors(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    write(tmp_path / ".agent-guard" / "policy.yaml", "safe\n")
    write(tmp_path / "README.md", "agent-guard context check --root .\n")

    policy_surfaces = surface_inventory_metadata.collect_policy_surfaces(tmp_path)
    documented_surfaces = surface_inventory_metadata.collect_documented_guard_surfaces(
        tmp_path
    )
    inventory = surface_inventory_context.collect_agent_surface_inventory(
        root=tmp_path,
        context_policy={},
        schema_version="v2",
    )
    direct_budget = max(
        surface_inventory_core._canonical_json_size(policy_surfaces),
        surface_inventory_core._canonical_json_size(documented_surfaces),
    )
    inventory_budget = surface_inventory_core._canonical_json_size(
        inventory["surfaces"]
    )

    monkeypatch.setattr(
        surface_inventory_core,
        "MAX_SURFACE_INVENTORY_AGGREGATE_RESULT_BYTES",
        direct_budget,
    )
    assert surface_inventory_metadata.collect_policy_surfaces(tmp_path) == policy_surfaces
    assert (
        surface_inventory_metadata.collect_documented_guard_surfaces(tmp_path)
        == documented_surfaces
    )
    with pytest.raises(ValueError) as raised:
        surface_inventory_context.collect_agent_surface_inventory(
            root=tmp_path,
            context_policy={},
            schema_version="v2",
        )
    assert str(raised.value) == surface_inventory_core.ERROR_SURFACE_INVENTORY_LIMIT

    monkeypatch.setattr(
        surface_inventory_core,
        "MAX_SURFACE_INVENTORY_AGGREGATE_RESULT_BYTES",
        inventory_budget,
    )
    assert (
        surface_inventory_context.collect_agent_surface_inventory(
            root=tmp_path,
            context_policy={},
            schema_version="v2",
        )
        == inventory
    )
    monkeypatch.setattr(
        surface_inventory_core,
        "MAX_SURFACE_INVENTORY_AGGREGATE_RESULT_BYTES",
        inventory_budget - 1,
    )
    with pytest.raises(ValueError) as raised:
        surface_inventory_context.collect_agent_surface_inventory(
            root=tmp_path,
            context_policy={},
            schema_version="v2",
        )
    assert str(raised.value) == surface_inventory_core.ERROR_SURFACE_INVENTORY_LIMIT


def test_document_inventory_enforces_incremental_result_limit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    write(
        tmp_path / "README.md",
        "agent-guard context check --root .\n"
        "agent-guard context check --root .\n",
    )
    surfaces = surface_inventory_metadata.collect_documented_guard_surfaces(tmp_path)
    one_surface_budget = surface_inventory_core._canonical_json_size(surfaces[:1])
    monkeypatch.setattr(
        surface_inventory_core,
        "MAX_SURFACE_INVENTORY_AGGREGATE_RESULT_BYTES",
        one_surface_budget,
    )

    with pytest.raises(ValueError) as raised:
        surface_inventory_metadata.collect_documented_guard_surfaces(tmp_path)

    assert str(raised.value) == surface_inventory_core.ERROR_SURFACE_INVENTORY_LIMIT


def test_agent_inventory_preserves_v1_v2_collector_compatibility(tmp_path: Path) -> None:
    write(tmp_path / "AGENTS.md", "Run local tests.\n")
    write(tmp_path / ".agent-guard" / "policy.yaml", "safe\n")
    write(tmp_path / "README.md", "agent-guard context check --root .\n")
    write(tmp_path / ".mcp.json", "{}\n")
    context_policy = {"scan": {"include": ["AGENTS.md"], "exclude": []}}

    v1 = surface_inventory_context.collect_agent_surface_inventory(
        root=tmp_path,
        context_policy=context_policy,
        schema_version="v1",
    )
    v2 = surface_inventory_context.collect_agent_surface_inventory(
        root=tmp_path,
        context_policy=context_policy,
        schema_version="v2",
    )

    assert v1["schema_version"] == "agent-guard.agent_surface_inventory.v1"
    assert v2["schema_version"] == "agent-guard.agent_surface_inventory.v2"
    assert {item["surface"] for item in v1["surfaces"]} == {
        "agent_context",
        "policy_file",
    }
    assert {item["surface"] for item in v2["surfaces"]} == {
        "agent_context",
        "documented_guard_command",
        "mcp_config",
        "policy_file",
    }
    assert v2["summary"]["surface_count"] == len(v2["surfaces"])


def test_policy_inventory_uses_policy_file_ceiling(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy = tmp_path / ".agent-guard" / "oversized.yaml"
    policy.parent.mkdir(parents=True)
    policy.write_bytes(
        b"x" * (surface_inventory_core.MAX_SURFACE_INVENTORY_POLICY_BYTES + 1)
    )
    parsed = False

    def unexpected_read(*_args: object, **_kwargs: object) -> None:
        nonlocal parsed
        parsed = True

    monkeypatch.setattr(surface_inventory_metadata, "policy_kind", unexpected_read)

    with pytest.raises(ValueError) as raised:
        surface_inventory_metadata.collect_policy_surfaces(tmp_path)

    assert str(raised.value) == surface_inventory_core.ERROR_SURFACE_INVENTORY_LIMIT
    assert not parsed


def test_workflow_inventory_fails_closed_on_external_path_swap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "repo"
    workflow = root / ".github" / "workflows" / "ci.yml"
    outside = tmp_path / "outside.yml"
    write(workflow, "name: safe\njobs: {}\n")
    write(
        outside,
        "name: outside-private-marker\n"
        "jobs:\n"
        "  leak:\n"
        "    steps:\n"
        "      - run: agent-guard drift check --root .\n",
    )
    probe = root / "symlink-probe"
    try:
        probe.symlink_to(outside)
        probe.unlink()
    except OSError:
        pytest.skip("symlink creation is unavailable")

    original_read = surface_inventory_core.read_repo_bound_bytes
    swapped = False

    def swap_before_open(path: Path, repo_root: Path, *, max_bytes: int):
        nonlocal swapped
        if path == workflow and not swapped:
            path.unlink()
            path.symlink_to(outside)
            swapped = True
        return original_read(path, repo_root, max_bytes=max_bytes)

    monkeypatch.setattr(
        surface_inventory_core,
        "read_repo_bound_bytes",
        swap_before_open,
    )

    with pytest.raises(ValueError) as raised:
        surface_inventory_workflow.collect_workflow_surfaces(root)

    assert swapped
    assert str(raised.value) == surface_inventory_core.ERROR_SURFACE_INVENTORY_INPUT
    assert "outside-private-marker" not in str(raised.value)


def test_workflow_inventory_preserves_legitimate_bounded_workflow(tmp_path: Path) -> None:
    write(
        tmp_path / ".github" / "workflows" / "ci.yml",
        "name: ci\n"
        "jobs:\n"
        "  test:\n"
        "    steps:\n"
        "      - run: agent-guard drift check --root .\n",
    )

    surfaces = surface_inventory_workflow.collect_workflow_surfaces(tmp_path)

    assert [item["surface"] for item in surfaces] == [
        "workflow_file",
        "workflow_reference",
    ]


def test_workflow_inventory_preserves_nonaliased_workflow_within_file_ceiling(
    tmp_path: Path,
) -> None:
    workflow = tmp_path / ".github" / "workflows" / "large-name.yml"
    write(
        workflow,
        "name: " + "x" * (MAX_YAML_EXPANDED_BYTES + 1) + "\njobs: {}\n",
    )

    surfaces = surface_inventory_workflow.collect_workflow_surfaces(tmp_path)

    assert workflow.stat().st_size <= surface_inventory_core.MAX_SURFACE_INVENTORY_FILE_BYTES
    assert surfaces == [
        {
            "surface": "workflow_file",
            "path": ".github/workflows/large-name.yml",
            "kind": "github_actions",
            "status": "scanned",
        }
    ]


def test_workflow_inventory_preserves_internal_symlink_control(tmp_path: Path) -> None:
    workflow = tmp_path / "shared" / "ci.yml"
    write(
        workflow,
        "name: ci\n"
        "jobs:\n"
        "  test:\n"
        "    steps:\n"
        "      - run: agent-guard drift check --root .\n",
    )
    alias = tmp_path / ".github" / "workflows" / "ci.yml"
    alias.parent.mkdir(parents=True)
    try:
        alias.symlink_to("../../shared/ci.yml")
    except OSError:
        pytest.skip("symlink creation is unavailable")

    surfaces = surface_inventory_workflow.collect_workflow_surfaces(tmp_path)

    assert [item["path"] for item in surfaces] == ["shared/ci.yml", "shared/ci.yml"]
