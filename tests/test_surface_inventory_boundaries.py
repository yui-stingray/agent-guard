"""Focused resource and path-boundary tests for surface inventory collectors."""

from __future__ import annotations

from pathlib import Path

import pytest

from agent_guard import surface_inventory_core
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
