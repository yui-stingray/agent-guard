"""Exercise native Windows final-handle containment for repository readers."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

from agent_guard import (
    api_guard,
    bounded_repo_reader,
    content_guard,
    evidence_pack,
    report_render,
    surface_inventory_mcp,
    workflow_guard,
)
from agent_guard.consumer import validate_agent_policy_audit_event_files


WINDOWS_ONLY = pytest.mark.skipif(os.name != "nt", reason="requires native Windows handles")
POSIX_ONLY = pytest.mark.skipif(os.name == "nt", reason="requires POSIX directory descriptors")
AUDIT_EVENT_PROFILE = "agent-guard.public_agent_policy_audit_event.v1"


@POSIX_ONLY
def test_posix_directory_handoff_closes_new_descriptor_when_previous_close_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    opened_fds = iter((100, 101))
    open_calls: list[tuple[object, int | None]] = []
    close_calls: list[int] = []

    def fake_open(path: object, flags: int, *, dir_fd: int | None = None) -> int:
        open_calls.append((path, dir_fd))
        return next(opened_fds)

    def fake_close(file_fd: int) -> None:
        close_calls.append(file_fd)
        if len(close_calls) == 1:
            raise OSError("synthetic previous descriptor close failure")

    monkeypatch.setattr(bounded_repo_reader.os, "open", fake_open)
    monkeypatch.setattr(bounded_repo_reader.os, "close", fake_close)
    monkeypatch.setattr(bounded_repo_reader.os, "supports_dir_fd", {fake_open})

    with pytest.raises(bounded_repo_reader.BoundedRepoReadError):
        bounded_repo_reader._open_repo_file_posix(
            Path("repo"),
            Path("nested/file.txt"),
        )

    assert open_calls == [(Path("repo"), None), ("nested", 100)]
    assert close_calls == [100, 101]


@POSIX_ONLY
def test_posix_final_directory_close_failure_also_closes_file_descriptor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    opened_fds = iter((100, 101))
    close_calls: list[int] = []

    def fake_open(path: object, flags: int, *, dir_fd: int | None = None) -> int:
        return next(opened_fds)

    def fake_close(file_fd: int) -> None:
        close_calls.append(file_fd)
        if file_fd == 100:
            raise OSError("synthetic directory close failure")

    monkeypatch.setattr(bounded_repo_reader.os, "open", fake_open)
    monkeypatch.setattr(bounded_repo_reader.os, "close", fake_close)
    monkeypatch.setattr(bounded_repo_reader.os, "fstat", lambda _fd: os.stat(__file__))
    monkeypatch.setattr(bounded_repo_reader.os, "supports_dir_fd", {fake_open})

    with pytest.raises(bounded_repo_reader.BoundedRepoReadError):
        bounded_repo_reader._open_repo_file_posix(Path("repo"), Path("file.txt"))

    assert close_calls == [100, 101]


def _extended_windows_path(path: Path) -> Path:
    raw_path = str(path.resolve(strict=True))
    if raw_path.startswith("\\\\?\\"):
        return Path(raw_path)
    if raw_path.startswith("\\\\"):
        return Path("\\\\?\\UNC\\" + raw_path[2:])
    return Path("\\\\?\\" + raw_path)


def _volume_guid_windows_path(path: Path) -> Path:
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    get_volume_path_name = kernel32.GetVolumePathNameW
    get_volume_path_name.argtypes = [wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD]
    get_volume_path_name.restype = wintypes.BOOL
    get_volume_name = kernel32.GetVolumeNameForVolumeMountPointW
    get_volume_name.argtypes = [wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD]
    get_volume_name.restype = wintypes.BOOL

    # Both APIs document MAX_PATH-sized volume names.
    capacity = 261
    volume_path = ctypes.create_unicode_buffer(capacity)
    resolved_path = path.resolve(strict=True)
    if not get_volume_path_name(str(resolved_path), volume_path, capacity):
        raise ctypes.WinError(ctypes.get_last_error())
    volume_name = ctypes.create_unicode_buffer(capacity)
    if not get_volume_name(volume_path.value, volume_name, capacity):
        raise ctypes.WinError(ctypes.get_last_error())
    relative_path = os.path.relpath(resolved_path, volume_path.value)
    return Path(volume_name.value) / relative_path


@WINDOWS_ONLY
def test_windows_repo_bound_readers_accept_in_root_regular_files(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    api_path = repo / "src" / "api.py"
    content_path = repo / "docs" / "note.md"
    workflow_path = repo / ".github" / "workflows" / "ci.yml"
    bounded_context_path = repo / "context" / "AGENTS.md"
    bounded_mcp_path = repo / ".mcp.json"
    audit_event_path = repo / "reviewed" / "policy-admission-event.json"
    for path, text in (
        (api_path, "def handler():\n    return 'ok'\n"),
        (content_path, "Reviewed documentation.\n"),
        (workflow_path, "name: ci\njobs: {}\n"),
        (bounded_context_path, "Require approval before writes.\n"),
        (bounded_mcp_path, '{"mcpServers":{}}\n'),
        (
            audit_event_path,
            '{"repo":"example/repo","capability":"read","context":{},'
            '"decision":{"mode":"auto_allow","reason":"repo_policy",'
            '"matched_repo":"example/repo"}}\n',
        ),
    ):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(text.encode("utf-8"))

    api_text, api_relative = api_guard._read_repo_text(api_path, repo)
    assert api_text == "def handler():\n    return 'ok'\n"
    assert api_relative == "src/api.py"
    assert content_guard._read_scan_text(content_path, repo) == "Reviewed documentation.\n"
    assert workflow_guard._read_repo_bound_bytes(
        workflow_path,
        repo,
        max_bytes=1024,
    ) == b"name: ci\njobs: {}\n"
    context_read = bounded_repo_reader.read_repo_bound_bytes(
        bounded_context_path,
        repo,
        max_bytes=1024,
    )
    assert context_read.data == b"Require approval before writes.\n"
    assert context_read.relative_path == "context/AGENTS.md"
    mcp_read = bounded_repo_reader.read_repo_bound_bytes(
        bounded_mcp_path,
        repo,
        max_bytes=1024,
    )
    assert mcp_read.data == b'{"mcpServers":{}}\n'
    assert mcp_read.relative_path == ".mcp.json"
    artifacts = evidence_pack.build_agent_policy_audit_event_artifacts(
        ["reviewed/policy-admission-event.json"],
        event_profile=AUDIT_EVENT_PROFILE,
        root=repo,
    )
    validate_agent_policy_audit_event_files(
        {
            "evidence_pack_manifest": {
                "schema_version": "agent-guard.evidence_pack_manifest.v2",
                "artifacts": artifacts,
            }
        },
        (str(audit_event_path),),
        event_profile=AUDIT_EVENT_PROFILE,
        repo_root=repo,
    )
    validate_agent_policy_audit_event_files(
        {
            "evidence_pack_manifest": {
                "schema_version": "agent-guard.evidence_pack_manifest.v2",
                "artifacts": artifacts,
            }
        },
        ("reviewed/policy-admission-event.json",),
        event_profile=AUDIT_EVENT_PROFILE,
        repo_root=repo,
    )


@WINDOWS_ONLY
@pytest.mark.parametrize("root_form", ("extended", "volume-guid"))
def test_windows_repo_bound_reader_accepts_prefix_preserving_root_forms(
    tmp_path: Path,
    root_form: str,
) -> None:
    repo = tmp_path / "repo"
    target = repo / "nested" / "payload.txt"
    target.parent.mkdir(parents=True)
    target.write_bytes(b"bounded payload\n")
    alternate_root = (
        _extended_windows_path(repo)
        if root_form == "extended"
        else _volume_guid_windows_path(repo)
    )

    opened = bounded_repo_reader.read_repo_bound_bytes(
        alternate_root / "nested" / "payload.txt",
        alternate_root,
        max_bytes=1024,
    )

    assert opened.data == b"bounded payload\n"
    assert opened.relative_path == "nested/payload.txt"


@WINDOWS_ONLY
def test_windows_mcp_wildcard_discovery_is_case_insensitive(tmp_path: Path) -> None:
    config_path = tmp_path / ".claude" / "Settings-CI.JSON"
    config_path.parent.mkdir(parents=True)
    config_path.write_text('{"mcpServers":{}}', encoding="utf-8")

    surfaces = surface_inventory_mcp.collect_mcp_config_surfaces(tmp_path)

    assert any(item.get("path") == ".claude/Settings-CI.JSON" for item in surfaces)


@WINDOWS_ONLY
def test_windows_mcp_launcher_paths_preserve_package_metadata_without_disclosure(
    tmp_path: Path,
) -> None:
    launcher = r"C:\Program Files\nodejs\npx.cmd"
    (tmp_path / ".mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "native": {
                        "command": launcher,
                        "args": ["pkg@1.2.3"],
                    }
                }
            }
        ),
        encoding="utf-8",
    )

    surfaces = surface_inventory_mcp.collect_mcp_config_surfaces(tmp_path)
    native = next(
        item
        for item in surfaces
        if item.get("surface") == "mcp_server_reference"
        and item.get("server_name") == "native"
    )

    assert native["command_basename"] == "npx.cmd"
    assert native["package_manager"] == "npx"
    assert native["version_pinned"] is True
    assert launcher not in str(native)
    assert "Program Files" not in str(native)


@WINDOWS_ONLY
def test_windows_report_output_renames_the_open_temp_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    real_rename = report_render._windows_rename_open_file

    def race_temp_path(
        file_fd: int,
        *,
        directory_handle: int,
        final_name: str,
    ) -> None:
        temp_path = next(repo.glob(".agent-guard-*.tmp"))
        displaced = repo / "displaced.tmp"
        os.replace(temp_path, displaced)
        temp_path.write_text("attacker\n", encoding="utf-8")
        real_rename(
            file_fd,
            directory_handle=directory_handle,
            final_name=final_name,
        )

    monkeypatch.setattr(report_render, "_windows_rename_open_file", race_temp_path)

    report_render.emit_report_output("public\n", "report.txt", root=repo)

    assert (repo / "report.txt").read_text(encoding="utf-8") == "public\n"
    assert next(repo.glob(".agent-guard-*.tmp")).read_text(encoding="utf-8") == "attacker\n"


@WINDOWS_ONLY
def test_windows_repo_bound_readers_reject_outside_junction(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    outside = tmp_path / "outside"
    repo.mkdir()
    outside.mkdir()
    (outside / "payload.txt").write_text("synthetic external payload\n", encoding="utf-8")
    junction = repo / "linked"
    created = subprocess.run(
        ["cmd", "/d", "/c", "mklink", "/J", str(junction), str(outside)],
        capture_output=True,
        text=True,
        check=False,
    )
    if created.returncode != 0:
        pytest.fail("Windows junction setup failed")

    linked = junction / "payload.txt"
    resolved_root = repo.resolve(strict=True)
    try:
        with pytest.raises(ValueError, match="^api scan target must stay under repo root$"):
            api_guard._read_repo_text(linked, repo)
        with pytest.raises(ValueError, match="^content scan target must stay under repo root$"):
            content_guard._read_scan_text(linked, repo)
        with pytest.raises(ValueError, match="^workflow scan target must stay under repo root$"):
            workflow_guard._read_repo_bound_bytes(linked, repo, max_bytes=1024)
        with pytest.raises(bounded_repo_reader.BoundedRepoContainmentError):
            bounded_repo_reader.read_repo_bound_bytes(linked, repo, max_bytes=1024)
        with pytest.raises(
            ValueError,
            match="^agent-policy audit event must be a repository file$",
        ):
            evidence_pack.build_agent_policy_audit_event_binding(
                linked,
                event_profile=AUDIT_EVENT_PROFILE,
                repo_root=repo,
            )
        with pytest.raises(ValueError, match="^report output path is unsafe$"):
            report_render.emit_report_output(
                "public\n",
                "linked/report.txt",
                root=repo,
            )
        assert not (outside / "report.txt").exists()

        # The final-handle check also rejects an already-external path passed
        # directly to the opener, independently of caller-side resolution.
        with pytest.raises(ValueError, match="^api scan target must stay under repo root$"):
            api_guard._open_repo_file_windows(resolved_root, linked)
        with pytest.raises(ValueError, match="^content scan target must stay under repo root$"):
            content_guard._open_repo_file_windows(resolved_root, linked)
        with pytest.raises(ValueError, match="^workflow scan target must stay under repo root$"):
            workflow_guard._open_repo_file_windows(resolved_root, linked)
        with pytest.raises(bounded_repo_reader.BoundedRepoContainmentError):
            bounded_repo_reader._open_repo_file_windows(resolved_root, linked)
    finally:
        junction.rmdir()
