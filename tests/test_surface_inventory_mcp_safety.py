"""Where: tests/test_surface_inventory_mcp_safety.py
What: focused package-pin inference tests for MCP surface metadata.
Why: keep only immutable, actual package operands marked as pinned.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent_guard.surface_inventory_mcp import collect_mcp_config_surfaces
from agent_guard.surface_inventory_mcp_safety import infer_version_pin


FULL_SHA256 = "a" * 64


@pytest.mark.parametrize(
    ("command", "args", "expected"),
    [
        ("npx", ["@scope/pkg@1.2.3"], True),
        ("npx", ["-y", "pkg@1.2.3"], True),
        ("npm", ["exec", "@scope/pkg@1.2.3"], True),
        ("npm", ["x", "pkg@1.2.3"], True),
        ("npm", ["--yes", "exec", "pkg"], False),
        ("npm", ["-y", "exec", "pkg@1.2.3"], True),
        ("npm", ["--quiet", "x", "--package=pkg@1.2.3", "tool"], True),
        ("npm", ["-q", "--registry", "https://registry.example", "exec", "pkg@1.2.3"], True),
        ("npm", ["--registry", "x", "exec", "pkg@1.2.3"], True),
        ("npm", ["--registry=https://registry.example", "exec", "pkg@1.2.3"], True),
        ("npm", ["--package=pkg@1.2.3", "exec", "tool"], True),
        ("npm", ["--package=pkg@1.2.3", "exec", "tool", "-p", "other@2.3.4"], True),
        ("npm", ["--package=pkg@1.2.3", "exec", "tool", "-p", "other"], True),
        ("npm", ["--unknown", "exec", "pkg@1.2.3"], False),
        ("npm", ["--unknown", "value", "exec", "pkg@1.2.3"], False),
        ("pnpm", ["dlx", "pkg@1.2.3"], True),
        ("pnpm", ["--silent", "dlx", "pkg@1.2.3"], True),
        ("pnpm", ["--silent", "dlx", "pkg"], False),
        ("pnpm", ["--reporter", "append-only", "dlx", "pkg@1.2.3"], True),
        ("pnpm", ["--package=pkg@1.2.3", "dlx", "tool"], True),
        ("pnpm", ["--package", "pkg@1.2.3", "dlx", "tool"], True),
        ("pnpm", ["--package=pkg", "dlx", "tool"], False),
        ("pnpm", ["--unknown", "dlx", "pkg@1.2.3"], False),
        ("yarn", ["dlx", "pkg@1.2.3"], True),
        ("yarn", ["--quiet", "dlx", "pkg@1.2.3"], True),
        ("yarn", ["--unknown", "dlx", "pkg@1.2.3"], False),
        ("bun", ["x", "pkg@1.2.3"], True),
        ("bun", ["--cwd", "workspace", "x", "pkg@1.2.3"], True),
        ("bun", ["--shell", "system", "x", "pkg@1.2.3"], True),
        ("bun", ["x", "--bun", "pkg@1.2.3"], True),
        ("bun", ["--unknown", "x", "pkg@1.2.3"], False),
        ("uvx", ["pkg==1"], False),
        ("uvx", ["pkg==1.2"], False),
        ("uvx", ["pkg==1.2.3rc1"], False),
        ("uvx", ["pkg==1.2.3.post1"], False),
        ("uvx", ["pkg[cli,server]==1.2.3rc1"], False),
        ("npx", [f"pkg@sha256:{FULL_SHA256}"], True),
        ("npm", ["exec", "--package=pkg@1.2.3", "-p", "tool"], True),
        ("npx", ["--package=pkg@1.2.3", "-p", "other@2.3.4", "tool"], True),
        ("pnpm", ["dlx", "--package=pkg@1.2.3", "-p", "other@2.3.4", "tool"], False),
        ("yarn", ["dlx", "--package=pkg@1.2.3", "-p", "other@2.3.4", "tool"], True),
        ("bun", ["x", "--package=safe@1.2.3", "tool"], False),
        ("bun", ["x", "-p", "safe@1.2.3", "tool"], False),
        ("bun", ["x", "--cwd", "safe@1.2.3"], False),
        ("bun", ["x", "--cwd", "workspace", "safe@1.2.3"], False),
        ("bun", ["x", "--shell", "safe@1.2.3"], False),
        ("bun", ["x", "--shell", "system", "safe@1.2.3"], False),
        ("uvx", ["--from=pkg==1.2", "-w", "other==2.3", "tool"], True),
        ("uvx", ["--with", "dep==1.2.3", "mainpkg@2.3.4"], True),
        ("uvx", ["--with", "dep==1.2.3", "mainpkg"], False),
        ("uvx", ["-w", "dep==1.2.3", "mainpkg"], False),
        ("uvx", ["--with=dep", "mainpkg==2.3.4"], False),
        ("uvx", ["--with-editable", "dep==1.2.3", "mainpkg==2.3.4"], False),
        ("uvx", ["--with", "dep==1.2.3", "--", "mainpkg"], False),
        ("uvx", ["--with", "dep==1.2.3", "--", "mainpkg@2.3.4"], True),
        ("uvx", ["--from=pkg==1.2.3", "--with=dep==2.3.4", "tool"], True),
        ("uvx", ["--from=pkg==1.2.3", "--with=dep", "tool"], False),
        ("uvx", ["--from=pkg==1.2.3", "--with-editable=dep==2.3.4", "tool"], False),
        ("npx", ["pkg@1.2.3", "--", "--package=unpinned"], True),
        ("npm", ["exec", "--package=pkg", "--", "tool"], False),
        ("npx", ["--package=pkg", "tool"], False),
        ("pnpm", ["dlx", "--package", "pkg", "tool"], False),
        ("yarn", ["dlx", "-p", "pkg", "tool"], False),
        ("uvx", ["--python", "3.12", "--from", "pkg", "tool"], False),
        ("uvx", ["--offline", "pkg"], False),
        ("uvx", ["--with-requirements", "requirements.txt", "tool"], False),
        ("uvx", ["--with-requirements=requirements.txt", "tool"], False),
        ("uvx", ["--from=pkg==1.2.3", "--with-requirements", "requirements.txt", "tool"], False),
        ("npm", ["exec", f"tool@sha256:{FULL_SHA256}", "--package=unpinned"], False),
        ("npm", ["exec", "tool", "--package=pkg@1.2.3"], True),
        ("npm", ["exec", "tool", "--package=pkg@1.2.3", "-p", "other@2.3.4"], True),
        ("npm", ["exec", "tool", "--package=pkg@1.2.3", "-p", "other"], True),
        ("npm", ["x"], False),
        ("npx", ["--package=pkg@1.2.3", "--package", "unpinned", "tool"], False),
        ("uvx", ["--from=pkg==1.2", "--with=unpinned", "tool"], False),
        ("npx", ["--package=pkg@1.2.3", "--unknown", "tool"], False),
        ("npx", ["pkg@1.2.3", "--unknown"], False),
        ("npm", ["exec", "pkg@1.2.3", "--unknown"], False),
        ("pnpm", ["dlx", "pkg@1.2.3", "--unknown"], False),
        ("yarn", ["dlx", "pkg@1.2.3", "--unknown"], False),
        ("bun", ["x", "pkg@1.2.3", "--unknown"], False),
        ("bunx", ["pkg@1.2.3", "--unknown"], False),
        ("uvx", ["pkg==1.2.3", "--unknown"], False),
        ("npx", ["pkg@1.2.3", "--", "--unknown"], True),
        ("npm", ["exec", "pkg@1.2.3", "--", "--unknown"], True),
        ("pnpm", ["dlx", "pkg@1.2.3", "--", "--unknown"], True),
        ("yarn", ["dlx", "pkg@1.2.3", "--", "--unknown"], True),
        ("bun", ["x", "pkg@1.2.3", "--", "--unknown"], True),
        ("bunx", ["pkg@1.2.3", "--", "--unknown"], True),
        ("uvx", ["pkg==1.2.3", "--", "--unknown"], False),
        ("npx", ["tool", "--package=pkg@1.2.3"], False),
        ("pnpm", ["dlx", "tool", "--package=pkg@1.2.3"], False),
        ("yarn", ["dlx", "tool", "--package=pkg@1.2.3"], False),
        ("bun", ["x", "tool", "--package=pkg@1.2.3"], False),
        ("bunx", ["tool", "--package=pkg@1.2.3"], False),
        ("uvx", ["tool", "--from=pkg==1.2.3"], False),
        ("npx", ["pkg@1"], False),
        ("npx", ["pkg@1.2"], False),
        ("npx", ["pkg@^1.2.3"], False),
        ("npx", ["pkg@~1.2.3"], False),
        ("npx", ["pkg@>=1.2.3"], False),
        ("npx", ["pkg@latest"], False),
        ("npx", ["pkg@next"], False),
        ("npx", ["pkg@1.2.3-0"], True),
        ("npx", ["pkg@1.2.3-alpha.1"], True),
        ("npx", ["pkg@1.2.3-01alpha"], True),
        ("npx", ["pkg@1.2.3+build.01"], True),
        ("npx", ["pkg@1.2.3-01"], False),
        ("npx", ["pkg@1.2.3-alpha.01"], False),
        ("npx", ["pkg@1\u0662.2.3"], False),
        ("npx", ["pkg@sha256:" + ("a" * 16)], False),
        ("npx", ["pkg", "--label", f"sha256:{FULL_SHA256}"], False),
        ("npx", ["--cache", "pkg@1.2.3", "pkg"], False),
        ("npx", [], False),
        ("npm", ["exec"], False),
        ("pnpm", ["dlx"], False),
        ("yarn", ["dlx"], False),
        ("bun", ["x"], False),
        ("bunx", [], False),
        ("bunx", ["--bun", "@scope/pkg@1.2.3"], True),
        ("bunx", ["pkg"], False),
        ("uvx", [], False),
        ("uvx", ["pkg>=1.2"], False),
        ("uvx", ["pkg==1.*"], False),
        ("uvx", ["pkg==1.2.3+\u212a"], False),
        ("uvx", ["pkg@1.2.3"], True),
        ("uvx", ["pkg@1"], True),
        ("uvx", ["--with", "dep@1.2.3", "pkg@2.3.4"], False),
        ("NPX.CMD", ["pkg"], None),
        ("uvx.exe", ["pkg"], None),
        ("npm", ["install", "pkg@1.2.3"], None),
        ("node", ["pkg@1.2.3"], None),
        ("python", ["pkg==1.2.3"], None),
        ("deno", ["pkg@1.2.3"], None),
        ("docker", [f"image@sha256:{FULL_SHA256}"], None),
    ],
)
def test_infer_version_pin_uses_only_supported_package_operands(
    command: str,
    args: list[str],
    expected: bool | None,
) -> None:
    assert infer_version_pin(command, args) is expected


def test_collect_mcp_config_surfaces_emits_unpinned_package_for_recognized_forms(tmp_path: Path) -> None:
    servers = {
        "npm-exec": {"command": "npm", "args": ["exec", "--package=pkg", "--", "tool"]},
        "npm-prefix": {"command": "npm", "args": ["--yes", "exec", "pkg"]},
        "npm-prefix-pinned": {"command": "npm", "args": ["-q", "exec", "pkg@1.2.3"]},
        "npm-selector-after-command": {
            "command": "npm",
            "args": ["exec", "tool", "--package=pkg@1.2.3"],
        },
        "npx": {"command": "npx", "args": ["--package=pkg", "tool"]},
        "latest": {"command": "npx", "args": ["pkg@latest"]},
        "mixed-case-manager": {"command": "NPX", "args": ["pkg"]},
        "windows-npx-launcher": {"command": "NPX.CMD", "args": ["pkg"]},
        "windows-uvx-launcher": {"command": "uvx.exe", "args": ["pkg"]},
        "pnpm": {"command": "pnpm", "args": ["dlx", "--package", "pkg", "tool"]},
        "pnpm-prefix": {"command": "pnpm", "args": ["--silent", "dlx", "pkg"]},
        "pnpm-prefix-pinned": {
            "command": "pnpm",
            "args": ["--silent", "dlx", "pkg@1.2.3"],
        },
        "yarn": {"command": "yarn", "args": ["dlx", "-p", "pkg", "tool"]},
        "bun-mixed": {
            "command": "bun",
            "args": ["x", "--package=pkg@1.2.3", "-p", "other", "tool"],
        },
        "bun-unsupported-selector": {
            "command": "bun",
            "args": ["x", "--package=safe@1.2.3", "tool"],
        },
        "bunx-unpinned": {"command": "bunx", "args": ["pkg"]},
        "bunx-pinned": {"command": "bunx", "args": ["--bun", "@scope/pkg@1.2.3"]},
        "semver-leading-zero": {"command": "npx", "args": ["pkg@1.2.3-01"]},
        "uvx-from": {"command": "uvx", "args": ["--python", "3.12", "--from", "pkg", "tool"]},
        "uvx-offline": {"command": "uvx", "args": ["--offline", "pkg"]},
        "uvx-package-file": {
            "command": "uvx",
            "args": ["--from=pkg==1.2.3", "--with-requirements", "requirements.txt", "tool"],
        },
        "uvx-with-unpinned-main": {
            "command": "uvx",
            "args": ["--with", "dep==1.2.3", "mainpkg"],
        },
        "uvx-with-pinned-main": {
            "command": "uvx",
            "args": ["--with", "dep==1.2.3", "mainpkg@2.3.4"],
        },
        "uvx-pinned": {"command": "uvx", "args": ["pkg@1.2.3"]},
        "pinned": {"command": "npx", "args": ["--package=pkg@1.2.3", "--", "tool"]},
        "unrelated": {"command": "node", "args": ["pkg@1.2.3"]},
    }
    (tmp_path / ".mcp.json").write_text(
        json.dumps({"mcpServers": servers}),
        encoding="utf-8",
    )

    surfaces = collect_mcp_config_surfaces(tmp_path)
    by_server = {
        surface["server_name"]: surface
        for surface in surfaces
        if surface["surface"] == "mcp_server_reference"
    }

    unpinned_servers = {
        "bun-mixed",
        "bun-unsupported-selector",
        "bunx-unpinned",
        "latest",
        "npm-exec",
        "npm-prefix",
        "npx",
        "pnpm",
        "pnpm-prefix",
        "semver-leading-zero",
        "uvx-from",
        "uvx-offline",
        "uvx-package-file",
        "uvx-with-unpinned-main",
        "yarn",
    }
    for server_name in unpinned_servers:
        assert by_server[server_name]["version_pinned"] is False
        assert "unpinned_package" in by_server[server_name]["risky_patterns"]

    for server_name in {
        "npm-prefix-pinned",
        "bunx-pinned",
        "npm-selector-after-command",
        "pinned",
        "pnpm-prefix-pinned",
        "uvx-with-pinned-main",
        "uvx-pinned",
    }:
        assert by_server[server_name]["version_pinned"] is True
        assert "unpinned_package" not in by_server[server_name].get("risky_patterns", [])

    assert "latest_package" in by_server["latest"]["risky_patterns"]
    assert by_server["mixed-case-manager"]["command_basename"] == "NPX"
    assert "package_manager" not in by_server["mixed-case-manager"]
    assert "version_pinned" not in by_server["mixed-case-manager"]
    assert by_server["windows-npx-launcher"]["command_basename"] == "NPX.CMD"
    assert "package_manager" not in by_server["windows-npx-launcher"]
    assert "version_pinned" not in by_server["windows-npx-launcher"]
    assert by_server["windows-uvx-launcher"]["command_basename"] == "uvx.exe"
    assert "package_manager" not in by_server["windows-uvx-launcher"]
    assert "version_pinned" not in by_server["windows-uvx-launcher"]
    assert "version_pinned" not in by_server["unrelated"]
    assert "unpinned_package" not in by_server["unrelated"].get("risky_patterns", [])
