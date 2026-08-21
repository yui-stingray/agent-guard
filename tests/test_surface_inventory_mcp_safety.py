"""Where: tests/test_surface_inventory_mcp_safety.py
What: focused package-pin inference tests for MCP surface metadata.
Why: keep only immutable, actual package operands marked as pinned.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent_guard.bounded_scan import run_isolated_scan
from agent_guard.content_guard import MAX_CONTENT_LINE_CHARS
from agent_guard.surface_inventory_mcp import collect_mcp_config_surfaces
from agent_guard.surface_inventory_mcp_safety import (
    command_basename,
    command_inline_args,
    has_latest_package_operand,
    infer_version_pin,
    is_npm_full_semver,
)


FULL_SHA256 = "a" * 64
NPM_SEMVER_MAX_SAFE_INTEGER = "9007199254740991"
NPM_SEMVER_AT_LENGTH_LIMIT = "1.2.3+" + ("a" * (256 - len("1.2.3+")))
NPM_SEMVER_OVER_LENGTH_LIMIT = "1.2.3+" + ("a" * (257 - len("1.2.3+")))


@pytest.mark.parametrize(
    ("command", "expected_basename", "expected_args"),
    (
        (r"tools\npx.cmd", "npx.cmd", []),
        (r"C:\Program Files\nodejs\npx.cmd", "npx.cmd", []),
        (r"C:\Program Files\nodejs\npx.cmd --yes pkg@1.2.3", "npx.cmd", ["--yes", "pkg@1.2.3"]),
        (r'"C:\Program Files\nodejs\npx.cmd" --yes pkg@1.2.3', "npx.cmd", ["--yes", "pkg@1.2.3"]),
        ("npx --yes pkg@1.2.3", "npx", ["--yes", "pkg@1.2.3"]),
        ("npx --package 'pkg@1.2.3' tool", "npx", ["--package", "pkg@1.2.3", "tool"]),
        (r"npx foo\bar.cmd", "npx", ["foobar.cmd"]),
        (r"env FLAG=1 tools\npx.cmd", "env", ["FLAG=1", "toolsnpx.cmd"]),
        ("'npx'\\''shim' --yes pkg@1.2.3", "npx'shim", ["--yes", "pkg@1.2.3"]),
    ),
)
def test_windows_launcher_paths_are_parsed_before_posix_shell_lexing(
    command: str,
    expected_basename: str,
    expected_args: list[str],
) -> None:
    assert command_basename(command) == expected_basename
    assert command_inline_args(command) == expected_args


@pytest.mark.parametrize(
    ("command", "args", "expected"),
    [
        ("npx", ["@scope/pkg@1.2.3-alpha.1+build.5"], True),
        ("npx", ["-y", "pkg@1.2.3"], True),
        ("npx", ["--loglevel=silent", "pkg@1.2.3"], True),
        ("npx", ["-C", "exec", "pkg@1.2.3"], True),
        ("npx", ["-C=exec", "pkg@1.2.3"], True),
        ("npx", ["-C=pkg@1.2.3", "pkg"], False),
        ("npx", ["--userconfig=exec", "pkg@1.2.3"], True),
        ("npx", [f"pkg@{NPM_SEMVER_MAX_SAFE_INTEGER}.0.0"], True),
        ("npx", ["pkg@9007199254740992.0.0"], False),
        ("npx", [f"pkg@{NPM_SEMVER_AT_LENGTH_LIMIT}"], True),
        ("npx", [f"pkg@{NPM_SEMVER_OVER_LENGTH_LIMIT}"], False),
        ("npm", ["exec", "@scope/pkg@1.2.3"], True),
        ("npm", ["x", "pkg@1.2.3"], True),
        ("npm", ["--yes", "exec", "pkg"], False),
        ("npm", ["-y", "exec", "pkg@1.2.3"], True),
        ("npm", ["--quiet", "x", "--package=pkg@1.2.3", "tool"], True),
        ("npm", ["-q", "--registry", "https://registry.example", "exec", "pkg@1.2.3"], True),
        ("npm", ["--registry", "x", "exec", "pkg@1.2.3"], True),
        ("npm", ["--registry=https://registry.example", "exec", "pkg@1.2.3"], True),
        ("npm", ["-C", "exec", "exec", "--", "pkg@1.2.3"], True),
        ("npm", ["-C=exec", "exec", "--", "pkg@1.2.3"], True),
        ("npm", ["-C=exec", "ignored@1.2.3"], None),
        ("npm", ["--prefix", "exec", "exec", "--", "pkg@1.2.3"], True),
        ("npm", ["--prefix=exec", "x", "--", "pkg@1.2.3"], True),
        ("npm", ["--userconfig", "exec", "exec", "--", "pkg@1.2.3"], True),
        ("npm", ["--userconfig=exec", "x", "--", "pkg@1.2.3"], True),
        ("npm", ["--prefix", "exec", "ignored@1.2.3"], None),
        ("npm", ["--userconfig", "exec", "ignored@1.2.3"], None),
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
        ("npx", [f"pkg@sha256:{FULL_SHA256}"], False),
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
        ("uvx", ["--color=always", "pkg@1.2.3"], True),
        ("uvx", ["--color", "always", "pkg@1.2.3"], True),
        ("uvx", ["--color", "always", "pkg@1.2.3", "--", "ignored@latest"], True),
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
        ("npx", ["pkg@1.2.3", "--unknown"], True),
        ("npm", ["exec", "pkg@1.2.3", "--unknown"], False),
        ("pnpm", ["dlx", "pkg@1.2.3", "--unknown"], True),
        ("yarn", ["dlx", "pkg@1.2.3", "--unknown"], True),
        ("bun", ["x", "pkg@1.2.3", "--unknown"], True),
        ("bunx", ["pkg@1.2.3", "--unknown"], True),
        ("uvx", ["pkg==1.2.3", "--unknown"], False),
        ("uvx", ["pkg@1.2.3", "--stdio"], True),
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
        ("NPX", ["pkg@1.2.3"], True),
        ("NPX.CMD", ["pkg"], False),
        ("uvx.exe", ["pkg"], False),
        ("BUNX.PS1", ["pkg@1.2.3"], True),
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


def test_is_npm_full_semver_enforces_npm_numeric_and_length_boundaries() -> None:
    assert len(NPM_SEMVER_AT_LENGTH_LIMIT) == 256
    assert len(NPM_SEMVER_OVER_LENGTH_LIMIT) == 257
    assert is_npm_full_semver(f"{NPM_SEMVER_MAX_SAFE_INTEGER}.0.0")
    assert not is_npm_full_semver("9007199254740992.0.0")
    assert not is_npm_full_semver("1.9007199254740992.0")
    assert not is_npm_full_semver("1.2.9007199254740992")
    assert is_npm_full_semver("1.2.3-9007199254740992")
    assert is_npm_full_semver(NPM_SEMVER_AT_LENGTH_LIMIT)
    assert not is_npm_full_semver(NPM_SEMVER_OVER_LENGTH_LIMIT)


def test_infer_version_pin_rejects_long_malformed_semver_within_scan_budget() -> None:
    prefix = "pkg@1.2.3-"
    malformed_operand = prefix + ("a" * (MAX_CONTENT_LINE_CHARS - len(prefix) - 1)) + "!"

    assert len(malformed_operand) == MAX_CONTENT_LINE_CHARS
    assert (
        run_isolated_scan(
            infer_version_pin,
            "npx",
            [malformed_operand],
            timeout_error="pin inference exceeded execution budget",
            runtime_error="pin inference could not complete safely",
        )
        is False
    )


@pytest.mark.parametrize(
    ("command", "args"),
    [
        ("npx", [f"pkg@sha256:{FULL_SHA256}"]),
        ("npm", ["exec", f"pkg@sha256:{FULL_SHA256}"]),
        ("pnpm", ["dlx", f"pkg@sha256:{FULL_SHA256}"]),
        ("yarn", ["dlx", f"pkg@sha256:{FULL_SHA256}"]),
        ("bun", ["x", f"pkg@sha256:{FULL_SHA256}"]),
        ("bunx", [f"pkg@sha256:{FULL_SHA256}"]),
    ],
)
def test_infer_version_pin_rejects_unsupported_js_sha256_selectors(
    command: str,
    args: list[str],
) -> None:
    assert infer_version_pin(command, args) is False


def test_has_latest_package_operand_recovers_npm_operand_after_global_option_prefix() -> None:
    args = ["--loglevel=silent", "exec", "--", "pkg@latest"]

    assert infer_version_pin("npm", args) is False
    assert has_latest_package_operand("npm", args) is True


@pytest.mark.parametrize(
    ("command", "args", "expected"),
    [
        ("npx", ["pkg@latest"], True),
        ("npx", ["--loglevel=silent", "pkg@latest"], True),
        ("npx", ["-C", "exec", "pkg@latest"], True),
        ("npx", ["-C=exec", "pkg@latest"], True),
        ("npx", ["-C=ignored@latest", "pkg@1.2.3"], False),
        ("npx", ["--userconfig=exec", "pkg@latest"], True),
        ("npx", ["--package=@scope/pkg@latest", "tool"], True),
        ("npx", ["pkg@1.2.3", "--", "--label", "ignored@latest"], False),
        ("npx", ["--cache", "ignored@latest", "pkg@1.2.3"], False),
        ("npx", ["--userconfig", "ignored@latest", "pkg@1.2.3"], False),
        ("npm", ["exec", "tool", "--package=pkg@latest"], True),
        ("npm", ["-C", "exec", "exec", "--", "pkg@latest"], True),
        ("npm", ["-C=exec", "exec", "--", "pkg@latest"], True),
        ("npm", ["-C=exec", "ignored@latest"], False),
        ("npm", ["--prefix", "exec", "exec", "--", "pkg@latest"], True),
        ("npm", ["--prefix=exec", "x", "--", "pkg@latest"], True),
        ("npm", ["--userconfig", "exec", "exec", "--", "pkg@latest"], True),
        ("npm", ["--userconfig=exec", "x", "--", "pkg@latest"], True),
        ("npm", ["--prefix", "exec", "ignored@latest"], False),
        ("npm", ["--userconfig", "exec", "ignored@latest"], False),
        ("npm", ["--unknown", "exec", "pkg@latest"], False),
        ("npm", ["exec", "pkg@1.2.3", "--", "ignored@latest"], False),
        (
            "npm",
            ["--loglevel=silent", "exec", "--", "pkg@1.2.3", "ignored@latest"],
            False,
        ),
        (
            "npm",
            ["--loglevel", "ignored@latest", "exec", "--", "pkg@1.2.3"],
            False,
        ),
        ("pnpm", ["--package=pkg@latest", "dlx", "tool"], True),
        ("pnpm", ["dlx", "pkg@1.2.3", "--", "ignored@latest"], False),
        ("yarn", ["dlx", "-p", "pkg@latest", "tool"], True),
        ("yarn", ["dlx", "pkg@1.2.3", "--", "ignored@latest"], False),
        ("bun", ["x", "pkg@latest"], True),
        ("bun", ["x", "pkg@1.2.3", "--", "ignored@latest"], False),
        ("uvx", ["--color=always", "pkg@latest"], True),
        ("uvx", ["--color", "always", "pkg@latest"], True),
        ("uvx", ["--color", "always", "pkg@1.2.3", "--", "ignored@latest"], False),
        ("uvx", ["--from=pkg@latest", "tool"], True),
        ("uvx", ["pkg@1.2.3", "--", "ignored@latest"], False),
        ("node", ["ignored@latest"], False),
    ],
)
def test_has_latest_package_operand_uses_recognized_package_boundaries(
    command: str,
    args: list[str],
    expected: bool,
) -> None:
    assert has_latest_package_operand(command, args) is expected


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
        "latest-selector": {"command": "npx", "args": ["--package=pkg@latest", "tool"]},
        "latest-trailing": {
            "command": "npx",
            "args": ["pkg@1.2.3", "--", "--label", "ignored@latest"],
        },
        "latest-option": {
            "command": "npx",
            "args": ["--cache", "ignored@latest", "pkg@1.2.3"],
        },
        "latest-non-launcher": {"command": "node", "args": ["ignored@latest"]},
        "mixed-case-manager": {"command": "NPX", "args": ["pkg"]},
        "windows-npx-launcher": {"command": "NPX.CMD", "args": ["pkg"]},
        "windows-relative-npx-launcher": {
            "command": r"tools\npx.cmd",
            "args": ["pkg"],
        },
        "windows-absolute-npx-launcher": {
            "command": r"C:\Program Files\nodejs\npx.cmd",
            "args": ["pkg@1.2.3"],
        },
        "windows-quoted-inline-npx-launcher": {
            "command": r'"C:\Program Files\nodejs\npx.cmd" --yes pkg@1.2.3',
        },
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
        "latest-selector",
        "mixed-case-manager",
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
        "windows-npx-launcher",
        "windows-relative-npx-launcher",
        "windows-uvx-launcher",
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
        "windows-absolute-npx-launcher",
        "windows-quoted-inline-npx-launcher",
    }:
        assert by_server[server_name]["version_pinned"] is True
        assert "unpinned_package" not in by_server[server_name].get("risky_patterns", [])

    for server_name in {"latest", "latest-selector"}:
        assert "latest_package" in by_server[server_name]["risky_patterns"]
    for server_name in {"latest-trailing", "latest-option", "latest-non-launcher"}:
        assert "latest_package" not in by_server[server_name].get("risky_patterns", [])
    assert by_server["mixed-case-manager"]["command_basename"] == "NPX"
    assert by_server["mixed-case-manager"]["package_manager"] == "npx"
    assert by_server["windows-npx-launcher"]["command_basename"] == "NPX.CMD"
    assert by_server["windows-npx-launcher"]["package_manager"] == "npx"
    assert by_server["windows-relative-npx-launcher"]["command_basename"] == "npx.cmd"
    assert by_server["windows-relative-npx-launcher"]["package_manager"] == "npx"
    assert by_server["windows-absolute-npx-launcher"]["command_basename"] == "npx.cmd"
    assert by_server["windows-absolute-npx-launcher"]["package_manager"] == "npx"
    assert by_server["windows-quoted-inline-npx-launcher"]["command_basename"] == "npx.cmd"
    assert by_server["windows-quoted-inline-npx-launcher"]["package_manager"] == "npx"
    assert by_server["windows-uvx-launcher"]["command_basename"] == "uvx.exe"
    assert by_server["windows-uvx-launcher"]["package_manager"] == "uvx"
    assert r"tools\npx.cmd" not in str(surfaces)
    assert r"C:\Program Files\nodejs\npx.cmd" not in str(surfaces)
    assert "version_pinned" not in by_server["unrelated"]
    assert "unpinned_package" not in by_server["unrelated"].get("risky_patterns", [])
