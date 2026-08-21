"""Where: src/agent_guard/surface_inventory_mcp.py
What: static MCP config surface inventory.
Why: expose sanitized MCP config metadata without raw commands, URLs, or secret values.
"""

from __future__ import annotations

import json
import re
import tomllib
from collections.abc import Sequence
from pathlib import Path
from urllib.parse import parse_qsl, urlparse

from .surface_inventory_core import is_repo_bound_path, rel_path, repo_bound_glob
from .surface_inventory_mcp_safety import (
    AUTH_OPTION_RE,
    BROAD_AUTHORIZATION_SCOPE_VALUES,
    MCP_URL_KEYS,
    SCOPE_FIELD_NAMES,
    SECRET_SHAPED_VALUE,
    command_basename,
    command_inline_args,
    contains_filesystem_root,
    extract_remote_host,
    has_latest_package_operand,
    has_unsafe_mcp_url_scheme,
    has_instruction_like_description,
    infer_transport,
    infer_version_pin,
    is_authorization_field_name,
    is_env_reference,
    is_inline_auth_literal,
    normalized_auth_field_name,
    normalized_package_manager_command,
    safe_mcp_command_basename,
    safe_mcp_env_var_name,
    safe_mcp_remote_host,
    safe_mcp_server_name,
    string_list,
    string_values,
)


MCP_CONFIG_FILES = (
    (".codex/config.toml", "codex_mcp_config"),
    (".mcp.json", "mcp_config"),
    ("mcp.json", "mcp_config"),
    (".cursor/mcp.json", "cursor_mcp_config"),
    (".vscode/mcp.json", "vscode_mcp_config"),
    (".gemini/settings.json", "gemini_mcp_config"),
    (".claude/settings*.json", "claude_mcp_config"),
)


def load_structured_config(path: Path) -> object:
    if not path.is_file():
        raise FileNotFoundError(path)
    if path.suffix == ".toml":
        with path.open("rb") as handle:
            return tomllib.load(handle)
    return json.loads(path.read_text(encoding="utf-8"))


def iter_mcp_config_files(
    root: Path,
    *,
    opaque_directories: Sequence[str] = (),
) -> list[tuple[Path, str]]:
    files: list[tuple[Path, str]] = []
    for pattern, kind in MCP_CONFIG_FILES:
        for path in sorted(
            repo_bound_glob(
                root,
                pattern,
                opaque_directories=opaque_directories,
            )
        ):
            if path.is_file():
                files.append((path, kind))
    return files


def contains_inline_authorization_value(value: object) -> bool:
    if isinstance(value, dict):
        for key, child in value.items():
            if is_authorization_field_name(key):
                if any(is_inline_auth_literal(item) for item in string_values(child)):
                    return True
            elif contains_inline_authorization_value(child):
                return True
    elif isinstance(value, list):
        return any(contains_inline_authorization_value(child) for child in value)
    return False


def contains_inline_authorization_arg(args: list[str]) -> bool:
    for index, arg in enumerate(args):
        if not AUTH_OPTION_RE.match(arg):
            continue
        if "=" in arg:
            value = arg.split("=", 1)[1]
        elif index + 1 < len(args) and not args[index + 1].startswith("-"):
            value = args[index + 1]
        else:
            continue
        if is_inline_auth_literal(value):
            return True
    return False


def contains_inline_authorization_url_value(raw: dict[str, object]) -> bool:
    for key in MCP_URL_KEYS:
        value = raw.get(key)
        if not isinstance(value, str):
            continue
        parsed = urlparse(value.strip())
        for query_key, query_value in parse_qsl(parsed.query, keep_blank_values=False):
            if is_authorization_field_name(query_key) and is_inline_auth_literal(query_value):
                return True
    return False


def is_scope_field_name(name: object) -> bool:
    normalized = normalized_auth_field_name(name)
    if normalized in SCOPE_FIELD_NAMES:
        return True
    return normalized.endswith("_scope") or normalized.endswith("_scopes")


def scope_values(value: object) -> list[str]:
    values: list[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            if is_scope_field_name(key):
                values.extend(string_values(child))
            else:
                values.extend(scope_values(child))
    elif isinstance(value, list):
        for child in value:
            values.extend(scope_values(child))
    return values


def has_broad_authorization_scope(raw: dict[str, object]) -> bool:
    for value in scope_values(raw):
        for token in re.split(r"[\s,]+", value.strip().lower()):
            cleaned = token.strip("'\"[](){}")
            if not cleaned:
                continue
            if "*" in cleaned or cleaned in BROAD_AUTHORIZATION_SCOPE_VALUES:
                return True
            if cleaned.startswith("admin:") or cleaned.endswith(":admin"):
                return True
    return False


def mcp_server_maps(config: object) -> dict[str, object]:
    if not isinstance(config, dict):
        return {}
    for key in ("mcpServers", "mcp_servers", "servers"):
        value = config.get(key)
        if isinstance(value, dict):
            return value
    return {}


def collect_mcp_config_surfaces(
    root: Path,
    *,
    opaque_directories: Sequence[str] = (),
) -> list[dict[str, object]]:
    surfaces: list[dict[str, object]] = []
    for path, kind in iter_mcp_config_files(
        root,
        opaque_directories=opaque_directories,
    ):
        if not is_repo_bound_path(path, root):
            continue
        display_path = rel_path(path, root)
        try:
            loaded = load_structured_config(path)
        except Exception:
            surfaces.append(
                {
                    "surface": "mcp_config",
                    "path": display_path,
                    "kind": kind,
                    "status": "parse_error",
                }
            )
            continue
        surfaces.append(
            {
                "surface": "mcp_config",
                "path": display_path,
                "kind": kind,
                "status": "present",
                "size_bytes": path.stat().st_size,
            }
        )
        for server_name, raw_server in sorted(mcp_server_maps(loaded).items()):
            if not isinstance(raw_server, dict):
                continue
            command = safe_mcp_command_basename(command_basename(raw_server.get("command")))
            args = command_inline_args(raw_server.get("command")) + string_list(raw_server.get("args"))
            env = raw_server.get("env")
            env_vars = (
                sorted({name for name in (safe_mcp_env_var_name(key) for key in env.keys()) if name})
                if isinstance(env, dict)
                else []
            )
            remote_host = safe_mcp_remote_host(extract_remote_host(raw_server))
            transport = infer_transport(raw_server, remote_host, command)
            version_pinned = infer_version_pin(command, args)
            package_manager = normalized_package_manager_command(command)
            all_strings = string_values(raw_server)
            metadata_strings = [*all_strings, *args]
            risky_patterns: set[str] = set()
            if has_latest_package_operand(command, args):
                risky_patterns.add("latest_package")
            if package_manager and version_pinned is False:
                risky_patterns.add("unpinned_package")
            if has_unsafe_mcp_url_scheme(raw_server):
                risky_patterns.add("unsafe_url_scheme")
            if (
                contains_inline_authorization_arg(args)
                or contains_inline_authorization_url_value(raw_server)
                or contains_inline_authorization_value(raw_server)
            ):
                risky_patterns.add("inline_authorization_value")
            if has_broad_authorization_scope(raw_server):
                risky_patterns.add("broad_authorization_scope")
            if has_instruction_like_description(raw_server):
                risky_patterns.add("instruction_like_description")
            has_filesystem_root = any(contains_filesystem_root(item) for item in metadata_strings)
            if has_filesystem_root:
                risky_patterns.add("filesystem_root_reference")
            if any(SECRET_SHAPED_VALUE.search(item) for item in args):
                risky_patterns.add("secret_shaped_inline_value")
            if isinstance(env, dict):
                for value in env.values():
                    if not isinstance(value, str):
                        continue
                    if SECRET_SHAPED_VALUE.search(value):
                        risky_patterns.add("secret_shaped_inline_value")
                    elif value and not is_env_reference(value):
                        risky_patterns.add("inline_env_value")
            surfaces.append(
                {
                    "surface": "mcp_server_reference",
                    "path": display_path,
                    "kind": kind,
                    "status": "referenced",
                    "server_name": safe_mcp_server_name(server_name),
                    "transport": transport,
                    **({"command_basename": command} if command else {}),
                    **({"package_manager": package_manager} if package_manager else {}),
                    **({"version_pinned": version_pinned} if version_pinned is not None else {}),
                    **({"remote_host": remote_host} if remote_host else {}),
                    **({"env_vars": env_vars} if env_vars else {}),
                    "filesystem_root": has_filesystem_root,
                    **({"risky_patterns": sorted(risky_patterns)} if risky_patterns else {}),
                }
            )
    return surfaces
