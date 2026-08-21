"""Where: src/agent_guard/surface_inventory_mcp.py
What: static MCP config surface inventory.
Why: expose sanitized MCP config metadata without raw commands, URLs, or secret values.
"""

from __future__ import annotations

import fnmatch
import json
import os
import re
import stat
import tomllib
from collections.abc import Sequence
from pathlib import Path
from urllib.parse import parse_qsl, urlparse

from .bounded_repo_reader import (
    BoundedRepoContainmentError,
    BoundedRepoFile,
    BoundedRepoFileNotFoundError,
    BoundedRepoLimitError,
    BoundedRepoReadError,
    DistinctInputBudget,
    read_repo_bound_bytes,
)
from .bounded_scan import MAX_ISOLATED_MESSAGE_BYTES
from .bounded_yaml import BoundedYamlLimitError, _validate_object_graph
from .surface_inventory_core import has_glob_magic, is_in_opaque_directory, rel_path
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

ERROR_MCP_CONFIG_NOT_FOUND = "MCP configuration file not found"
ERROR_MCP_CONFIG_INVALID = "MCP configuration is not parseable"
ERROR_MCP_CONFIG_TARGET = "MCP configuration must stay under repo root"
ERROR_MCP_CONFIG_LIMIT = "MCP configuration exceeds configured limits"
# Match API/content scanner selection and per-file ceilings.
MAX_MCP_CONFIG_FILES = 10_000
MAX_MCP_CONFIG_FILE_BYTES = 1_048_576
# Match the workflow scanner's aggregate distinct-input ceiling.
MAX_MCP_DISTINCT_INPUT_BYTES = 16 * 1024 * 1024
# Reuse the established API/content 10,000-item result/selection ceiling.
MAX_MCP_SERVERS = 10_000
# Reserve half the isolated transport cap for container/serialization overhead.
MAX_MCP_AGGREGATE_RESULT_BYTES = MAX_ISOLATED_MESSAGE_BYTES // 2


def _read_structured_config(
    path: Path,
    root: Path,
    *,
    max_bytes: int,
) -> BoundedRepoFile:
    try:
        return read_repo_bound_bytes(path, root, max_bytes=max_bytes)
    except BoundedRepoFileNotFoundError:
        raise FileNotFoundError(ERROR_MCP_CONFIG_NOT_FOUND) from None
    except BoundedRepoLimitError:
        raise ValueError(ERROR_MCP_CONFIG_LIMIT) from None
    except BoundedRepoContainmentError:
        raise ValueError(ERROR_MCP_CONFIG_TARGET) from None
    except BoundedRepoReadError:
        raise ValueError(ERROR_MCP_CONFIG_INVALID) from None


def _parse_structured_config(path: Path, data: bytes) -> object:
    try:
        text = data.decode("utf-8")
        loaded = tomllib.loads(text) if path.suffix == ".toml" else json.loads(text)
        _validate_object_graph(loaded)
    except BoundedYamlLimitError:
        raise ValueError(ERROR_MCP_CONFIG_LIMIT) from None
    except (MemoryError, OverflowError, RecursionError):
        raise ValueError(ERROR_MCP_CONFIG_LIMIT) from None
    except (UnicodeDecodeError, ValueError):
        raise ValueError(ERROR_MCP_CONFIG_INVALID) from None
    return loaded


def load_structured_config(path: Path, *, root: Path | None = None) -> object:
    allowed_root = path.parent if root is None else root
    opened = _read_structured_config(
        path,
        allowed_root,
        max_bytes=MAX_MCP_CONFIG_FILE_BYTES,
    )
    return _parse_structured_config(path, opened.data)


def _resolved_repo_relative(path: Path, root: Path) -> Path:
    try:
        return path.resolve(strict=True).relative_to(root)
    except ValueError:
        raise ValueError(ERROR_MCP_CONFIG_TARGET) from None
    except (OSError, RuntimeError):
        raise ValueError(ERROR_MCP_CONFIG_INVALID) from None


def _append_mcp_config_candidate(
    files: list[tuple[Path, str]],
    seen: set[Path],
    *,
    path: Path,
    kind: str,
    root: Path,
    opaque_directories: Sequence[str],
    existing_count: int = 0,
    discovered: bool = False,
) -> None:
    try:
        path.relative_to(root)
    except ValueError:
        raise ValueError(ERROR_MCP_CONFIG_TARGET) from None
    if is_in_opaque_directory(
        path,
        root=root,
        opaque_directories=opaque_directories,
    ):
        return
    try:
        path_stat = path.stat()
    except FileNotFoundError:
        if discovered:
            raise ValueError(ERROR_MCP_CONFIG_INVALID) from None
        return
    except OSError:
        raise ValueError(ERROR_MCP_CONFIG_INVALID) from None
    if not stat.S_ISREG(path_stat.st_mode):
        if discovered:
            raise ValueError(ERROR_MCP_CONFIG_INVALID) from None
        return
    try:
        resolved_relative = _resolved_repo_relative(path, root)
    except ValueError as exc:
        if str(exc) == ERROR_MCP_CONFIG_TARGET:
            # Preserve surface-inventory compatibility: a stable external
            # symlink is absent from the repository inventory. The bounded
            # descriptor read still fails closed if a selected path later moves.
            return
        raise
    resolved_path = root / resolved_relative
    if resolved_path in seen:
        return
    if existing_count + len(files) >= MAX_MCP_CONFIG_FILES:
        raise ValueError(ERROR_MCP_CONFIG_LIMIT)
    seen.add(resolved_path)
    files.append((path, kind))


def _mcp_filename_matches(name: str, pattern: str) -> bool:
    if os.name == "nt":
        return fnmatch.fnmatchcase(name.casefold(), pattern.casefold())
    return fnmatch.fnmatchcase(name, pattern)


def iter_mcp_config_files(
    root: Path,
    *,
    opaque_directories: Sequence[str] = (),
) -> list[tuple[Path, str]]:
    try:
        root = root.resolve(strict=True)
    except (OSError, RuntimeError):
        raise ValueError(ERROR_MCP_CONFIG_TARGET) from None
    files: list[tuple[Path, str]] = []
    seen: set[Path] = set()
    wildcard_entries = 0
    for pattern, kind in MCP_CONFIG_FILES:
        pattern_path = Path(pattern)
        parent_parts = pattern_path.parts[:-1]
        filename_pattern = pattern_path.parts[-1]
        if any(has_glob_magic(part) for part in parent_parts):
            raise ValueError(ERROR_MCP_CONFIG_LIMIT)
        parent = root.joinpath(*parent_parts) if parent_parts else root
        if is_in_opaque_directory(
            parent,
            root=root,
            opaque_directories=opaque_directories,
        ):
            continue
        if has_glob_magic(filename_pattern):
            if not parent.exists():
                continue
            try:
                _resolved_repo_relative(parent, root)
            except ValueError as exc:
                if str(exc) == ERROR_MCP_CONFIG_TARGET:
                    continue
                raise
            pattern_files: list[tuple[Path, str]] = []
            try:
                with os.scandir(parent) as entries:
                    for entry in entries:
                        if wildcard_entries >= MAX_MCP_CONFIG_FILES:
                            raise ValueError(ERROR_MCP_CONFIG_LIMIT)
                        wildcard_entries += 1
                        if not _mcp_filename_matches(entry.name, filename_pattern):
                            continue
                        try:
                            if not entry.is_file(follow_symlinks=True):
                                continue
                        except OSError:
                            raise ValueError(ERROR_MCP_CONFIG_INVALID) from None
                        candidate = parent / entry.name
                        _append_mcp_config_candidate(
                            pattern_files,
                            seen,
                            path=candidate,
                            kind=kind,
                            root=root,
                            opaque_directories=opaque_directories,
                            existing_count=len(files),
                            discovered=True,
                        )
            except ValueError:
                raise
            except OSError:
                raise ValueError(ERROR_MCP_CONFIG_INVALID) from None
            files.extend(sorted(pattern_files, key=lambda item: item[0]))
            continue
        _append_mcp_config_candidate(
            files,
            seen,
            path=parent / filename_pattern,
            kind=kind,
            root=root,
            opaque_directories=opaque_directories,
        )
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
        try:
            parsed = urlparse(value.strip())
            query_items = parse_qsl(parsed.query, keep_blank_values=False)
        except ValueError:
            raise ValueError(ERROR_MCP_CONFIG_INVALID) from None
        for query_key, query_value in query_items:
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


def _canonical_json_size(value: object) -> int:
    return len(
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8", errors="surrogatepass")
    )


class _McpSurfaceResultBudget:
    def __init__(self) -> None:
        self.used = _canonical_json_size([])
        self.count = 0
        if self.used > MAX_MCP_AGGREGATE_RESULT_BYTES:
            raise ValueError(ERROR_MCP_CONFIG_LIMIT)

    def add(self, item: dict[str, object]) -> None:
        amount = _canonical_json_size(item) + (1 if self.count else 0)
        if amount > MAX_MCP_AGGREGATE_RESULT_BYTES - self.used:
            raise ValueError(ERROR_MCP_CONFIG_LIMIT)
        self.used += amount
        self.count += 1


def collect_mcp_config_surfaces(
    root: Path,
    *,
    opaque_directories: Sequence[str] = (),
    _input_budget: DistinctInputBudget | None = None,
) -> list[dict[str, object]]:
    try:
        root = root.resolve(strict=True)
    except (OSError, RuntimeError):
        raise ValueError(ERROR_MCP_CONFIG_TARGET) from None
    surfaces: list[dict[str, object]] = []
    result_budget = _McpSurfaceResultBudget()
    input_budget = _input_budget or DistinctInputBudget(
        max_bytes=MAX_MCP_DISTINCT_INPUT_BYTES
    )
    server_count = 0
    config_files = iter_mcp_config_files(
        root,
        opaque_directories=opaque_directories,
    )
    if len(config_files) > MAX_MCP_CONFIG_FILES:
        raise ValueError(ERROR_MCP_CONFIG_LIMIT)
    for path, kind in config_files:
        display_path = rel_path(path, root)
        try:
            opened = _read_structured_config(
                path,
                root,
                max_bytes=MAX_MCP_CONFIG_FILE_BYTES,
            )
        except FileNotFoundError:
            raise ValueError(ERROR_MCP_CONFIG_INVALID) from None
        try:
            input_budget.charge(opened)
        except BoundedRepoLimitError:
            raise ValueError(ERROR_MCP_CONFIG_LIMIT) from None
        except BoundedRepoReadError:
            raise ValueError(ERROR_MCP_CONFIG_INVALID) from None
        display_path = opened.relative_path
        try:
            loaded = _parse_structured_config(path, opened.data)
        except ValueError as exc:
            if str(exc) != ERROR_MCP_CONFIG_INVALID:
                raise
            config_surface = {
                "surface": "mcp_config",
                "path": display_path,
                "kind": kind,
                "status": "parse_error",
            }
            result_budget.add(config_surface)
            surfaces.append(config_surface)
            continue
        config_surface = {
            "surface": "mcp_config",
            "path": display_path,
            "kind": kind,
            "status": "present",
            "size_bytes": len(opened.data),
        }
        result_budget.add(config_surface)
        surfaces.append(config_surface)
        server_map = mcp_server_maps(loaded)
        if len(server_map) > MAX_MCP_SERVERS - server_count:
            raise ValueError(ERROR_MCP_CONFIG_LIMIT)
        try:
            server_items = sorted(server_map.items())
        except (MemoryError, OverflowError, RecursionError):
            raise ValueError(ERROR_MCP_CONFIG_LIMIT) from None
        for server_name, raw_server in server_items:
            server_count += 1
            if server_count > MAX_MCP_SERVERS:
                raise ValueError(ERROR_MCP_CONFIG_LIMIT)
            if not isinstance(raw_server, dict):
                continue
            try:
                command = safe_mcp_command_basename(command_basename(raw_server.get("command")))
                args = command_inline_args(raw_server.get("command")) + string_list(raw_server.get("args"))
                env = raw_server.get("env")
                env_vars = (
                    sorted({name for name in (safe_mcp_env_var_name(key) for key in env.keys()) if name})
                    if isinstance(env, dict)
                    else []
                )
                try:
                    remote_host = safe_mcp_remote_host(extract_remote_host(raw_server))
                    unsafe_url_scheme = has_unsafe_mcp_url_scheme(raw_server)
                    inline_authorization_url = contains_inline_authorization_url_value(
                        raw_server
                    )
                except ValueError:
                    raise ValueError(ERROR_MCP_CONFIG_INVALID) from None
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
                if unsafe_url_scheme:
                    risky_patterns.add("unsafe_url_scheme")
                if (
                    contains_inline_authorization_arg(args)
                    or inline_authorization_url
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
            except (MemoryError, OverflowError, RecursionError):
                raise ValueError(ERROR_MCP_CONFIG_LIMIT) from None
            server_surface = {
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
            result_budget.add(server_surface)
            surfaces.append(server_surface)
    return surfaces
