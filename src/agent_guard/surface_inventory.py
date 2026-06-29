"""Where: src/agent_guard/surface_inventory.py
What: repo-local agent surface inventory without raw instruction or command text.
Why: maintainers need to know which agent-facing surfaces exist before review.
"""

from __future__ import annotations

import json
import re
import shlex
import tomllib
from pathlib import Path, PureWindowsPath
from typing import Literal
from urllib.parse import parse_qsl, urlparse

import yaml

from .context_guard import collect_context_inventory
from .workflow_guard import collect_run_lines


AGENT_SURFACE_SCHEMA_VERSION_V1 = "agent-guard.agent_surface_inventory.v1"
AGENT_SURFACE_SCHEMA_VERSION_V2 = "agent-guard.agent_surface_inventory.v2"
AGENT_SURFACE_SCHEMA_VERSION = AGENT_SURFACE_SCHEMA_VERSION_V1
WORKFLOW_GLOBS = ("*.yml", "*.yaml")
DOC_GLOBS = ("README.md", "docs/*.md")
AGENT_SKILL_DIRS = (
    (".github/skills", "github_copilot_skill"),
    (".agents/skills", "github_copilot_skill"),
    (".claude/skills", "claude_skill"),
    (".codex/skills", "codex_skill"),
    (".cursor/skills", "cursor_skill"),
    (".gemini/skills", "gemini_skill"),
)
AGENT_PROFILE_DIRS = (
    (".github/agents", "github_copilot_agent"),
    (".claude/agents", "claude_agent"),
    (".codex/agents", "codex_agent"),
    (".cursor/agents", "cursor_agent"),
)
AGENT_COMMAND_DIRS = (
    (".claude/commands", "claude_command"),
    (".cursor/commands", "cursor_command"),
    (".gemini/commands", "gemini_command"),
)
AGENT_HOOK_FILES = (
    (".github/hooks/*.json", "github_hook_config"),
    (".cursor/hooks.json", "cursor_hook_config"),
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
PACKAGE_MANAGER_COMMANDS = {"npx", "npm", "pnpm", "yarn", "bun", "uvx", "python", "python3", "node", "deno", "docker"}
MCP_URL_KEYS = ("url", "uri", "endpoint", "serverUrl", "server_url")
SAFE_MCP_URL_SCHEMES = {"http", "https", "sse"}
AUTH_FIELD_NAMES = {
    "api_key",
    "apikey",
    "access_token",
    "accesstoken",
    "authorization",
    "authorization_header",
    "authorizationheader",
    "auth_token",
    "authtoken",
    "bearer_token",
    "bearertoken",
    "client_secret",
    "clientsecret",
    "oauth_token",
    "oauthtoken",
    "password",
    "refresh_token",
    "refreshtoken",
    "secret",
    "token",
}
AUTH_OPTION_RE = re.compile(
    r"^--?(?:access-token|api-key|apikey|auth-token|authorization|bearer-token|client-secret|oauth-token|password|refresh-token|secret|token)(?:=|$)",
    re.IGNORECASE,
)
SCOPE_FIELD_NAMES = {
    "authscope",
    "authscopes",
    "authorizationscope",
    "authorizationscopes",
    "oauthscope",
    "oauthscopes",
    "scope",
    "scopes",
}
BROAD_AUTHORIZATION_SCOPE_VALUES = {
    "*",
    "admin",
    "all",
    "full",
    "full-access",
    "full_access",
    "read-write",
    "read_write",
    "repo",
    "write",
}
SECRET_SHAPED_VALUE = re.compile(
    r"(?:github_pat_[A-Za-z0-9_]{20,}|gh[pousr]_[A-Za-z0-9_]{20,}|sk-[A-Za-z0-9_-]{16,}|AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16})"
)
MAX_SURFACE_TREE_FILES = 1000
SurfaceVersion = Literal["v1", "v2"]


def rel_path(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.name


def policy_kind(path: str) -> str:
    name = Path(path).name
    if name == "context-policy.yaml":
        return "context_policy"
    if name == "path-policy.yaml":
        return "path_policy"
    if name == "content-policy.yaml":
        return "content_policy"
    if name == "workflow-policy.yaml":
        return "workflow_policy"
    if "digest" in name:
        return "digest_policy"
    return "agent_guard_policy"


def parse_agent_guard_command(command: str) -> dict[str, object] | None:
    match = re.search(
        r"(?:^|\s)(?:python(?:3(?:\.\d+)?)?\s+-m\s+agent_guard\.cli|agent-guard)\s+([a-z][a-z-]*)(?:\s+([a-z][a-z-]*))?",
        command,
    )
    if not match:
        return None
    return {
        "scanner": match.group(1),
        "command": match.group(2) or "",
    }


def normalize_surface_version(version: str) -> SurfaceVersion:
    if version in {"v1", AGENT_SURFACE_SCHEMA_VERSION_V1}:
        return "v1"
    if version in {"v2", AGENT_SURFACE_SCHEMA_VERSION_V2}:
        return "v2"
    raise ValueError("surface inventory schema version must be v1 or v2")


def schema_for_surface_version(version: SurfaceVersion) -> str:
    return AGENT_SURFACE_SCHEMA_VERSION_V1 if version == "v1" else AGENT_SURFACE_SCHEMA_VERSION_V2


def safe_metadata_path(raw_path: str) -> str:
    text = str(raw_path).strip().strip("'\"")
    if not text:
        return ""
    windows_path = PureWindowsPath(text)
    if windows_path.is_absolute() or windows_path.drive or text.startswith("\\\\"):
        return windows_path.name or "<external-path>"
    path = Path(text)
    if path.is_absolute() or ".." in path.parts:
        return path.name or "<external-path>"
    return path.as_posix()


def command_basename(command: object) -> str:
    if not isinstance(command, str):
        return ""
    raw_text = command.strip()
    try:
        parts = shlex.split(raw_text, posix=True)
    except ValueError:
        parts = raw_text.split()
    text = (parts[0] if parts else raw_text).strip().strip("'\"")
    if not text:
        return ""
    windows_path = PureWindowsPath(text)
    if windows_path.drive or "\\" in text:
        return windows_path.name
    return Path(text).name


def unsafe_mcp_public_token(text: str) -> bool:
    if any(ord(char) < 32 or ord(char) == 127 for char in text):
        return True
    if SECRET_SHAPED_VALUE.search(text):
        return True
    if "/" in text or "\\" in text:
        return True
    if PureWindowsPath(text).drive or text.startswith("\\\\"):
        return True
    if Path(text).is_absolute() or ".." in Path(text).parts:
        return True
    return len(text) > 80


def safe_mcp_public_token(raw_name: object, *, empty: str, redacted: str) -> str:
    text = str(raw_name).strip()
    if not text:
        return empty
    if unsafe_mcp_public_token(text):
        return redacted
    return text


def safe_mcp_server_name(raw_name: object) -> str:
    return safe_mcp_public_token(raw_name, empty="<unnamed-server>", redacted="<redacted-server>")


def safe_mcp_command_basename(raw_name: object) -> str:
    return safe_mcp_public_token(raw_name, empty="", redacted="<redacted-command>")


def safe_mcp_env_var_name(raw_name: object) -> str:
    token = safe_mcp_public_token(raw_name, empty="", redacted="<redacted-env>")
    if not token or token == "<redacted-env>":
        return token
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,79}", token):
        return token
    return "<redacted-env>"


def safe_mcp_remote_host(raw_name: object) -> str:
    return safe_mcp_public_token(raw_name, empty="", redacted="<redacted-host>")


def count_tree_files(base: Path, *, cap: int = MAX_SURFACE_TREE_FILES) -> tuple[int, bool]:
    if base.is_file():
        return 1, False
    count = 0
    for item in base.rglob("*"):
        if not item.is_file():
            continue
        count += 1
        if count >= cap:
            return count, True
    return count, False


def collect_directory_surfaces(
    root: Path,
    entries: tuple[tuple[str, str], ...],
    *,
    surface: str,
) -> list[dict[str, object]]:
    surfaces: list[dict[str, object]] = []
    for rel_base, kind in entries:
        base = root / rel_base
        if not base.is_dir():
            continue
        children = sorted(item for item in base.iterdir() if item.is_dir() or item.is_file())
        if not children:
            file_count, truncated = count_tree_files(base)
            surfaces.append(
                {
                    "surface": surface,
                    "path": rel_path(base, root),
                    "kind": kind,
                    "status": "present",
                    "file_count": file_count,
                    **({"truncated": True} if truncated else {}),
                }
            )
            continue
        for child in children:
            file_count, truncated = count_tree_files(child)
            surfaces.append(
                {
                    "surface": surface,
                    "path": rel_path(child, root),
                    "kind": kind,
                    "status": "present",
                    "file_count": file_count,
                    **({"truncated": True} if truncated else {}),
                }
            )
    return surfaces


def collect_hook_surfaces(root: Path) -> list[dict[str, object]]:
    surfaces: list[dict[str, object]] = []
    for pattern, kind in AGENT_HOOK_FILES:
        for path in sorted(root.glob(pattern)):
            if not path.is_file():
                continue
            surfaces.append(
                {
                    "surface": "agent_hook_config",
                    "path": rel_path(path, root),
                    "kind": kind,
                    "status": "present",
                    "size_bytes": path.stat().st_size,
                }
            )
    return surfaces


def load_structured_config(path: Path) -> object:
    if path.suffix == ".toml":
        with path.open("rb") as handle:
            return tomllib.load(handle)
    return json.loads(path.read_text(encoding="utf-8"))


def iter_mcp_config_files(root: Path) -> list[tuple[Path, str]]:
    files: list[tuple[Path, str]] = []
    for pattern, kind in MCP_CONFIG_FILES:
        for path in sorted(root.glob(pattern)):
            if path.is_file():
                files.append((path, kind))
    return files


def string_values(value: object) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        values: list[str] = []
        for child in value.values():
            values.extend(string_values(child))
        return values
    if isinstance(value, list):
        values = []
        for child in value:
            values.extend(string_values(child))
        return values
    return []


def string_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str)]


def command_inline_args(command: object) -> list[str]:
    if not isinstance(command, str):
        return []
    try:
        parts = shlex.split(command, posix=True)
    except ValueError:
        parts = command.split()
    return [item for item in parts[1:] if isinstance(item, str)]


def is_env_reference(value: str) -> bool:
    text = value.strip()
    return bool(re.fullmatch(r"\$\{?[A-Za-z_][A-Za-z0-9_]*\}?", text))


def contains_env_reference(value: str) -> bool:
    return bool(re.search(r"\$\{?[A-Za-z_][A-Za-z0-9_]*\}?", value.strip()))


def is_inline_auth_literal(value: str) -> bool:
    text = value.strip()
    return bool(text) and not is_env_reference(text) and not contains_env_reference(text)


def contains_filesystem_root(value: str) -> bool:
    text = value.strip().strip("'\"")
    if not text:
        return False
    if text in {"/", ".", "${workspaceFolder}", "${workspaceRoot}"}:
        return True
    if text.startswith(("~/", "$HOME/", "${HOME}/", "${workspaceFolder}/", "${workspaceRoot}/")):
        return True
    if PureWindowsPath(text).drive or text.startswith("\\\\"):
        return True
    return Path(text).is_absolute()


def has_unsafe_mcp_url_scheme(raw: dict[str, object]) -> bool:
    for key in MCP_URL_KEYS:
        value = raw.get(key)
        if not isinstance(value, str):
            continue
        parsed = urlparse(value.strip())
        if parsed.scheme and parsed.scheme.lower() not in SAFE_MCP_URL_SCHEMES:
            return True
    return False


def extract_remote_host(raw: dict[str, object]) -> str:
    for key in MCP_URL_KEYS:
        value = raw.get(key)
        if not isinstance(value, str):
            continue
        parsed = urlparse(value)
        if parsed.scheme in {"http", "https", "sse"} and parsed.hostname:
            return parsed.hostname
    return ""


def infer_transport(raw: dict[str, object], remote_host: str, command: str) -> str:
    raw_transport = raw.get("transport") or raw.get("type")
    if isinstance(raw_transport, str):
        text = raw_transport.lower()
        if text in {"stdio", "http", "sse", "streamable-http"}:
            return text
    if remote_host:
        return "http"
    if command:
        return "stdio"
    return "unknown"


def infer_version_pin(command: str, args: list[str]) -> bool | None:
    if not command and not args:
        return None
    joined = " ".join(args)
    if "@latest" in joined:
        return False
    if re.search(r"(?:^|\s)[^\s@]+@v?\d+(?:[.\-][A-Za-z0-9]+)*", joined):
        return True
    if re.search(r"(?:^|\s)[^\s=<>!~]+==[A-Za-z0-9_.+-]+", joined):
        return True
    if re.search(r"(?:@sha256:|sha256:)[A-Fa-f0-9]{16,}", joined):
        return True
    return False if command in PACKAGE_MANAGER_COMMANDS else None


def normalized_auth_field_name(name: object) -> str:
    return re.sub(r"[^a-z0-9]+", "_", str(name).strip().lower()).strip("_")


def is_authorization_field_name(name: object) -> bool:
    normalized = normalized_auth_field_name(name)
    if normalized in AUTH_FIELD_NAMES:
        return True
    return normalized.endswith(("_token", "_secret"))


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


def collect_mcp_config_surfaces(root: Path) -> list[dict[str, object]]:
    surfaces: list[dict[str, object]] = []
    for path, kind in iter_mcp_config_files(root):
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
            package_manager = command if command in PACKAGE_MANAGER_COMMANDS else ""
            all_strings = string_values(raw_server)
            metadata_strings = [*all_strings, *args]
            risky_patterns: set[str] = set()
            if any("@latest" in item for item in args):
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


def parse_output_artifact(command: str) -> str:
    match = re.search(r"(?:^|\s)--output(?:=|\s+)([^\s]+)", command)
    if not match:
        return ""
    return safe_metadata_path(match.group(1))


def iter_workflow_files(root: Path) -> list[Path]:
    workflow_dir = root / ".github" / "workflows"
    if not workflow_dir.is_dir():
        return []
    files: list[Path] = []
    for pattern in WORKFLOW_GLOBS:
        files.extend(workflow_dir.glob(pattern))
    return sorted(path for path in files if path.is_file())


def collect_workflow_artifact_surfaces(workflow: dict[str, object], *, workflow_path: str) -> list[dict[str, object]]:
    raw_jobs = workflow.get("jobs", {})
    if not isinstance(raw_jobs, dict):
        return []
    surfaces: list[dict[str, object]] = []
    for raw_job_id, raw_job in raw_jobs.items():
        if not isinstance(raw_job, dict):
            continue
        raw_steps = raw_job.get("steps", [])
        if not isinstance(raw_steps, list):
            continue
        for step_index, raw_step in enumerate(raw_steps, start=1):
            if not isinstance(raw_step, dict):
                continue
            uses = str(raw_step.get("uses", ""))
            with_cfg = raw_step.get("with", {})
            if "upload-artifact" in uses and isinstance(with_cfg, dict):
                artifact_path = safe_metadata_path(str(with_cfg.get("path", "")))
                if artifact_path:
                    surfaces.append(
                        {
                            "surface": "evidence_artifact_reference",
                            "path": workflow_path,
                            "kind": "github_artifact",
                            "status": "referenced",
                            "job_id": str(raw_job_id),
                            "step_index": step_index,
                            "artifact_path": artifact_path,
                        }
                    )
    return surfaces


def collect_workflow_surfaces(root: Path, *, include_artifacts: bool = False) -> list[dict[str, object]]:
    surfaces: list[dict[str, object]] = []
    for workflow_file in iter_workflow_files(root):
        workflow_path = rel_path(workflow_file, root)
        try:
            loaded = yaml.safe_load(workflow_file.read_text(encoding="utf-8")) or {}
        except Exception:
            surfaces.append(
                {
                    "surface": "workflow_file",
                    "path": workflow_path,
                    "kind": "github_actions",
                    "status": "parse_error",
                }
            )
            continue
        if not isinstance(loaded, dict):
            surfaces.append(
                {
                    "surface": "workflow_file",
                    "path": workflow_path,
                    "kind": "github_actions",
                    "status": "not_object",
                }
            )
            continue
        surfaces.append(
            {
                "surface": "workflow_file",
                "path": workflow_path,
                "kind": "github_actions",
                "status": "scanned",
            }
        )
        for line in collect_run_lines(loaded, workflow_path=workflow_path):
            command = parse_agent_guard_command(line.command)
            if command is None:
                continue
            surfaces.append(
                {
                    "surface": "workflow_reference",
                    "path": workflow_path,
                    "kind": "agent_guard_command",
                    "status": "referenced",
                    "job_id": line.job_id,
                    "step_index": line.step_index,
                    "command": command,
                }
            )
            if include_artifacts:
                artifact_path = parse_output_artifact(line.command)
                if artifact_path:
                    surfaces.append(
                        {
                            "surface": "evidence_artifact_reference",
                            "path": workflow_path,
                            "kind": "agent_guard_output",
                            "status": "referenced",
                            "job_id": line.job_id,
                            "step_index": line.step_index,
                            "artifact_path": artifact_path,
                            "command": command,
                        }
                    )
        if include_artifacts:
            surfaces.extend(collect_workflow_artifact_surfaces(loaded, workflow_path=workflow_path))
    return surfaces


def collect_documented_guard_surfaces(root: Path) -> list[dict[str, object]]:
    surfaces: list[dict[str, object]] = []
    doc_files: list[Path] = []
    for pattern in DOC_GLOBS:
        doc_files.extend(root.glob(pattern))
    for doc_file in sorted(path for path in doc_files if path.is_file()):
        doc_path = rel_path(doc_file, root)
        try:
            lines = doc_file.read_text(encoding="utf-8").splitlines()
        except Exception:
            continue
        for lineno, line in enumerate(lines, start=1):
            command = parse_agent_guard_command(line)
            if command is None:
                continue
            surfaces.append(
                {
                    "surface": "documented_guard_command",
                    "path": doc_path,
                    "kind": "documentation_recipe",
                    "status": "documented",
                    "line": lineno,
                    "command": command,
                }
            )
    return surfaces


def collect_committed_evidence_surfaces(root: Path) -> list[dict[str, object]]:
    surfaces: list[dict[str, object]] = []
    for base in (root / ".agent-guard" / "evidence", root / "docs" / "evidence-samples"):
        if not base.is_dir():
            continue
        for path in sorted(base.glob("*")):
            if not path.is_file():
                continue
            surfaces.append(
                {
                    "surface": "evidence_artifact",
                    "path": rel_path(path, root),
                    "kind": "committed_evidence_sample" if "docs" in path.parts else "repo_evidence_file",
                    "status": "present",
                    "size_bytes": path.stat().st_size,
                }
            )
    return surfaces


def collect_policy_surfaces(root: Path) -> list[dict[str, object]]:
    policy_dir = root / ".agent-guard"
    if not policy_dir.is_dir():
        return []
    surfaces: list[dict[str, object]] = []
    for path in sorted(policy_dir.glob("*.yaml")):
        if not path.is_file():
            continue
        display = rel_path(path, root)
        surfaces.append(
            {
                "surface": "policy_file",
                "path": display,
                "kind": policy_kind(display),
                "status": "present",
                "size_bytes": path.stat().st_size,
            }
        )
    return surfaces


def summarize_surfaces(surfaces: list[dict[str, object]]) -> dict[str, object]:
    by_surface: dict[str, int] = {}
    for item in surfaces:
        surface = str(item.get("surface", "unknown"))
        by_surface[surface] = by_surface.get(surface, 0) + 1
    return {
        "surface_count": len(surfaces),
        "by_surface": dict(sorted(by_surface.items())),
    }


def collect_agent_surface_inventory(
    *,
    root: Path,
    context_policy: dict[str, object],
    schema_version: str = "v1",
) -> dict[str, object]:
    root = root.resolve()
    version = normalize_surface_version(schema_version)
    context_inventory = collect_context_inventory(root=root, policy=context_policy)
    surfaces: list[dict[str, object]] = []
    for item in context_inventory.context_files:
        surfaces.append(
            {
                "surface": "agent_context",
                "path": item.path,
                "kind": item.kind,
                "status": item.read_status,
                "size_bytes": item.size_bytes,
                **({"line_count": item.line_count} if item.line_count is not None else {}),
            }
        )
    surfaces.extend(collect_policy_surfaces(root))
    surfaces.extend(collect_workflow_surfaces(root, include_artifacts=version == "v2"))
    if version == "v2":
        surfaces.extend(collect_documented_guard_surfaces(root))
        surfaces.extend(collect_committed_evidence_surfaces(root))
        surfaces.extend(collect_directory_surfaces(root, AGENT_SKILL_DIRS, surface="agent_skill"))
        surfaces.extend(collect_directory_surfaces(root, AGENT_PROFILE_DIRS, surface="agent_profile"))
        surfaces.extend(collect_directory_surfaces(root, AGENT_COMMAND_DIRS, surface="agent_command"))
        surfaces.extend(collect_hook_surfaces(root))
        surfaces.extend(collect_mcp_config_surfaces(root))
    surfaces = sorted(surfaces, key=lambda item: (str(item.get("path", "")), str(item.get("surface", ""))))
    return {
        "schema_version": schema_for_surface_version(version),
        "summary": summarize_surfaces(surfaces),
        "surfaces": surfaces,
    }


def public_safe_surface_text(payload: dict[str, object]) -> str:
    """Return serialized inventory text for tests and downstream safety checks."""

    import json

    return json.dumps(payload, ensure_ascii=False, sort_keys=True)
