"""Where: src/agent_guard/surface_inventory_mcp_safety.py
What: MCP config sanitizers and deterministic risk metadata helpers.
Why: keep secret-safe MCP analysis reusable without mixing it into collection IO.
"""

from __future__ import annotations

import re
import shlex
from pathlib import Path, PureWindowsPath
from urllib.parse import parse_qsl, urlparse


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
DESCRIPTION_FIELD_NAMES = {"description", "tooldescription", "tool_description"}
INSTRUCTION_LIKE_DESCRIPTION = re.compile(
    r"\bwhen\s+shown\s+to\s+an\s+agent\b.{0,160}"
    r"\b(?:skip|bypass|disable|ignore)\b.{0,80}"
    r"\b(?:approval|permission|policy|guardrail|safety\s+checks?)\b"
    r"|"
    r"\bwhen\s+shown\s+to\s+an\s+agent\b.{0,160}"
    r"\bhide\b.{0,80}\b(?:tool\s+output|output)\b",
    re.IGNORECASE | re.DOTALL,
)


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


def has_instruction_like_description(raw: dict[str, object]) -> bool:
    for key, value in raw.items():
        if normalized_auth_field_name(key) not in DESCRIPTION_FIELD_NAMES:
            continue
        if any(INSTRUCTION_LIKE_DESCRIPTION.search(item) for item in string_values(value)):
            return True
    return False
