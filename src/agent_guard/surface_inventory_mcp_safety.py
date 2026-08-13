"""Where: src/agent_guard/surface_inventory_mcp_safety.py
What: MCP config sanitizers and deterministic risk metadata helpers.
Why: keep secret-safe MCP analysis reusable without mixing it into collection IO.
"""

from __future__ import annotations

import re
import shlex
from pathlib import Path, PureWindowsPath
from urllib.parse import parse_qsl, urlparse


PACKAGE_MANAGER_COMMANDS = {"npx", "npm", "pnpm", "yarn", "bun", "bunx", "uvx", "python", "python3", "node", "deno", "docker"}
WINDOWS_PACKAGE_MANAGER_SUFFIXES = (".cmd", ".exe", ".bat", ".ps1")
DIRECT_PACKAGE_OPERAND_COMMANDS = frozenset({"npx", "uvx"})
PACKAGE_OPERAND_SUBCOMMANDS = {
    "npm": frozenset({"exec", "x"}),
    "pnpm": frozenset({"dlx"}),
    "yarn": frozenset({"dlx"}),
    "bun": frozenset({"x"}),
}
PACKAGE_SELECTOR_OPTIONS = {
    "npx": frozenset({"--package", "-p"}),
    "npm": frozenset({"--package"}),
    "pnpm": frozenset({"--package"}),
    "yarn": frozenset({"--package", "-p"}),
}
UVX_PACKAGE_SELECTOR_OPTIONS = frozenset({"--from", "--with", "-w"})
BUN_GLOBAL_VALUE_OPTIONS = frozenset({"--cwd", "--shell"})
BUNX_BOOLEAN_OPTIONS = frozenset({"--bun"})
PACKAGE_OPERAND_BOOLEAN_OPTIONS = {
    "npx": frozenset({"-q", "-y", "--quiet", "--yes"}),
    "npm": frozenset(
        {
            "--dangerously-allow-all-scripts",
            "--include-workspace-root",
            "--strict-allow-scripts",
            "--workspaces",
            "--parseable",
            "-p",
            "-q",
            "-y",
            "--quiet",
            "--yes",
        }
    ),
    "pnpm": frozenset({"-c", "-s", "--shell-mode", "--silent"}),
    "yarn": frozenset({"-q", "--quiet"}),
    "uvx": frozenset(
        {
            "--offline",
            "-q",
            "-v",
            "--quiet",
            "--verbose",
        }
    ),
}
PACKAGE_OPERAND_VALUE_OPTIONS = {
    "npx": frozenset({"--allow-scripts", "--cache", "--call", "--registry", "--workspace", "-c", "-w"}),
    "npm": frozenset({"--allow-scripts", "--cache", "--call", "--registry", "--workspace", "-c", "-w"}),
    "pnpm": frozenset({"--allow-build", "--reporter"}),
    "yarn": frozenset(),
    "uvx": frozenset(
        {
            "--cache-dir",
            "--directory",
            "--project",
            "--python",
            "-p",
        }
    ),
}
NPM_PACKAGE_NAME = r"(?:@[A-Za-z0-9][A-Za-z0-9._-]*/)?[A-Za-z0-9][A-Za-z0-9._-]*"
SEMVER_NUMERIC_IDENTIFIER = r"(?:0|[1-9]\d*)"
SEMVER_ALPHANUMERIC_IDENTIFIER = r"(?:[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)"
SEMVER_PRERELEASE_IDENTIFIER = rf"(?:{SEMVER_NUMERIC_IDENTIFIER}|{SEMVER_ALPHANUMERIC_IDENTIFIER})"
NPM_FULL_SEMVER = (
    r"v?(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)"
    rf"(?:-{SEMVER_PRERELEASE_IDENTIFIER}(?:\.{SEMVER_PRERELEASE_IDENTIFIER})*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
)
PYTHON_PACKAGE_NAME = r"[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?"
PYTHON_EXTRA_NAME = r"[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?"
PYTHON_EXTRAS = rf"(?:\[{PYTHON_EXTRA_NAME}(?:,{PYTHON_EXTRA_NAME})*\])?"
PYTHON_EXACT_VERSION = (
    r"v?(?:[0-9]+!)?[0-9]+(?:\.[0-9]+)*"
    r"(?:[._-]?(?:alpha|a|beta|b|preview|pre|c|rc)[._-]?[0-9]*)?"
    r"(?:-(?:[0-9]+)|[._-]?(?:post|rev|r)[._-]?[0-9]*)?"
    r"(?:[._-]?dev[._-]?[0-9]*)?"
    r"(?:\+[A-Za-z0-9]+(?:[._-][A-Za-z0-9]+)*)?"
)
NPM_PACKAGE_VERSION_PIN_RE = re.compile(
    rf"{NPM_PACKAGE_NAME}@{NPM_FULL_SEMVER}",
    re.ASCII,
)
NPM_PACKAGE_SHA256_PIN_RE = re.compile(
    rf"{NPM_PACKAGE_NAME}@sha256:[A-Fa-f0-9]{{64}}",
    re.ASCII,
)
PYTHON_PACKAGE_VERSION_PIN_RE = re.compile(
    rf"{PYTHON_PACKAGE_NAME}{PYTHON_EXTRAS}=={PYTHON_EXACT_VERSION}",
    re.ASCII | re.IGNORECASE,
)
UVX_COMMAND_VERSION_PIN_RE = re.compile(
    rf"{PYTHON_PACKAGE_NAME}@{PYTHON_EXACT_VERSION}",
    re.ASCII | re.IGNORECASE,
)
MCP_URL_KEYS = ("url", "uri", "endpoint", "serverUrl", "server_url")
SAFE_MCP_URL_SCHEMES = {"http", "https", "sse"}
MCP_RISKY_PATTERNS = frozenset(
    {
        "broad_authorization_scope",
        "filesystem_root_reference",
        "inline_authorization_value",
        "inline_env_value",
        "instruction_like_description",
        "latest_package",
        "secret_shaped_inline_value",
        "unsafe_url_scheme",
        "unpinned_package",
    }
)
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


def option_value(
    args: list[str],
    index: int,
    options: frozenset[str],
) -> tuple[str | None, int] | None:
    value = args[index]
    for option in options:
        if value == option:
            if index + 1 >= len(args) or args[index + 1].startswith("-"):
                return None, 1
            return args[index + 1], 2
        if value.startswith(f"{option}="):
            inline_value = value[len(option) + 1 :]
            return inline_value or None, 1
        if len(option) == 2 and value.startswith(option) and len(value) > len(option):
            inline_value = value[len(option) :].removeprefix("=")
            return inline_value or None, 1
    return None


def is_boolean_option(value: str, options: frozenset[str]) -> bool:
    if value in options:
        return True
    return any(option.startswith("--") and value.startswith(f"{option}=") for option in options)


def npm_package_operand_args(args: list[str]) -> tuple[list[str], list[str], bool] | None:
    try:
        boundary = args.index("--")
    except ValueError:
        prefix_and_subcommand = args
    else:
        prefix_and_subcommand = args[:boundary]

    selectors: list[str] = []
    index = 0
    while index < len(prefix_and_subcommand):
        value = prefix_and_subcommand[index]
        if value.lower() in PACKAGE_OPERAND_SUBCOMMANDS["npm"]:
            return args[index + 1 :], selectors, True

        selector_option = option_value(
            prefix_and_subcommand,
            index,
            package_selector_options("npm"),
        )
        if selector_option is not None:
            selector, consumed = selector_option
            if selector is None:
                return None
            selectors.append(selector)
            index += consumed
            continue

        value_option = option_value(prefix_and_subcommand, index, PACKAGE_OPERAND_VALUE_OPTIONS["npm"])
        if value_option is not None:
            option_argument, consumed = value_option
            if option_argument is None:
                return None
            index += consumed
            continue

        if is_boolean_option(value, PACKAGE_OPERAND_BOOLEAN_OPTIONS["npm"]):
            index += 1
            continue
        if value.startswith("-"):
            subcommand_index = next(
                (
                    candidate
                    for candidate in range(index + 1, len(prefix_and_subcommand))
                    if prefix_and_subcommand[candidate].lower() in PACKAGE_OPERAND_SUBCOMMANDS["npm"]
                ),
                None,
            )
            if subcommand_index is not None:
                return args[subcommand_index + 1 :], selectors, False
        return None
    return None


def bun_package_operand_args(args: list[str]) -> tuple[list[str], list[str], bool] | None:
    try:
        boundary = args.index("--")
    except ValueError:
        prefix_and_subcommand = args
    else:
        prefix_and_subcommand = args[:boundary]

    subcommands = PACKAGE_OPERAND_SUBCOMMANDS["bun"]
    index = 0
    while index < len(prefix_and_subcommand):
        value = prefix_and_subcommand[index]
        if value.lower() in subcommands:
            return args[index + 1 :], [], True

        value_option = option_value(
            prefix_and_subcommand,
            index,
            BUN_GLOBAL_VALUE_OPTIONS,
        )
        if value_option is not None:
            option_argument, consumed = value_option
            if option_argument is None:
                return None
            index += consumed
            continue
        if value.startswith("-") and any(
            candidate.lower() in subcommands
            for candidate in prefix_and_subcommand[index + 1 :]
        ):
            subcommand_index = next(
                candidate
                for candidate in range(index + 1, len(prefix_and_subcommand))
                if prefix_and_subcommand[candidate].lower() in subcommands
            )
            return args[subcommand_index + 1 :], [], False
        return None
    return None


def subcommand_package_operand_args(
    command: str,
    args: list[str],
) -> tuple[list[str], list[str], bool] | None:
    try:
        boundary = args.index("--")
    except ValueError:
        prefix_and_subcommand = args
    else:
        prefix_and_subcommand = args[:boundary]

    subcommands = PACKAGE_OPERAND_SUBCOMMANDS[command]
    selectors: list[str] = []
    index = 0
    while index < len(prefix_and_subcommand):
        value = prefix_and_subcommand[index]
        if value.lower() in subcommands:
            return args[index + 1 :], selectors, True

        selector_option = option_value(
            prefix_and_subcommand,
            index,
            package_selector_options(command),
        )
        if selector_option is not None:
            selector, consumed = selector_option
            if selector is None:
                return None
            selectors.append(selector)
            index += consumed
            continue

        value_option = option_value(
            prefix_and_subcommand,
            index,
            PACKAGE_OPERAND_VALUE_OPTIONS[command],
        )
        if value_option is not None:
            option_argument, consumed = value_option
            if option_argument is None:
                return None
            index += consumed
            continue
        if is_boolean_option(value, PACKAGE_OPERAND_BOOLEAN_OPTIONS[command]):
            index += 1
            continue
        if value.startswith("-") and any(
            candidate.lower() in subcommands
            for candidate in prefix_and_subcommand[index + 1 :]
        ):
            subcommand_index = next(
                candidate
                for candidate in range(index + 1, len(prefix_and_subcommand))
                if prefix_and_subcommand[candidate].lower() in subcommands
            )
            return args[subcommand_index + 1 :], selectors, False
        return None
    return None


def bunx_package_operands(args: list[str]) -> list[tuple[str, bool]] | None:
    try:
        boundary = args.index("--")
    except ValueError:
        before_boundary = args
        after_boundary: list[str] = []
    else:
        before_boundary = args[:boundary]
        after_boundary = args[boundary + 1 :]

    first_positional: str | None = None
    for value in before_boundary:
        if first_positional is not None:
            break
        if value in BUNX_BOOLEAN_OPTIONS:
            continue
        if value.startswith("-"):
            return None
        if first_positional is None:
            first_positional = value

    if first_positional is not None:
        return [(first_positional, True)]
    if after_boundary:
        if after_boundary[0].startswith("-"):
            return None
        return [(after_boundary[0], True)]
    return []


def normalized_package_manager_command(command: str) -> str:
    normalized_command = command.strip().casefold()
    for suffix in WINDOWS_PACKAGE_MANAGER_SUFFIXES:
        if normalized_command.endswith(suffix):
            normalized_command = normalized_command[: -len(suffix)]
            break
    return normalized_command if normalized_command in PACKAGE_MANAGER_COMMANDS else ""


def package_operand_args(command: str, args: list[str]) -> tuple[list[str], list[str], bool] | None:
    normalized_command = normalized_package_manager_command(command)
    if not normalized_command:
        return None
    if normalized_command == "bunx":
        return args, [], True
    if normalized_command in DIRECT_PACKAGE_OPERAND_COMMANDS:
        return args, [], True
    if normalized_command == "bun":
        return bun_package_operand_args(args)
    if normalized_command == "npm":
        return npm_package_operand_args(args)
    subcommands = PACKAGE_OPERAND_SUBCOMMANDS.get(normalized_command)
    if not subcommands:
        return None
    return subcommand_package_operand_args(normalized_command, args)


def package_selector_options(command: str) -> frozenset[str]:
    if command == "uvx":
        return UVX_PACKAGE_SELECTOR_OPTIONS
    return PACKAGE_SELECTOR_OPTIONS.get(command, frozenset())


def package_operands(
    command: str,
    args: list[str],
    initial_selectors: list[str],
) -> list[tuple[str, bool]] | None:
    if command in {"bun", "bunx"}:
        return bunx_package_operands(args)

    try:
        boundary = args.index("--")
    except ValueError:
        before_boundary = args
        after_boundary: list[str] = []
    else:
        before_boundary = args[:boundary]
        after_boundary = args[boundary + 1 :]

    selectors = list(initial_selectors)
    first_positional: str | None = None
    uvx_from_selected = False
    index = 0
    while index < len(before_boundary):
        if first_positional is not None and command != "npm":
            break
        value = before_boundary[index]
        selector_option = option_value(
            before_boundary,
            index,
            package_selector_options(command),
        )
        if selector_option is not None:
            selector_value, consumed = selector_option
            if selector_value is None:
                return None
            if first_positional is not None and command != "npm":
                return None
            if command == "uvx" and (value == "--from" or value.startswith("--from=")):
                uvx_from_selected = True
            selectors.append(selector_value)
            index += consumed
            continue

        value_option = option_value(
            before_boundary,
            index,
            PACKAGE_OPERAND_VALUE_OPTIONS[command],
        )
        if value_option is not None:
            option_argument, consumed = value_option
            if option_argument is None:
                return None
            if first_positional is not None and command != "npm":
                return None
            index += consumed
            continue

        if is_boolean_option(value, PACKAGE_OPERAND_BOOLEAN_OPTIONS[command]):
            if first_positional is not None and command != "npm":
                return None
            index += 1
            continue
        if value.startswith("-"):
            return None
        if first_positional is None:
            first_positional = value
        index += 1

    if selectors and command == "uvx" and not uvx_from_selected:
        primary_operand = first_positional
        if primary_operand is None and after_boundary:
            primary_operand = after_boundary[0]
        if primary_operand is None or primary_operand.startswith("-"):
            return None
        return [*((selector, False) for selector in selectors), (primary_operand, True)]
    if selectors:
        return [(selector, False) for selector in selectors]
    if first_positional is not None:
        return [(first_positional, True)]
    if after_boundary:
        if after_boundary[0].startswith("-"):
            return None
        return [(after_boundary[0], True)]
    return []


def is_immutable_package_operand(command: str, operand: str, *, primary: bool) -> bool:
    if command == "uvx":
        pattern = UVX_COMMAND_VERSION_PIN_RE if primary else PYTHON_PACKAGE_VERSION_PIN_RE
        return bool(pattern.fullmatch(operand))
    return bool(
        NPM_PACKAGE_SHA256_PIN_RE.fullmatch(operand)
        or NPM_PACKAGE_VERSION_PIN_RE.fullmatch(operand)
    )


def infer_version_pin(command: str, args: list[str]) -> bool | None:
    normalized_command = normalized_package_manager_command(command)
    if not normalized_command:
        return None
    package_execution = package_operand_args(normalized_command, args)
    if package_execution is None:
        return None
    operand_args, initial_selectors, valid = package_execution
    if not valid:
        return False
    operands = package_operands(normalized_command, operand_args, initial_selectors)
    if not operands:
        return False
    return all(
        is_immutable_package_operand(normalized_command, operand, primary=primary)
        for operand, primary in operands
    )


def normalized_auth_field_name(name: object) -> str:
    return re.sub(r"[^a-z0-9]+", "_", str(name).strip().lower()).strip("_")


def is_authorization_field_name(name: object) -> bool:
    normalized = normalized_auth_field_name(name)
    if normalized in AUTH_FIELD_NAMES:
        return True
    compact = normalized.replace("_", "")
    return compact.endswith(("token", "secret"))


def has_instruction_like_description(raw: dict[str, object]) -> bool:
    for key, value in raw.items():
        if normalized_auth_field_name(key) not in DESCRIPTION_FIELD_NAMES:
            continue
        if any(INSTRUCTION_LIKE_DESCRIPTION.search(item) for item in string_values(value)):
            return True
    return False
