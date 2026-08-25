"""Where: src/agent_guard/workflow_guard.py
What: static workflow drift guard for repository safety gates.
Why: ensure CI keeps running declared guard commands and required policy files.
"""

from __future__ import annotations

import argparse
import io
import os
import re
import stat
from collections import deque
from dataclasses import dataclass, field
from functools import cache
from pathlib import Path, PureWindowsPath
from typing import Any, Iterator, NoReturn

import yaml

from .bounded_repo_reader import (
    BoundedRepoLimitError,
    BoundedRepoReadError,
    DistinctInputBudget,
)


WORKFLOW_POLICY_SCHEMA_VERSION = "agent-guard.workflow_policy.v1"
HEREDOC_DELIMITER_RE = re.compile(r"[-A-Za-z0-9_]+")
DOCUMENTATION_COMMANDS = {"echo", "printf"}
HELP_OPTIONS = {"--help", "-h"}
ERROR_WORKFLOW_SCAN_TARGET = "workflow scan target must stay under repo root"
ERROR_WORKFLOW_CONFIGURATION_LIMIT = "workflow configuration exceeds safety limits"
ERROR_WORKFLOW_SHELL_SYNTAX = "workflow shell syntax is unsupported or ambiguous"
ERROR_WORKFLOW_POLICY_INVALID = "workflow policy configuration is invalid"

# Descriptor and construction limits are deliberately independent. Byte limits
# apply before YAML parsing; event limits apply before object construction; the
# remaining limits apply before scan result materialization.
MAX_WORKFLOW_POLICY_BYTES = 256 * 1024
MAX_WORKFLOW_POLICY_STRING_BYTES = 4 * 1024
MAX_WORKFLOW_FILE_BYTES = 1 * 1024 * 1024
MAX_WORKFLOW_DISTINCT_INPUT_BYTES = 16 * 1024 * 1024
MAX_WORKFLOW_YAML_ALIASES = 128
MAX_WORKFLOW_YAML_NODES = 50_000
MAX_WORKFLOW_YAML_DEPTH = 64
MAX_WORKFLOW_GRAPH_TRAVERSAL = 100_000
MAX_WORKFLOW_REQUIRED_FILES = 1_024
MAX_WORKFLOW_CHECKS = 256
MAX_WORKFLOW_REQUIRED_COMMANDS = 4_096
MAX_WORKFLOW_JOBS = 1_024
MAX_WORKFLOW_STEPS = 16_384
MAX_WORKFLOW_COMMANDS = 16_384
MAX_WORKFLOW_COMMAND_CHARS = 4 * 1024 * 1024
MAX_WORKFLOW_MATCH_CHARS = 16 * 1024 * 1024
MAX_WORKFLOW_FINDINGS = 4_096
MAX_WORKFLOW_AGGREGATE_RESULT_BYTES = 8 * 1024 * 1024
WORKFLOW_FINDING_RESULT_OVERHEAD_BYTES = 512
MAX_WORKFLOW_TRAVERSAL = 32_768
MAX_WORKFLOW_PARALLEL_DEPTH = 64
MAX_WORKFLOW_SHELL_NESTING = 64
MAX_WORKFLOW_HEREDOCS = 128
# Per-command lexer limits are independent from aggregate scan limits. The
# lexer is linear, so deterministic structural budgets are preferable to a
# host-speed-dependent deadline.
MAX_WORKFLOW_LEXER_CHARS = MAX_WORKFLOW_FILE_BYTES
MAX_WORKFLOW_LEXER_STEPS = 256 * 1024
MAX_WORKFLOW_COMMAND_OPERATORS = 16_384
MAX_WORKFLOW_COMMAND_SEGMENTS = MAX_WORKFLOW_COMMAND_OPERATORS + 1

_DEFAULT_WORKFLOW_SHELL = object()
_SUPPORTED_WORKFLOW_COMMAND_SHELLS = frozenset(
    {"bash", "sh", "pwsh", "powershell", "cmd"}
)
_WORKFLOW_DECIMAL_LITERAL_RE = re.compile(
    r"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?\Z"
)
_WORKFLOW_HEX_LITERAL_RE = re.compile(r"-?0[xX][0-9a-fA-F]+\Z")
_AGENT_GUARD_PYTHON_EXECUTABLE_RE = re.compile(r"python(?:3(?:\.\d+)?)?\Z")
_AGENT_GUARD_COMMAND_MARKER_RE = re.compile(
    r"(?<![A-Za-z0-9_.-])(?:agent-guard(?:\.exe)?|agent_guard\.cli)"
    r"(?![A-Za-z0-9_.-])"
)
_AGENT_GUARD_LOOKING_EXPANSION_RE = re.compile(
    r"\$(?:\{[^}\r\n]*\}|[A-Za-z_][A-Za-z0-9_]*)"
    r"|%[^%\r\n]+%|![^!\r\n]+!"
)
_CMD_EXPANSION_RE = re.compile(r"%[^%\r\n]+%|%[0-9*~]|![^!\r\n]+!")
_SIMPLE_QUOTED_SHELL_SCALAR_RE = re.compile(
    r'"\$([A-Za-z_][A-Za-z0-9_]*)"'
)

_ARRAY_TOKEN_START = 0
_ARRAY_TOKEN_NAME = 1
_ARRAY_TOKEN_PLUS = 2
_ARRAY_TOKEN_ASSIGNMENT = 3
_ARRAY_TOKEN_INVALID = 4


class _WorkflowConfigurationLimit(ValueError):
    pass


@dataclass(frozen=True)
class RequiredFile:
    check_id: str
    path: str
    severity: str


@dataclass(frozen=True)
class RequiredWorkflowCommand:
    command_id: str
    command: str


@dataclass(frozen=True)
class WorkflowCheck:
    check_id: str
    path: str
    severity: str
    required_commands: list[RequiredWorkflowCommand]


@dataclass(frozen=True)
class WorkflowGuardFinding:
    rule_id: str
    severity: str
    file: str
    message: str
    reason: str
    workflow_id: str | None = None
    requirement_id: str | None = None
    job_id: str | None = None
    job_name: str | None = None
    step_index: int | None = None
    step_name: str | None = None

    def to_dict(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "file": self.file,
            "message": self.message,
            "reason": self.reason,
        }
        optional: dict[str, object | None] = {
            "workflow_id": self.workflow_id,
            "requirement_id": self.requirement_id,
            "job_id": self.job_id,
            "job_name": self.job_name,
            "step_index": self.step_index,
            "step_name": self.step_name,
        }
        payload.update({key: value for key, value in optional.items() if value is not None})
        return payload


@dataclass(frozen=True)
class WorkflowRunLine:
    workflow: str
    job_id: str
    job_name: str
    step_index: int
    step_name: str
    command: str
    shell: str | None = None


@dataclass(frozen=True)
class _CachedWorkflow:
    public_path: str
    raw: bytes
    parsed: dict[str, Any]
    run_lines: tuple[WorkflowRunLine, ...]


@dataclass(frozen=True)
class _HeredocSpec:
    delimiter: str
    strip_tabs: bool


@dataclass
class _ShellContext:
    kind: str
    depth: int
    return_quote: str | None


@dataclass
class _ShellState:
    quote: str | None = None
    contexts: list[_ShellContext] = field(default_factory=list)


@dataclass
class _ShellLexicalState:
    """Track whether the consumed prefix ends in a shell array assignment."""

    array_token: int = _ARRAY_TOKEN_START
    assignment_before_whitespace: bool = False

    @property
    def can_open_array(self) -> bool:
        return (
            self.array_token == _ARRAY_TOKEN_ASSIGNMENT
            or self.assignment_before_whitespace
        )

    def consume(self, character: str) -> None:
        if character.isspace():
            if self.array_token == _ARRAY_TOKEN_ASSIGNMENT:
                self.assignment_before_whitespace = True
            elif self.array_token != _ARRAY_TOKEN_START:
                self.assignment_before_whitespace = False
            self.array_token = _ARRAY_TOKEN_START
            return

        if character in ";|&":
            self.array_token = _ARRAY_TOKEN_START
            self.assignment_before_whitespace = False
            return

        self.assignment_before_whitespace = False
        if self.array_token == _ARRAY_TOKEN_START:
            self.array_token = (
                _ARRAY_TOKEN_NAME
                if character == "_"
                or "A" <= character <= "Z"
                or "a" <= character <= "z"
                else _ARRAY_TOKEN_INVALID
            )
        elif self.array_token == _ARRAY_TOKEN_NAME:
            if (
                character == "_"
                or "A" <= character <= "Z"
                or "a" <= character <= "z"
                or "0" <= character <= "9"
            ):
                return
            if character == "+":
                self.array_token = _ARRAY_TOKEN_PLUS
            elif character == "=":
                self.array_token = _ARRAY_TOKEN_ASSIGNMENT
            else:
                self.array_token = _ARRAY_TOKEN_INVALID
        elif self.array_token == _ARRAY_TOKEN_PLUS and character == "=":
            self.array_token = _ARRAY_TOKEN_ASSIGNMENT
        else:
            self.array_token = _ARRAY_TOKEN_INVALID

    def consume_range(self, value: str, *, start: int, end: int) -> None:
        for index in range(start, end):
            self.consume(value[index])


@dataclass
class _CommandLexerBudget:
    characters: int
    steps: int = 0
    operators: int = 0
    segments: int = 0


@dataclass
class _WorkflowScanBudget:
    jobs: int = 0
    steps: int = 0
    commands: int = 0
    command_chars: int = 0
    match_chars: int = 0
    traversal: int = 0
    distinct_input_bytes: int = 0
    finding_result_bytes: int = 0


def is_windows_absolute_path(raw_path: str) -> bool:
    return PureWindowsPath(raw_path).is_absolute() or bool(re.match(r"^[A-Za-z]:[\\/]", raw_path))


def _raise_configuration_limit() -> NoReturn:
    raise _WorkflowConfigurationLimit(ERROR_WORKFLOW_CONFIGURATION_LIMIT)


def _validate_command_lexer_characters(value: str) -> int:
    characters = len(value)
    if characters > MAX_WORKFLOW_LEXER_CHARS:
        _raise_configuration_limit()
    return characters


def _new_command_lexer_budget(value: str) -> _CommandLexerBudget:
    return _CommandLexerBudget(
        characters=_validate_command_lexer_characters(value)
    )


def _consume_command_lexer_budget(
    budget: _CommandLexerBudget,
    *,
    field_name: str,
    limit: int,
) -> None:
    current = getattr(budget, field_name)
    if current >= limit:
        _raise_configuration_limit()
    setattr(budget, field_name, current + 1)


def _utf8_size_bytes(value: str) -> int:
    try:
        return len(value.encode("utf-8"))
    except UnicodeEncodeError:
        _raise_configuration_limit()


def _validate_workflow_policy_string(value: str) -> None:
    if _utf8_size_bytes(value) > MAX_WORKFLOW_POLICY_STRING_BYTES:
        _raise_configuration_limit()


def _preflight_yaml_events(text: str) -> None:
    """Bound YAML syntax before SafeLoader constructs Python objects."""
    aliases = 0
    nodes = 0
    depth = 0
    node_events = (
        yaml.events.AliasEvent,
        yaml.events.MappingStartEvent,
        yaml.events.ScalarEvent,
        yaml.events.SequenceStartEvent,
    )
    start_events = (yaml.events.MappingStartEvent, yaml.events.SequenceStartEvent)
    end_events = (yaml.events.MappingEndEvent, yaml.events.SequenceEndEvent)

    for event in yaml.parse(text, Loader=yaml.SafeLoader):
        if isinstance(event, node_events):
            if nodes >= MAX_WORKFLOW_YAML_NODES:
                _raise_configuration_limit()
            nodes += 1
        if isinstance(event, yaml.events.AliasEvent):
            if aliases >= MAX_WORKFLOW_YAML_ALIASES:
                _raise_configuration_limit()
            aliases += 1
        if isinstance(event, start_events):
            if depth >= MAX_WORKFLOW_YAML_DEPTH:
                _raise_configuration_limit()
            depth += 1
        elif isinstance(event, end_events):
            depth -= 1
        if isinstance(event, yaml.events.ScalarEvent) and (
            event.tag == "tag:yaml.org,2002:merge"
            or (event.value == "<<" and event.style is None and event.implicit[0])
        ):
            # SafeLoader expands merge aliases while constructing mappings. The
            # ordinary alias form remains supported without that expansion.
            _raise_configuration_limit()


def _iter_mapping_children(value: dict[Any, Any]) -> Iterator[Any]:
    for key, child in value.items():
        yield key
        yield child


def _container_children(value: Any) -> Iterator[Any] | None:
    if isinstance(value, dict):
        return _iter_mapping_children(value)
    if isinstance(value, (list, tuple, set, frozenset)):
        return iter(value)
    return None


def _validate_object_graph(value: Any) -> None:
    """Reject cycles and bound alias-expanded graph traversal without recursion."""
    active: set[int] = set()
    stack: list[tuple[int, Iterator[Any], int]] = []
    traversed = 0

    def enter(child: Any, *, depth: int) -> None:
        nonlocal traversed
        if traversed >= MAX_WORKFLOW_GRAPH_TRAVERSAL or depth > MAX_WORKFLOW_YAML_DEPTH:
            _raise_configuration_limit()
        traversed += 1
        children = _container_children(child)
        if children is None:
            return
        identity = id(child)
        if identity in active:
            _raise_configuration_limit()
        active.add(identity)
        stack.append((identity, children, depth))

    enter(value, depth=1)
    while stack:
        identity, children, depth = stack[-1]
        try:
            child = next(children)
        except StopIteration:
            stack.pop()
            active.remove(identity)
            continue
        enter(child, depth=depth + 1)


def _parse_bounded_yaml(raw: bytes) -> Any:
    text = raw.decode("utf-8")
    try:
        _preflight_yaml_events(text)
        loaded = yaml.safe_load(text)
    except _WorkflowConfigurationLimit:
        raise
    except (OverflowError, RecursionError, ValueError):
        _raise_configuration_limit()
    _validate_object_graph(loaded)
    return loaded


def _read_workflow_policy_bytes(path: Path) -> bytes:
    try:
        with path.open("rb") as handle:
            raw = handle.read(MAX_WORKFLOW_POLICY_BYTES + 1)
    except FileNotFoundError:
        raise FileNotFoundError(f"policy file not found: {path}") from None
    except OSError:
        raise ValueError(ERROR_WORKFLOW_POLICY_INVALID) from None
    if len(raw) > MAX_WORKFLOW_POLICY_BYTES:
        _raise_configuration_limit()
    return raw


def load_workflow_policy(path: Path) -> dict[str, Any]:
    try:
        loaded = _parse_bounded_yaml(_read_workflow_policy_bytes(path)) or {}
    except (UnicodeDecodeError, yaml.YAMLError):
        raise ValueError(ERROR_WORKFLOW_POLICY_INVALID) from None
    if not isinstance(loaded, dict):
        raise ValueError(f"policy file must be YAML object: {path}")
    return loaded


def normalize_repo_relative_path(value: Any, *, label: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{label}: path must be a string")
    _validate_workflow_policy_string(value)
    path_text = value.strip()
    if not path_text:
        raise ValueError(f"{label}: path is required")
    if is_windows_absolute_path(path_text) or Path(path_text).is_absolute():
        raise ValueError(f"{label}: path must be repository-relative")

    normalized = path_text.replace("\\", "/")
    parts = Path(normalized).parts
    if ".." in parts:
        raise ValueError(f"{label}: path must not contain '..'")
    return Path(normalized).as_posix()


def optional_string_field(item: dict[str, Any], field: str, *, default: str, label: str) -> str:
    if field not in item:
        return default
    value = item[field]
    if not isinstance(value, str):
        raise ValueError(f"{label}.{field}: must be a string")
    _validate_workflow_policy_string(value)
    return value.strip() or default


def required_string_field(item: dict[str, Any], field: str, *, label: str) -> str:
    if field not in item:
        raise ValueError(f"{label}.{field}: is required")
    value = item[field]
    if not isinstance(value, str):
        raise ValueError(f"{label}.{field}: must be a string")
    _validate_workflow_policy_string(value)
    text = value.strip()
    if not text:
        raise ValueError(f"{label}.{field}: is required")
    return text


def resolve_repo_file(root: Path, rel_path: str, *, label: str) -> tuple[Path, str]:
    normalized = normalize_repo_relative_path(rel_path, label=label)
    target = (root / normalized).resolve()
    try:
        relative = target.relative_to(root)
    except ValueError:
        raise ValueError(f"{label}: path escapes root") from None
    return target, relative.as_posix()


def _path_is_lexically_under(path: Path, root: Path) -> bool:
    try:
        Path(os.path.abspath(path)).relative_to(Path(os.path.abspath(root)))
    except ValueError:
        return False
    return True


def _open_repo_file_posix(repo_root: Path, relative_path: Path) -> int:
    """Open a regular in-repo file without following path components."""
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    directory = getattr(os, "O_DIRECTORY", 0)
    if not nofollow or not directory or os.open not in os.supports_dir_fd:
        raise ValueError(ERROR_WORKFLOW_SCAN_TARGET)

    directory_flags = os.O_RDONLY | nofollow | directory | getattr(os, "O_CLOEXEC", 0)
    file_flags = os.O_RDONLY | nofollow | getattr(os, "O_CLOEXEC", 0)
    directory_fd: int | None = None
    file_fd: int | None = None
    try:
        directory_fd = os.open(repo_root, directory_flags)
        for component in relative_path.parts[:-1]:
            next_fd = os.open(component, directory_flags, dir_fd=directory_fd)
            os.close(directory_fd)
            directory_fd = next_fd
        file_fd = os.open(relative_path.parts[-1], file_flags, dir_fd=directory_fd)
        if not stat.S_ISREG(os.fstat(file_fd).st_mode):
            raise OSError
        return file_fd
    except (OSError, TypeError, ValueError):
        if file_fd is not None:
            os.close(file_fd)
        raise ValueError(ERROR_WORKFLOW_SCAN_TARGET) from None
    finally:
        if directory_fd is not None:
            os.close(directory_fd)


def _windows_final_handle_path(file_fd: int) -> str:
    import ctypes
    import msvcrt
    from ctypes import wintypes

    get_final_path = ctypes.WinDLL("kernel32", use_last_error=True).GetFinalPathNameByHandleW
    get_final_path.argtypes = [
        wintypes.HANDLE,
        wintypes.LPWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
    ]
    get_final_path.restype = wintypes.DWORD
    handle = msvcrt.get_osfhandle(file_fd)
    capacity = 512
    while capacity <= 32_768:
        buffer = ctypes.create_unicode_buffer(capacity)
        length = get_final_path(handle, buffer, capacity, 0)
        if length == 0:
            raise OSError
        if length < capacity:
            final_path = buffer.value
            if final_path.startswith("\\\\?\\UNC\\"):
                return "\\\\" + final_path[8:]
            if final_path.startswith("\\\\?\\"):
                return final_path[4:]
            return final_path
        capacity = length
    raise OSError


def _open_repo_file_windows(repo_root: Path, resolved_path: Path) -> int:
    """Open a file, then verify its final handle remains below the repo root."""
    file_fd: int | None = None
    try:
        file_fd = os.open(
            resolved_path,
            os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOINHERIT", 0),
        )
        if not stat.S_ISREG(os.fstat(file_fd).st_mode):
            raise OSError
        final_path = os.path.normcase(os.path.normpath(_windows_final_handle_path(file_fd)))
        normalized_root = os.path.normcase(os.path.normpath(str(repo_root)))
        if os.path.commonpath((normalized_root, final_path)) != normalized_root:
            raise OSError
        return file_fd
    except (OSError, TypeError, ValueError):
        if file_fd is not None:
            os.close(file_fd)
        raise ValueError(ERROR_WORKFLOW_SCAN_TARGET) from None


def _open_repo_bound_file(path: Path, repo_root: Path) -> int:
    """Bind a repository-relative path to a regular file before reading it."""
    if not _path_is_lexically_under(path, repo_root):
        raise ValueError(ERROR_WORKFLOW_SCAN_TARGET)

    try:
        resolved_root = repo_root.resolve(strict=True)
        resolved_path = path.resolve(strict=True)
        relative_path = resolved_path.relative_to(resolved_root)
    except FileNotFoundError:
        raise
    except (OSError, RuntimeError, ValueError):
        raise ValueError(ERROR_WORKFLOW_SCAN_TARGET) from None
    if not relative_path.parts:
        raise ValueError(ERROR_WORKFLOW_SCAN_TARGET)

    if os.name == "nt":
        return _open_repo_file_windows(resolved_root, resolved_path)
    return _open_repo_file_posix(resolved_root, relative_path)


def _read_repo_bound_bytes(path: Path, repo_root: Path, *, max_bytes: int) -> bytes:
    file_fd = _open_repo_bound_file(path, repo_root)
    try:
        handle = os.fdopen(file_fd, "rb")
    except OSError:
        try:
            os.close(file_fd)
        except OSError:
            pass
        raise ValueError(ERROR_WORKFLOW_SCAN_TARGET) from None
    try:
        with handle:
            raw = handle.read(max_bytes + 1)
    except OSError:
        raise ValueError(ERROR_WORKFLOW_SCAN_TARGET) from None
    if len(raw) > max_bytes:
        _raise_configuration_limit()
    return raw


def normalize_required_files(raw: Any) -> list[RequiredFile]:
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise ValueError("required_files must be a list")
    if len(raw) > MAX_WORKFLOW_REQUIRED_FILES:
        _raise_configuration_limit()

    required_files: list[RequiredFile] = []
    for idx, item in enumerate(raw, start=1):
        label = f"required_files[{idx}]"
        if isinstance(item, str):
            check_id = f"required_file_{idx}"
            path = normalize_repo_relative_path(item, label=label)
            severity = "high"
        elif isinstance(item, dict):
            check_id = optional_string_field(item, "id", default=f"required_file_{idx}", label=label)
            path = normalize_repo_relative_path(required_string_field(item, "path", label=label), label=label)
            severity = optional_string_field(item, "severity", default="high", label=label)
        else:
            raise ValueError(f"{label}: entry must be a string or object")
        if len(required_files) >= MAX_WORKFLOW_REQUIRED_FILES:
            _raise_configuration_limit()
        required_files.append(RequiredFile(check_id=check_id, path=path, severity=severity))
    return required_files


def normalize_required_commands(
    raw: Any,
    *,
    workflow_id: str,
    limit: int | None = None,
) -> list[RequiredWorkflowCommand]:
    if not isinstance(raw, list):
        raise ValueError(f"{workflow_id}: required_commands must be a list")
    command_limit = MAX_WORKFLOW_REQUIRED_COMMANDS if limit is None else limit
    if len(raw) > command_limit:
        _raise_configuration_limit()

    commands: list[RequiredWorkflowCommand] = []
    for idx, item in enumerate(raw, start=1):
        if isinstance(item, str):
            _validate_workflow_policy_string(item)
            command_id = f"required_command_{idx}"
            command = item.strip()
        elif isinstance(item, dict):
            label = f"{workflow_id}.required_commands[{idx}]"
            command_id = optional_string_field(item, "id", default=f"required_command_{idx}", label=label)
            command = required_string_field(item, "command", label=label)
        else:
            raise ValueError(f"{workflow_id}: required_commands[{idx}] must be a string or object")
        if not command:
            raise ValueError(f"{workflow_id}: required_commands[{idx}] command is required")
        if len(commands) >= command_limit:
            _raise_configuration_limit()
        commands.append(RequiredWorkflowCommand(command_id=command_id, command=command))
    if not commands:
        raise ValueError(f"{workflow_id}: required_commands must contain at least one command")
    return commands


def normalize_workflow_checks(raw: Any) -> list[WorkflowCheck]:
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise ValueError("workflow_checks must be a list")
    if len(raw) > MAX_WORKFLOW_CHECKS:
        _raise_configuration_limit()

    checks: list[WorkflowCheck] = []
    command_count = 0
    for idx, item in enumerate(raw, start=1):
        if not isinstance(item, dict):
            raise ValueError(f"workflow_checks[{idx}] must be an object")
        label = f"workflow_checks[{idx}]"
        check_id = optional_string_field(item, "id", default=f"workflow_check_{idx}", label=label)
        path = normalize_repo_relative_path(required_string_field(item, "path", label=label), label=f"{check_id}.path")
        severity = optional_string_field(item, "severity", default="high", label=label)
        commands = normalize_required_commands(
            item.get("required_commands", []),
            workflow_id=check_id,
            limit=MAX_WORKFLOW_REQUIRED_COMMANDS - command_count,
        )
        command_count += len(commands)
        if len(checks) >= MAX_WORKFLOW_CHECKS:
            _raise_configuration_limit()
        checks.append(
            WorkflowCheck(
                check_id=check_id,
                path=path,
                severity=severity,
                required_commands=commands,
            )
        )
    return checks


def load_workflow_file(raw: bytes, *, workflow_id: str) -> dict[str, Any]:
    if len(raw) > MAX_WORKFLOW_FILE_BYTES:
        _raise_configuration_limit()
    try:
        loaded = _parse_bounded_yaml(raw) or {}
    except (UnicodeDecodeError, yaml.YAMLError) as exc:
        mark = getattr(exc, "problem_mark", None) or getattr(exc, "context_mark", None)
        location = f" at line {mark.line + 1}, column {mark.column + 1}" if mark is not None else ""
        raise ValueError(f"{workflow_id}: workflow YAML is invalid{location}") from exc
    if not isinstance(loaded, dict):
        raise ValueError(f"{workflow_id}: workflow file must be a YAML object")
    return loaded


def is_escaped_character(value: str, *, index: int) -> bool:
    backslash_count = 0
    cursor = index - 1
    while cursor >= 0 and value[cursor] == "\\":
        backslash_count += 1
        cursor -= 1
    return backslash_count % 2 == 1


def is_shell_comment_position(value: str, *, index: int) -> bool:
    if index == 0:
        return True
    previous = value[index - 1]
    if previous.isspace() or previous in {";", "|", "&", "(", ")"}:
        return not is_escaped_character(value, index=index - 1)
    return False


def _push_shell_context(state: _ShellState, *, kind: str, depth: int) -> None:
    if len(state.contexts) >= MAX_WORKFLOW_SHELL_NESTING:
        raise ValueError(ERROR_WORKFLOW_SHELL_SYNTAX)
    state.contexts.append(
        _ShellContext(kind=kind, depth=depth, return_quote=state.quote)
    )
    state.quote = None


def _pop_shell_context(state: _ShellState) -> None:
    context = state.contexts.pop()
    state.quote = context.return_quote


def _try_open_shell_context(
    value: str,
    *,
    index: int,
    state: _ShellState,
    lexical_state: _ShellLexicalState,
) -> int | None:
    if value.startswith("$((", index):
        _push_shell_context(state, kind="arithmetic", depth=2)
        return index + 3
    if value.startswith("$(", index):
        _push_shell_context(state, kind="command", depth=1)
        return index + 2
    if value.startswith("${", index):
        _push_shell_context(state, kind="parameter", depth=1)
        return index + 2
    if value[index] == "`":
        _push_shell_context(state, kind="backtick", depth=0)
        return index + 1
    if (
        state.quote is None
        and value[index] == "("
        and lexical_state.can_open_array
    ):
        _push_shell_context(state, kind="array", depth=1)
        return index + 1
    if state.quote is None and (
        value.startswith("<(", index) or value.startswith(">(", index)
    ):
        _push_shell_context(state, kind="process", depth=1)
        return index + 2
    return None


def _consume_shell_structure(
    value: str,
    *,
    index: int,
    state: _ShellState,
    lexical_state: _ShellLexicalState,
) -> int | None:
    """Consume quoting/nesting syntax, or return None for a plain root character."""
    character = value[index]
    if state.quote == "'":
        if character == "'":
            state.quote = None
        return index + 1
    if state.quote == '"':
        if character == "\\":
            return min(index + 2, len(value))
        if character == '"':
            state.quote = None
            return index + 1
        opened = _try_open_shell_context(
            value,
            index=index,
            state=state,
            lexical_state=lexical_state,
        )
        return opened if opened is not None else index + 1

    if character == "\\":
        return min(index + 2, len(value))
    if state.contexts and state.contexts[-1].kind == "backtick" and character == "`":
        _pop_shell_context(state)
        return index + 1
    if character in {"'", '"'}:
        state.quote = character
        return index + 1
    opened = _try_open_shell_context(
        value,
        index=index,
        state=state,
        lexical_state=lexical_state,
    )
    if opened is not None:
        return opened
    if not state.contexts:
        return None

    context = state.contexts[-1]
    if context.kind in {"arithmetic", "array", "command", "process"}:
        if character == "(":
            if context.depth >= MAX_WORKFLOW_SHELL_NESTING:
                raise ValueError(ERROR_WORKFLOW_SHELL_SYNTAX)
            context.depth += 1
        elif character == ")":
            context.depth -= 1
            if context.depth == 0:
                _pop_shell_context(state)
    elif context.kind == "parameter":
        if character == "{":
            if context.depth >= MAX_WORKFLOW_SHELL_NESTING:
                raise ValueError(ERROR_WORKFLOW_SHELL_SYNTAX)
            context.depth += 1
        elif character == "}":
            context.depth -= 1
            if context.depth == 0:
                _pop_shell_context(state)
    return index + 1


def _parse_heredoc(value: str, *, index: int) -> tuple[_HeredocSpec | None, int]:
    if value.startswith("<<<", index):
        return None, index + 3

    cursor = index + 2
    strip_tabs = False
    if cursor < len(value) and value[cursor] == "-":
        strip_tabs = True
        cursor += 1
    while cursor < len(value) and value[cursor] in {" ", "\t"}:
        cursor += 1
    if cursor >= len(value):
        raise ValueError(ERROR_WORKFLOW_SHELL_SYNTAX)

    delimiter_quote = value[cursor]
    if delimiter_quote in {"'", '"'}:
        delimiter_end = value.find(delimiter_quote, cursor + 1)
        if delimiter_end < 0:
            raise ValueError(ERROR_WORKFLOW_SHELL_SYNTAX)
        delimiter = value[cursor + 1 : delimiter_end]
        cursor = delimiter_end + 1
    else:
        delimiter_match = HEREDOC_DELIMITER_RE.match(value, cursor)
        if delimiter_match is None:
            raise ValueError(ERROR_WORKFLOW_SHELL_SYNTAX)
        delimiter = delimiter_match.group(0)
        cursor = delimiter_match.end()

    if not delimiter or HEREDOC_DELIMITER_RE.fullmatch(delimiter) is None:
        raise ValueError(ERROR_WORKFLOW_SHELL_SYNTAX)
    if cursor < len(value) and value[cursor] not in " \t;|&()<>#":
        raise ValueError(ERROR_WORKFLOW_SHELL_SYNTAX)
    return _HeredocSpec(delimiter=delimiter, strip_tabs=strip_tabs), cursor


def _scan_shell_fragment(
    value: str,
    *,
    state: _ShellState,
) -> tuple[str, bool, list[_HeredocSpec]]:
    lexer_budget = _new_command_lexer_budget(value)
    lexical_state = _ShellLexicalState()
    heredocs: list[_HeredocSpec] = []
    comment_start: int | None = None
    continued = False
    content_end = len(value)
    index = 0
    while index < len(value):
        _consume_command_lexer_budget(
            lexer_budget,
            field_name="steps",
            limit=MAX_WORKFLOW_LEXER_STEPS,
        )
        character = value[index]
        if state.quote != "'" and character == "\\" and index + 1 == len(value):
            continued = True
            content_end = index
            break
        if state.quote is None:
            if character == "#" and is_shell_comment_position(value, index=index):
                comment_start = index
                break
            arithmetic = bool(
                state.contexts and state.contexts[-1].kind == "arithmetic"
            )
            if not arithmetic and value.startswith("<<", index):
                spec, next_index = _parse_heredoc(value, index=index)
                if spec is not None:
                    if len(heredocs) >= MAX_WORKFLOW_HEREDOCS:
                        _raise_configuration_limit()
                    heredocs.append(spec)
                lexical_state.consume_range(value, start=index, end=next_index)
                index = next_index
                continue
        consumed = _consume_shell_structure(
            value,
            index=index,
            state=state,
            lexical_state=lexical_state,
        )
        next_index = index + 1 if consumed is None else consumed
        lexical_state.consume_range(value, start=index, end=next_index)
        index = next_index

    if comment_start is not None:
        content_end = comment_start
        if not state.contexts and state.quote is None:
            # Preserve the historical helper output for ordinary inline
            # comments. Nested comments are removed so later physical lines do
            # not become part of the comment after joining.
            content_end = len(value)
    return value[:content_end], continued, heredocs


def find_shell_comment_start(command_line: str) -> int | None:
    """Return the first root-level unquoted, unescaped shell-comment marker."""
    lexer_budget = _new_command_lexer_budget(command_line)
    lexical_state = _ShellLexicalState()
    state = _ShellState()
    index = 0
    while index < len(command_line):
        _consume_command_lexer_budget(
            lexer_budget,
            field_name="steps",
            limit=MAX_WORKFLOW_LEXER_STEPS,
        )
        character = command_line[index]
        if (
            state.quote is None
            and not state.contexts
            and character == "#"
            and is_shell_comment_position(command_line, index=index)
        ):
            return index
        consumed = _consume_shell_structure(
            command_line,
            index=index,
            state=state,
            lexical_state=lexical_state,
        )
        next_index = index + 1 if consumed is None else consumed
        lexical_state.consume_range(command_line, start=index, end=next_index)
        index = next_index
    return None


def find_heredoc_delimiter(command_line: str) -> str | None:
    """Return the first supported root or substitution heredoc delimiter."""
    _, _, heredocs = _scan_shell_fragment(command_line, state=_ShellState())
    return heredocs[0].delimiter if heredocs else None


def _iter_active_shell_lines(run_text: str) -> Iterator[str]:
    state = _ShellState()
    active_heredocs: deque[_HeredocSpec] = deque()
    pending_heredocs: deque[_HeredocSpec] = deque()
    logical_parts: list[str] = []
    continued = False
    heredoc_count = 0

    for raw_with_newline in io.StringIO(run_text):
        raw_line = raw_with_newline.removesuffix("\n").removesuffix("\r")
        if active_heredocs:
            heredoc = active_heredocs[0]
            candidate = raw_line.lstrip("\t") if heredoc.strip_tabs else raw_line
            if candidate == heredoc.delimiter:
                active_heredocs.popleft()
            continue

        if (
            not logical_parts
            and state.quote is None
            and not state.contexts
            and raw_line.lstrip().startswith("#")
        ):
            continue

        was_open = state.quote is not None or bool(state.contexts)
        fragment, continued, heredocs = _scan_shell_fragment(raw_line, state=state)
        if fragment or was_open:
            logical_parts.append(fragment.strip())
        for heredoc in heredocs:
            if heredoc_count >= MAX_WORKFLOW_HEREDOCS:
                _raise_configuration_limit()
            heredoc_count += 1
            pending_heredocs.append(heredoc)

        if pending_heredocs and not continued and state.quote is None:
            active_heredocs.extend(pending_heredocs)
            pending_heredocs.clear()

        if not continued and state.quote is None and not state.contexts:
            command = " ".join(logical_parts).strip()
            logical_parts.clear()
            if command and not command.startswith("#"):
                yield command

    if (
        active_heredocs
        or pending_heredocs
        or continued
        or state.quote is not None
        or state.contexts
    ):
        raise ValueError(ERROR_WORKFLOW_SHELL_SYNTAX)
    if logical_parts:
        command = " ".join(logical_parts).strip()
        if command and not command.startswith("#"):
            yield command


def iter_active_shell_lines(run_text: str) -> list[str]:
    active: list[str] = []
    command_chars = 0
    for command in _iter_active_shell_lines(run_text):
        if len(active) >= MAX_WORKFLOW_COMMANDS:
            _raise_configuration_limit()
        if len(command) > MAX_WORKFLOW_COMMAND_CHARS - command_chars:
            _raise_configuration_limit()
        command_chars += len(command)
        active.append(command)
    return active


def _consume_scan_budget(
    budget: _WorkflowScanBudget,
    *,
    field_name: str,
    limit: int,
) -> None:
    current = getattr(budget, field_name)
    if current >= limit:
        _raise_configuration_limit()
    setattr(budget, field_name, current + 1)


def _consume_scan_size_budget(
    budget: _WorkflowScanBudget,
    *,
    field_name: str,
    amount: int,
    limit: int,
) -> None:
    current = getattr(budget, field_name)
    if amount > limit - current:
        _raise_configuration_limit()
    setattr(budget, field_name, current + amount)


def _workflow_finding_result_size_bytes(*values: str | None) -> int:
    # JSON escaping can expand an individual UTF-8 byte to a six-byte escape.
    return WORKFLOW_FINDING_RESULT_OVERHEAD_BYTES + 6 * sum(
        _utf8_size_bytes(value) for value in values if value is not None
    )


def _append_workflow_finding(
    findings: list[WorkflowGuardFinding],
    budget: _WorkflowScanBudget,
    *,
    rule_id: str,
    severity: str,
    file: str,
    message: str,
    reason: str,
    workflow_id: str | None = None,
    requirement_id: str | None = None,
    job_id: str | None = None,
    job_name: str | None = None,
    step_index: int | None = None,
    step_name: str | None = None,
) -> None:
    if len(findings) >= MAX_WORKFLOW_FINDINGS:
        _raise_configuration_limit()
    finding_result_bytes = _workflow_finding_result_size_bytes(
        rule_id,
        severity,
        file,
        message,
        reason,
        workflow_id,
        requirement_id,
        job_id,
        job_name,
        step_name,
    )
    _consume_scan_size_budget(
        budget,
        field_name="finding_result_bytes",
        amount=finding_result_bytes,
        limit=MAX_WORKFLOW_AGGREGATE_RESULT_BYTES,
    )
    findings.append(
        WorkflowGuardFinding(
            rule_id=rule_id,
            severity=severity,
            file=file,
            message=message,
            reason=reason,
            workflow_id=workflow_id,
            requirement_id=requirement_id,
            job_id=job_id,
            job_name=job_name,
            step_index=step_index,
            step_name=step_name,
        )
    )


def collect_run_lines(
    workflow: dict[str, Any],
    *,
    workflow_path: str,
    _budget: _WorkflowScanBudget | None = None,
) -> list[WorkflowRunLine]:
    _validate_object_graph(workflow)
    raw_jobs = workflow.get("jobs", {})
    if raw_jobs is None:
        raw_jobs = {}
    if not isinstance(raw_jobs, dict):
        raise ValueError(f"{workflow_path}: jobs must be an object")
    budget = _budget if _budget is not None else _WorkflowScanBudget()
    if len(raw_jobs) > MAX_WORKFLOW_JOBS - budget.jobs:
        _raise_configuration_limit()

    workflow_shell = _default_run_shell(workflow, inherited=_DEFAULT_WORKFLOW_SHELL)
    lines: list[WorkflowRunLine] = []
    for raw_job_id, raw_job in raw_jobs.items():
        _consume_scan_budget(budget, field_name="jobs", limit=MAX_WORKFLOW_JOBS)
        _consume_scan_budget(
            budget,
            field_name="traversal",
            limit=MAX_WORKFLOW_TRAVERSAL,
        )
        job_id = str(raw_job_id)
        if not isinstance(raw_job, dict):
            raise ValueError(f"{workflow_path}: job {job_id} must be an object")
        job_name = str(raw_job.get("name", "")).strip()
        job_eligible = not _condition_is_statically_false(raw_job) and not (
            _continue_on_error_may_mask(raw_job)
        )
        job_shell = _default_run_shell(raw_job, inherited=workflow_shell)
        raw_steps = raw_job.get("steps", [])
        if raw_steps is None:
            raw_steps = []
        if not isinstance(raw_steps, list):
            raise ValueError(f"{workflow_path}: job {job_id} steps must be a list")
        if len(raw_steps) > MAX_WORKFLOW_STEPS - budget.steps:
            _raise_configuration_limit()
        for step_index, raw_step in enumerate(raw_steps, start=1):
            _collect_step_run_lines_iterative(
                raw_step,
                workflow_path=workflow_path,
                job_id=job_id,
                job_name=job_name,
                step_index=step_index,
                lines=lines,
                budget=budget,
                execution_eligible=job_eligible,
                default_shell=job_shell,
            )
    return lines


def collect_step_run_lines(
    raw_step: dict[str, Any],
    *,
    workflow_path: str,
    job_id: str,
    job_name: str,
    step_index: int,
) -> list[WorkflowRunLine]:
    lines: list[WorkflowRunLine] = []
    _validate_object_graph(raw_step)
    _collect_step_run_lines_iterative(
        raw_step,
        workflow_path=workflow_path,
        job_id=job_id,
        job_name=job_name,
        step_index=step_index,
        lines=lines,
        budget=_WorkflowScanBudget(),
        execution_eligible=True,
        default_shell=_DEFAULT_WORKFLOW_SHELL,
    )
    return lines


def _collect_step_run_lines_iterative(
    raw_step: Any,
    *,
    workflow_path: str,
    job_id: str,
    job_name: str,
    step_index: int,
    lines: list[WorkflowRunLine],
    budget: _WorkflowScanBudget,
    execution_eligible: bool,
    default_shell: object,
) -> None:
    active: set[int] = set()
    stack: list[tuple[int, Iterator[tuple[int, Any]], int, bool, object]] = []

    def enter(
        step: Any,
        *,
        parallel_depth: int,
        parallel_index: int | None,
        inherited_eligible: bool,
        inherited_shell: object,
    ) -> None:
        _consume_scan_budget(budget, field_name="steps", limit=MAX_WORKFLOW_STEPS)
        _consume_scan_budget(
            budget,
            field_name="traversal",
            limit=MAX_WORKFLOW_TRAVERSAL,
        )
        if parallel_depth > MAX_WORKFLOW_PARALLEL_DEPTH:
            _raise_configuration_limit()
        if not isinstance(step, dict):
            if parallel_index is None:
                raise ValueError(
                    f"{workflow_path}: job {job_id} step {step_index} must be an object"
                )
            raise ValueError(
                f"{workflow_path}: job {job_id} step {step_index} "
                f"parallel item {parallel_index} must be an object"
            )

        identity = id(step)
        if identity in active:
            _raise_configuration_limit()
        active.add(identity)

        step_eligible = inherited_eligible and not _condition_is_statically_false(step)
        step_eligible = step_eligible and not _continue_on_error_may_mask(step)
        effective_shell = step.get("shell", inherited_shell)
        run = step.get("run")
        if (
            isinstance(run, str)
            and step_eligible
            and _shell_can_run_required_command(effective_shell)
        ):
            step_name = str(step.get("name", "")).strip()
            for command in _iter_active_shell_lines(run):
                _consume_scan_budget(
                    budget,
                    field_name="commands",
                    limit=MAX_WORKFLOW_COMMANDS,
                )
                _consume_scan_size_budget(
                    budget,
                    field_name="command_chars",
                    amount=len(command),
                    limit=MAX_WORKFLOW_COMMAND_CHARS,
                )
                lines.append(
                    WorkflowRunLine(
                        workflow=workflow_path,
                        job_id=job_id,
                        job_name=job_name,
                        step_index=step_index,
                        step_name=step_name,
                        command=command,
                        shell=(
                            effective_shell
                            if isinstance(effective_shell, str)
                            else None
                        ),
                    )
                )

        raw_parallel = step.get("parallel")
        if raw_parallel is None:
            active.remove(identity)
            return
        if not isinstance(raw_parallel, list):
            raise ValueError(
                f"{workflow_path}: job {job_id} step {step_index} parallel must be a list"
            )
        if len(raw_parallel) > MAX_WORKFLOW_STEPS - budget.steps:
            _raise_configuration_limit()
        stack.append(
            (
                identity,
                iter(enumerate(raw_parallel, start=1)),
                parallel_depth,
                step_eligible,
                effective_shell,
            )
        )

    enter(
        raw_step,
        parallel_depth=0,
        parallel_index=None,
        inherited_eligible=execution_eligible,
        inherited_shell=default_shell,
    )
    while stack:
        (
            identity,
            children,
            parallel_depth,
            inherited_eligible,
            inherited_shell,
        ) = stack[-1]
        try:
            parallel_index, child = next(children)
        except StopIteration:
            stack.pop()
            active.remove(identity)
            continue
        enter(
            child,
            parallel_depth=parallel_depth + 1,
            parallel_index=parallel_index,
            inherited_eligible=inherited_eligible,
            inherited_shell=inherited_shell,
        )


def _condition_is_statically_false(container: dict[str, Any]) -> bool:
    if "if" not in container:
        return False
    value = container["if"]
    if value is False or value is None:
        return True
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return value == 0
    if not isinstance(value, str):
        return False
    normalized = value.strip()
    if normalized.startswith("${{") and normalized.endswith("}}"):
        normalized = normalized[3:-2].strip()
    if _workflow_numeric_literal_is_zero(normalized):
        return True
    return normalized.casefold() in {"", "false", "null", "''", '""'}


def _workflow_numeric_literal_is_zero(value: str) -> bool:
    if _WORKFLOW_HEX_LITERAL_RE.fullmatch(value):
        digits = value.lstrip("-")[2:]
        return bool(digits) and not digits.strip("0")
    if not _WORKFLOW_DECIMAL_LITERAL_RE.fullmatch(value):
        return False
    mantissa = re.split(r"[eE]", value.lstrip("-"), maxsplit=1)[0]
    digits = mantissa.replace(".", "")
    return bool(digits) and not digits.strip("0")


def _continue_on_error_may_mask(container: dict[str, Any]) -> bool:
    if "continue-on-error" not in container:
        return False
    value = container["continue-on-error"]
    if value is False:
        return False
    if not isinstance(value, str):
        return True
    normalized = value.strip()
    if normalized.startswith("${{") and normalized.endswith("}}"):
        normalized = normalized[3:-2].strip()
    return normalized.casefold() != "false"


def _default_run_shell(container: dict[str, Any], *, inherited: object) -> object:
    defaults = container.get("defaults")
    if not isinstance(defaults, dict):
        return inherited
    run_defaults = defaults.get("run")
    if not isinstance(run_defaults, dict) or "shell" not in run_defaults:
        return inherited
    return run_defaults["shell"]


def _shell_can_run_required_command(shell: object) -> bool:
    if shell is _DEFAULT_WORKFLOW_SHELL:
        return True
    return isinstance(shell, str) and shell in _SUPPORTED_WORKFLOW_COMMAND_SHELLS


def normalize_command_text(command: str) -> str:
    return re.sub(r"\s+", " ", command.strip())


def is_documentation_segment(segment: str) -> bool:
    first_token = re.search(r"\S+", segment)
    if first_token is None:
        return True
    return first_token.group(0).lower() in DOCUMENTATION_COMMANDS


def has_help_option(segment: str) -> bool:
    return any(
        token.group(0) in HELP_OPTIONS
        for token in re.finditer(r"\S+", segment)
    )


def is_file_descriptor_redirection_ampersand(command_line: str, *, index: int) -> bool:
    """Keep ``>&``, ``<&``, and Bash ``&>``/``&>>`` redirections in-segment."""
    return command_line.startswith("&>", index) or (
        index > 0
        and command_line[index - 1] in {">", "<"}
        and not is_escaped_character(command_line, index=index - 1)
    )


def _iter_bounded_command_segments(
    command_line: str,
) -> Iterator[tuple[str, str | None]]:
    budget = _new_command_lexer_budget(command_line)
    lexical_state = _ShellLexicalState()
    state = _ShellState()
    segment_start = 0
    command_end = len(command_line)
    index = 0
    while index < len(command_line):
        _consume_command_lexer_budget(
            budget,
            field_name="steps",
            limit=MAX_WORKFLOW_LEXER_STEPS,
        )
        character = command_line[index]
        if state.quote != "'" and character == "\\" and index + 1 == len(command_line):
            raise ValueError(ERROR_WORKFLOW_SHELL_SYNTAX)
        if (
            state.quote is None
            and not state.contexts
            and character == "#"
            and is_shell_comment_position(command_line, index=index)
        ):
            command_end = index
            break

        if state.quote is None:
            arithmetic = bool(
                state.contexts and state.contexts[-1].kind == "arithmetic"
            )
            if not arithmetic and command_line.startswith("<<", index):
                _, next_index = _parse_heredoc(command_line, index=index)
                lexical_state.consume_range(
                    command_line,
                    start=index,
                    end=next_index,
                )
                index = next_index
                continue

        consumed = _consume_shell_structure(
            command_line,
            index=index,
            state=state,
            lexical_state=lexical_state,
        )
        if consumed is not None:
            lexical_state.consume_range(
                command_line,
                start=index,
                end=consumed,
            )
            index = consumed
            continue

        operator: str | None = None
        operator_width = 0
        if command_line.startswith("&&", index):
            operator = "&&"
            operator_width = 2
        elif command_line.startswith("||", index):
            operator = "||"
            operator_width = 2
        elif character == ";":
            operator = ";"
            operator_width = 1
        elif command_line.startswith("|&", index):
            operator = "|"
            operator_width = 2
        elif character == "|":
            operator = "|"
            operator_width = 1
        elif character == "&" and not is_file_descriptor_redirection_ampersand(
            command_line, index=index
        ):
            operator = "&"
            operator_width = 1
        if operator is None:
            lexical_state.consume(command_line[index])
            index += 1
            continue

        _consume_command_lexer_budget(
            budget,
            field_name="operators",
            limit=MAX_WORKFLOW_COMMAND_OPERATORS,
        )
        _consume_command_lexer_budget(
            budget,
            field_name="segments",
            limit=MAX_WORKFLOW_COMMAND_SEGMENTS,
        )
        segment = command_line[segment_start:index]
        next_index = index + operator_width
        lexical_state.consume_range(
            command_line,
            start=index,
            end=next_index,
        )
        index = next_index
        segment_start = index
        yield segment, operator

    if state.quote is not None or state.contexts:
        raise ValueError(ERROR_WORKFLOW_SHELL_SYNTAX)
    _consume_command_lexer_budget(
        budget,
        field_name="segments",
        limit=MAX_WORKFLOW_COMMAND_SEGMENTS,
    )
    yield command_line[segment_start:command_end], None


def iter_command_segments(command_line: str) -> list[tuple[str, str | None]]:
    """Return bounded shell segments for compatibility with existing callers."""
    segments: list[tuple[str, str | None]] = []
    for segment in _iter_bounded_command_segments(command_line):
        # The iterator consumes segment/operator budgets before yielding, so
        # this append can never grow beyond the deterministic command limit.
        segments.append(segment)
    return segments


def has_unconditional_semicolon_tail(
    segments: list[tuple[str, str | None]], *, start_index: int
) -> bool:
    """Reject unconditional same-line work after a matched required command."""
    for index in range(start_index + 1, len(segments)):
        if segments[index - 1][1] != ";":
            continue
        if normalize_command_text(segments[index][0]):
            return True
    return False


def has_backgrounded_command_list(segments: list[tuple[str, str | None]], *, start_index: int) -> bool:
    """Reject a required command whose enclosing AND-list is backgrounded."""
    return any(operator == "&" for _, operator in segments[start_index:])


def has_preceding_same_list_or(segments: list[tuple[str, str | None]], *, start_index: int) -> bool:
    """Reject a guard whose enclosing AND-OR list can skip it through ``||``."""
    for index in range(start_index - 1, -1, -1):
        operator = segments[index][1]
        if operator in {";", "&"}:
            return False
        if operator == "||":
            return True
    return False


@dataclass(frozen=True)
class _NormalizedAgentGuardCommand:
    arguments: tuple[tuple[object, ...], ...]


@dataclass(frozen=True)
class _DynamicShellScalar:
    name: str


def _looks_like_agent_guard_command(command: str) -> bool:
    probe = _AGENT_GUARD_LOOKING_EXPANSION_RE.sub(
        "",
        command.replace("^", "").replace("`", ""),
    )
    return _AGENT_GUARD_COMMAND_MARKER_RE.search(probe) is not None


def _agent_guard_redirection_operator(
    command: str,
    *,
    index: int,
) -> tuple[str, int] | None:
    if command.startswith("<(", index) or command.startswith(">(", index):
        return None
    for operator in (
        "&>>",
        "<<<",
        "<<-",
        "&>",
        ">&",
        "<&",
        ">>",
        "<<",
        "<>",
        ">|",
        ">",
        "<",
    ):
        if command.startswith(operator, index):
            return operator, index + len(operator)
    return None


def _consume_static_agent_guard_word(
    command: str,
    *,
    index: int,
    reject_dynamic: bool,
    shell: str | None,
) -> tuple[str | _DynamicShellScalar, int, bool] | None:
    if reject_dynamic and shell in {None, "bash", "sh"}:
        dynamic_scalar = _SIMPLE_QUOTED_SHELL_SCALAR_RE.match(command, index)
        if dynamic_scalar is not None:
            end = dynamic_scalar.end()
            if (
                end == len(command)
                or command[end].isspace()
                or _agent_guard_redirection_operator(command, index=end) is not None
            ):
                return _DynamicShellScalar(dynamic_scalar.group(1)), end, False
    characters: list[str] = []
    started = False
    plain = True
    while index < len(command):
        character = command[index]
        if character.isspace():
            break
        if _agent_guard_redirection_operator(command, index=index) is not None:
            break
        if command.startswith("<(", index) or command.startswith(">(", index):
            return None
        if character == "'":
            plain = False
            started = True
            end = command.find("'", index + 1)
            if end < 0:
                return None
            characters.append(command[index + 1 : end])
            index = end + 1
            continue
        if character == '"':
            plain = False
            started = True
            index += 1
            while index < len(command) and command[index] != '"':
                character = command[index]
                if reject_dynamic and character in {"$", "`"}:
                    return None
                if character == "\\" and index + 1 < len(command):
                    escaped = command[index + 1]
                    if escaped in {'"', "\\", "$", "`"}:
                        if reject_dynamic and escaped in {"$", "`"} and shell in {
                            None,
                            "pwsh",
                            "powershell",
                        }:
                            return None
                        characters.append(escaped)
                        index += 2
                        continue
                characters.append(character)
                index += 1
            if index >= len(command):
                return None
            index += 1
            continue
        if character == "\\":
            plain = False
            started = True
            if index + 1 >= len(command):
                return None
            escaped = command[index + 1]
            if reject_dynamic and escaped in {"$", "`"} and shell in {
                None,
                "pwsh",
                "powershell",
            }:
                return None
            characters.append(escaped)
            index += 2
            continue
        if reject_dynamic and character in {"$", "`", "*", "?", "[", "{", "}"}:
            return None
        if (
            reject_dynamic
            and shell in {"pwsh", "powershell"}
            and character == "@"
            and not started
        ):
            return None
        started = True
        characters.append(character)
        index += 1
    if not started:
        return None
    return "".join(characters), index, plain


def _static_agent_guard_argv(
    command: str,
    *,
    shell: str | None,
) -> list[str | _DynamicShellScalar] | None:
    """Return static native argv while excluding shell redirections."""
    if "${{" in command:
        return None
    if shell == "cmd" and ("^" in command or _CMD_EXPANSION_RE.search(command)):
        return None
    if shell in {"pwsh", "powershell"} and "`" in command:
        return None

    argv: list[str | _DynamicShellScalar] = []
    index = 0
    while index < len(command):
        while index < len(command) and command[index].isspace():
            index += 1
        if index >= len(command):
            break

        redirection = _agent_guard_redirection_operator(command, index=index)
        if redirection is not None:
            _, index = redirection
            while index < len(command) and command[index].isspace():
                index += 1
            target = _consume_static_agent_guard_word(
                command,
                index=index,
                reject_dynamic=False,
                shell=shell,
            )
            if target is None:
                return None
            _, index, _ = target
            continue

        word = _consume_static_agent_guard_word(
            command,
            index=index,
            reject_dynamic=True,
            shell=shell,
        )
        if word is None:
            return None
        value, next_index, plain = word
        redirection = _agent_guard_redirection_operator(
            command,
            index=next_index,
        )
        if redirection is not None and plain and value.isdigit():
            index = next_index
            continue
        argv.append(value)
        index = next_index
    return argv


@cache
def _agent_guard_cli_parser() -> argparse.ArgumentParser:
    # Import lazily because the public CLI imports this workflow guard.
    from .cli import build_parser

    return build_parser()


def _agent_guard_entrypoint_size(
    argv: list[str | _DynamicShellScalar],
) -> int | None:
    if argv[:1] == ["agent-guard"]:
        return 1
    if (
        argv
        and isinstance(argv[0], str)
        and _AGENT_GUARD_PYTHON_EXECUTABLE_RE.fullmatch(argv[0])
    ):
        module_index = 2 if argv[1:2] == ["-I"] else 1
        if argv[module_index : module_index + 2] == ["-m", "agent_guard.cli"]:
            return module_index + 2
    return None


def _agent_guard_leaf_parser(
    argv: list[str | _DynamicShellScalar],
) -> tuple[list[str], argparse.ArgumentParser, int] | None:
    parser = _agent_guard_cli_parser()
    route: list[str] = []
    index = 0
    while True:
        subparsers = next(
            (
                action
                for action in parser._actions
                if isinstance(action, argparse._SubParsersAction)
            ),
            None,
        )
        if subparsers is None:
            return route, parser, index
        if index >= len(argv):
            return None
        route_value = argv[index]
        if not isinstance(route_value, str):
            return None
        subparser = subparsers.choices.get(route_value)
        if subparser is None:
            return None
        route.append(route_value)
        parser = subparser
        index += 1


def _resolve_agent_guard_option(
    value: str,
    *,
    options: dict[str, argparse.Action],
) -> tuple[argparse.Action | None, str | None, bool]:
    option, separator, inline_value = value.partition("=")
    action = options.get(option)
    if action is not None:
        return action, inline_value if separator else None, False
    if not option.startswith("--"):
        return None, None, False

    matching_actions = {
        id(candidate): candidate
        for option_name, candidate in options.items()
        if option_name.startswith("--") and option_name.startswith(option)
    }
    if len(matching_actions) == 1:
        return next(iter(matching_actions.values())), inline_value if separator else None, False
    return None, None, bool(matching_actions)


def _agent_guard_option_values(
    argv: list[str | _DynamicShellScalar],
    *,
    index: int,
    action: argparse.Action,
    inline_value: str | None,
) -> tuple[tuple[object, ...], int] | None:
    if action.nargs == 0:
        if inline_value is not None:
            return None
        return (), 1
    if action.nargs is None:
        if inline_value is not None:
            return (inline_value,), 1
        if index + 1 >= len(argv):
            return None
        value = argv[index + 1]
        if value == "--" or (
            isinstance(value, str) and value.startswith("-") and value != "-"
        ):
            return None
        return (value,), 2
    if action.nargs == "*":
        if inline_value is not None:
            return (inline_value,), 1
        end = index + 1
        while end < len(argv) and not (
            isinstance(argv[end], str) and argv[end].startswith("-")
        ):
            end += 1
        return tuple(argv[index + 1 : end]), end - index
    return None


def _normalize_agent_guard_command(
    command: str,
    *,
    shell: str | None = None,
) -> _NormalizedAgentGuardCommand | bool | None:
    argv = _static_agent_guard_argv(command, shell=shell)
    if argv is None:
        return False if _looks_like_agent_guard_command(command) else None
    entrypoint_size = _agent_guard_entrypoint_size(argv)
    if entrypoint_size is None:
        return None

    leaf = _agent_guard_leaf_parser(argv[entrypoint_size:])
    if leaf is None:
        return False
    route, parser, route_size = leaf
    options = {
        option: action
        for action in parser._actions
        for option in action.option_strings
    }
    normalized: list[tuple[object, ...]] = [
        ("literal", value) for value in argv[:entrypoint_size]
    ]
    normalized.extend(("literal", value) for value in route)

    tail = argv[entrypoint_size + route_size :]
    index = 0
    while index < len(tail):
        value = tail[index]
        if value == "--":
            return False
        if not isinstance(value, str):
            return False
        action, inline_value, ambiguous = _resolve_agent_guard_option(
            value,
            options=options,
        )
        if ambiguous:
            return False
        if action is None:
            return False
        if action.dest == "help":
            return False
        option_values = _agent_guard_option_values(
            tail,
            index=index,
            action=action,
            inline_value=inline_value,
        )
        if option_values is None:
            return False
        values, consumed = option_values
        normalized.append(("option", action.dest, *values))
        index += consumed

    return _NormalizedAgentGuardCommand(arguments=tuple(normalized))


def command_prefix_matches_required(
    candidate: str,
    required: str,
    *,
    shell: str | None = None,
) -> bool:
    required_command = _normalize_agent_guard_command(required)
    candidate_command = _normalize_agent_guard_command(candidate, shell=shell)
    if isinstance(required_command, _NormalizedAgentGuardCommand) or isinstance(
        candidate_command, _NormalizedAgentGuardCommand
    ):
        if not isinstance(required_command, _NormalizedAgentGuardCommand) or not isinstance(
            candidate_command, _NormalizedAgentGuardCommand
        ):
            return False
        required_arguments = required_command.arguments
        candidate_arguments = candidate_command.arguments
        if candidate_arguments[: len(required_arguments)] != required_arguments:
            return False
        required_option_destinations = {
            argument[1]
            for argument in required_arguments
            if argument[0] == "option"
        }
        return not any(
            argument[0] == "option" and argument[1] in required_option_destinations
            for argument in candidate_arguments[len(required_arguments) :]
        )

    if (
        required_command is False
        or candidate_command is False
        or _looks_like_agent_guard_command(required)
    ):
        return False
    return candidate == required or candidate.startswith(required + " ")


def command_line_matches_required(
    command_line: str,
    required_command: str,
    *,
    shell: str | None = None,
) -> bool:
    _validate_command_lexer_characters(command_line)
    _validate_command_lexer_characters(required_command)
    required = normalize_command_text(required_command)
    if not required:
        return False

    candidate_matched = False
    preceding_same_list_or = False
    previous_operator: str | None = None
    for segment, next_operator in _iter_bounded_command_segments(command_line):
        normalized = normalize_command_text(segment)
        if previous_operator == ";" and normalized:
            # A non-empty semicolon tail makes every earlier match
            # unconditional, but a new match in this segment may still count.
            candidate_matched = False

        if (
            normalized
            and not is_documentation_segment(normalized)
            and next_operator not in {"||", "|"}
            and not has_help_option(normalized)
            and not preceding_same_list_or
            and command_prefix_matches_required(
                normalized,
                required,
                shell=shell,
            )
        ):
            candidate_matched = True

        if next_operator in {"||", "&"}:
            # These operators invalidate all earlier candidates in their
            # remaining command list. Later semicolon-delimited candidates can
            # still establish a valid match.
            candidate_matched = False

        if next_operator == "||":
            preceding_same_list_or = True
        elif next_operator in {";", "&"}:
            preceding_same_list_or = False
        previous_operator = next_operator

    return candidate_matched


def validate_workflow_policy(policy: dict[str, Any]) -> None:
    schema_version = policy.get("schema_version")
    if isinstance(schema_version, str):
        _validate_workflow_policy_string(schema_version)
    if schema_version != WORKFLOW_POLICY_SCHEMA_VERSION:
        raise ValueError(f"schema_version must be {WORKFLOW_POLICY_SCHEMA_VERSION!r}")


def scan_workflow_policy(
    *,
    root: Path,
    policy: dict[str, Any],
    _input_budget: DistinctInputBudget | None = None,
) -> tuple[list[WorkflowGuardFinding], int]:
    root = root.resolve()
    _validate_object_graph(policy)
    validate_workflow_policy(policy)
    required_files = normalize_required_files(policy.get("required_files", []))
    workflow_checks = normalize_workflow_checks(policy.get("workflow_checks", []))
    if not required_files and not workflow_checks:
        raise ValueError("workflow policy must configure at least one required_files or workflow_checks entry")

    findings: list[WorkflowGuardFinding] = []
    budget = _WorkflowScanBudget()
    workflow_cache: dict[str, _CachedWorkflow] = {}
    checked_items = 0
    for required in required_files:
        target, rel_path = resolve_repo_file(root, required.path, label=required.check_id)
        checked_items += 1
        try:
            file_fd = _open_repo_bound_file(target, root)
        except FileNotFoundError:
            _append_workflow_finding(
                findings,
                budget,
                rule_id=required.check_id,
                severity=required.severity,
                file=rel_path,
                message="required file is missing",
                reason="missing_required_file",
                requirement_id=required.check_id,
            )
            continue
        try:
            os.close(file_fd)
        except OSError:
            raise ValueError(ERROR_WORKFLOW_SCAN_TARGET) from None

    for check in workflow_checks:
        cached = workflow_cache.get(check.path)
        if cached is None:
            workflow_path, rel_path = resolve_repo_file(
                root,
                check.path,
                label=check.check_id,
            )
            remaining_input_bytes = (
                MAX_WORKFLOW_DISTINCT_INPUT_BYTES - budget.distinct_input_bytes
            )
            if remaining_input_bytes < 0:
                _raise_configuration_limit()
            try:
                raw_workflow = _read_repo_bound_bytes(
                    workflow_path,
                    root,
                    max_bytes=min(MAX_WORKFLOW_FILE_BYTES, remaining_input_bytes),
                )
            except FileNotFoundError:
                raise FileNotFoundError(
                    f"{check.check_id}: workflow file not found: {rel_path}"
                ) from None
            _consume_scan_size_budget(
                budget,
                field_name="distinct_input_bytes",
                amount=len(raw_workflow),
                limit=MAX_WORKFLOW_DISTINCT_INPUT_BYTES,
            )
            if _input_budget is not None:
                try:
                    _input_budget.charge_bytes(
                        raw_workflow,
                        identity=("workflow", rel_path),
                    )
                except BoundedRepoLimitError:
                    _raise_configuration_limit()
                except BoundedRepoReadError:
                    raise ValueError(ERROR_WORKFLOW_SCAN_TARGET) from None
            workflow = load_workflow_file(raw_workflow, workflow_id=check.check_id)
            run_lines = tuple(
                collect_run_lines(
                    workflow,
                    workflow_path=rel_path,
                    _budget=budget,
                )
            )
            cached = _CachedWorkflow(
                public_path=rel_path,
                raw=raw_workflow,
                parsed=workflow,
                run_lines=run_lines,
            )
            workflow_cache[check.path] = cached
        rel_path = cached.public_path
        run_lines = cached.run_lines

        for required in check.required_commands:
            checked_items += 1
            matched = False
            for line in run_lines:
                _consume_scan_budget(
                    budget,
                    field_name="traversal",
                    limit=MAX_WORKFLOW_TRAVERSAL,
                )
                _consume_scan_size_budget(
                    budget,
                    field_name="match_chars",
                    amount=len(line.command) + len(required.command),
                    limit=MAX_WORKFLOW_MATCH_CHARS,
                )
                if command_line_matches_required(
                    line.command,
                    required.command,
                    shell=line.shell,
                ):
                    matched = True
                    break
            if matched:
                continue
            _append_workflow_finding(
                findings,
                budget,
                rule_id=required.command_id,
                severity=check.severity,
                file=rel_path,
                message="required workflow command is missing",
                reason="missing_required_workflow_command",
                workflow_id=check.check_id,
                requirement_id=required.command_id,
            )

    return findings, checked_items
