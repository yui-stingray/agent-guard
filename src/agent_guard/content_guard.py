"""Where: src/agent_guard/content_guard.py
What: static scanner for dangerous patterns in agent-facing text content.
Why: keep skill docs and similar Markdown content from drifting into unsafe instructions.
"""

from __future__ import annotations

import os
import re
import stat
import time
from dataclasses import dataclass
from fnmatch import fnmatch
from pathlib import Path
from typing import Iterable, Sequence

import yaml

from .bounded_scan import MAX_ISOLATED_MESSAGE_BYTES, run_isolated_scan
from .bounded_git import (
    UNTRUSTED_GIT_ENVIRONMENT_VARIABLES,
    BoundedGitOutputLimitError,
    BoundedGitProcessError,
    run_bounded_git,
    sanitized_git_environment,
)
from .bounded_yaml import (
    BoundedYamlInvalidError,
    BoundedYamlLimitError,
    load_bounded_yaml,
)


# Stable, public-safe errors for untrusted policy and scan resource failures.
ERROR_CONTENT_POLICY_NOT_FOUND = "content policy file not found"
ERROR_CONTENT_POLICY_INVALID = "content policy is invalid"
ERROR_CONTENT_POLICY_LIMIT = "content policy exceeds configured limits"
ERROR_CONTENT_SCAN_LIMIT = "content scan exceeds configured limits"
ERROR_CONTENT_SCAN_TIMEOUT = "content scan exceeded execution budget"
ERROR_CONTENT_SCAN_RUNTIME = "content scan could not complete safely"
ERROR_CONTENT_SCAN_TARGET = "content scan target must stay under repo root"

# Keep policy-controlled work bounded without turning this into a generic scanner.
MAX_POLICY_FILE_BYTES = 256 * 1024
MAX_POLICY_REGEX_COUNT = 64
MAX_POLICY_REGEX_LENGTH = 4_096
MAX_POLICY_METADATA_LENGTH = 4_096
MAX_POLICY_GLOB_COUNT = 128
MAX_POLICY_GLOB_LENGTH = 1_024
MAX_CONTENT_SCAN_FILES = 10_000
MAX_CONTENT_SCAN_WORK_ITEMS = 20_000
MAX_CONTENT_FILE_BYTES = 1_048_576
MAX_CONTENT_LINES_PER_FILE = 50_000
MAX_CONTENT_LINE_CHARS = 16_384
MAX_CONTENT_FINDINGS = 10_000
MAX_CONTENT_AGGREGATE_RESULT_BYTES = MAX_ISOLATED_MESSAGE_BYTES // 2
CONTENT_FINDING_RESULT_OVERHEAD_BYTES = 512
GIT_NAME_LIST_TIMEOUT_SECONDS = 15.0
MAX_GIT_NAME_LIST_OUTPUT_BYTES = 4 * 1024 * 1024
MAX_GIT_FILTER_CONFIG_OUTPUT_BYTES = 64 * 1024
MAX_GIT_FILTER_DRIVERS = 128
MAX_GIT_FILTER_DRIVER_NAME_BYTES = 128
CONTENT_TRAVERSAL_TIMEOUT_SECONDS = 5.0
CONTENT_GLOB_WORK_UNITS_PER_ITEM = 64
_GIT_FILTER_CONFIG_SUFFIXES = (b".clean", b".process", b".required")
_SAFE_GIT_FILTER_DRIVER_BYTES = frozenset(
    b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-"
)
_GIT_NAME_LIST_ROUTING_ENVIRONMENT_VARIABLES = (
    UNTRUSTED_GIT_ENVIRONMENT_VARIABLES
)
DEFAULT_POLICY: dict[str, object] = {
    "file_globs": ["**/*.md"],
    "exclude_globs": [],
    "forbidden_patterns": [
        {
            "id": "pipe_to_shell",
            "severity": "high",
            "pattern": r"(?i)curl\s+[^\n|]+\|\s*(bash|sh)\b",
            "message": "pipe-to-shell pattern is forbidden",
        },
        {
            "id": "destructive_rm_root",
            "severity": "high",
            "pattern": r"(?i)rm\s+-rf\s+(/|~|/home|/mnt/c)",
            "message": "destructive rm pattern is forbidden",
        },
        {
            "id": "force_history_rewrite",
            "severity": "high",
            "pattern": r"(?i)git\s+(reset\s+--hard|push\s+--force\b|clean\s+-f)",
            "message": "destructive git command pattern is forbidden",
        },
        {
            "id": "encoded_exec",
            "severity": "high",
            "pattern": r"(?i)base64\s+(-d|--decode).*(\||&&).*(bash|sh)\b",
            "message": "encoded execution pattern is forbidden",
        },
        {
            "id": "powershell_iex_download",
            "severity": "high",
            "pattern": r"(?i)(invoke-webrequest|iwr).*(\||;).*iex",
            "message": "PowerShell remote execution pattern is forbidden",
        },
        {
            "id": "secret_prompt",
            "severity": "high",
            "pattern": r"(?i)(入力|貼り付け|provide|paste|enter).*(api[_ -]?key|token|password|secret)",
            "message": "plaintext secret prompt is forbidden",
        },
        {
            "id": "hardcoded_credential",
            "severity": "high",
            "pattern": r"(AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|sk-[A-Za-z0-9]{20,})",
            "message": "hardcoded credential-like token found",
        },
    ],
}


@dataclass(frozen=True)
class ContentGuardFinding:
    file: str
    line: int
    rule_id: str
    severity: str
    message: str
    snippet: str

    def to_dict(self) -> dict[str, object]:
        return {
            "file": self.file,
            "line": self.line,
            "rule_id": self.rule_id,
            "severity": self.severity,
            "message": self.message,
            "snippet": self.snippet,
        }


def _git_name_list_environment() -> dict[str, str]:
    """Return the shared configuration-isolated Git environment."""

    return sanitized_git_environment()


def _run_git_name_list(repo_root: Path, args: Sequence[str]) -> bytes:
    """Return bounded raw NUL-delimited Git path output without exposing Git errors."""
    try:
        result = run_bounded_git(
            repo_root,
            args,
            timeout_seconds=GIT_NAME_LIST_TIMEOUT_SECONDS,
            max_output_bytes=MAX_GIT_NAME_LIST_OUTPUT_BYTES,
        )
    except BoundedGitOutputLimitError:
        raise ValueError(ERROR_CONTENT_SCAN_LIMIT) from None
    except BoundedGitProcessError:
        raise RuntimeError(ERROR_CONTENT_SCAN_RUNTIME) from None
    if result.returncode != 0:
        raise RuntimeError(ERROR_CONTENT_SCAN_RUNTIME)
    return result.stdout


def _resolve_git_commit_oid(repo_root: Path, ref: str) -> str:
    raw_ref = str(ref)
    if "\0" in raw_ref or "\r" in raw_ref or "\n" in raw_ref:
        raise RuntimeError(ERROR_CONTENT_SCAN_RUNTIME)
    normalized_ref = raw_ref.strip()
    if not normalized_ref or normalized_ref.startswith("-"):
        raise RuntimeError(ERROR_CONTENT_SCAN_RUNTIME)

    output = _run_git_name_list(
        repo_root,
        [
            "rev-parse",
            "--verify",
            "--end-of-options",
            f"{normalized_ref}^{{commit}}",
        ],
    )
    if re.fullmatch(rb"(?:[0-9a-f]{40}|[0-9a-f]{64})(?:\r?\n)?", output) is None:
        raise RuntimeError(ERROR_CONTENT_SCAN_RUNTIME)
    return output.rstrip(b"\r\n").decode("ascii")


def _git_name_list_entries(output: bytes) -> list[bytes]:
    if not output:
        return []

    entries = output.split(b"\0")
    if entries[-1] != b"":
        raise ValueError(ERROR_CONTENT_SCAN_TARGET)
    entries = entries[:-1]
    if any(not entry for entry in entries):
        raise ValueError(ERROR_CONTENT_SCAN_TARGET)
    return entries


def _configured_filter_drivers(repo_root: Path) -> tuple[str, ...]:
    """Return bounded effective filter names without reading configured commands."""

    try:
        result = run_bounded_git(
            repo_root,
            [
                "config",
                "--null",
                "--name-only",
                "--get-regexp",
                r"^filter\..*\.(clean|process|required)$",
            ],
            timeout_seconds=GIT_NAME_LIST_TIMEOUT_SECONDS,
            max_output_bytes=MAX_GIT_FILTER_CONFIG_OUTPUT_BYTES,
        )
    except BoundedGitOutputLimitError:
        raise ValueError(ERROR_CONTENT_SCAN_LIMIT) from None
    except BoundedGitProcessError:
        raise RuntimeError(ERROR_CONTENT_SCAN_RUNTIME) from None

    if result.returncode == 1 and not result.stdout:
        return ()
    if result.returncode != 0 or not result.stdout.endswith(b"\0"):
        raise RuntimeError(ERROR_CONTENT_SCAN_RUNTIME)

    drivers: set[bytes] = set()
    for raw_key in result.stdout[:-1].split(b"\0"):
        folded = raw_key.lower()
        if not folded.startswith(b"filter."):
            raise RuntimeError(ERROR_CONTENT_SCAN_RUNTIME)
        suffix = next(
            (
                candidate
                for candidate in _GIT_FILTER_CONFIG_SUFFIXES
                if folded.endswith(candidate)
            ),
            None,
        )
        if suffix is None:
            raise RuntimeError(ERROR_CONTENT_SCAN_RUNTIME)
        driver = raw_key[len(b"filter.") : -len(suffix)]
        if (
            not driver
            or len(driver) > MAX_GIT_FILTER_DRIVER_NAME_BYTES
            or any(byte not in _SAFE_GIT_FILTER_DRIVER_BYTES for byte in driver)
        ):
            raise RuntimeError(ERROR_CONTENT_SCAN_RUNTIME)
        drivers.add(driver)
        if len(drivers) > MAX_GIT_FILTER_DRIVERS:
            raise ValueError(ERROR_CONTENT_SCAN_LIMIT)

    return tuple(driver.decode("ascii") for driver in sorted(drivers))


def _neutralized_filter_config_args(repo_root: Path) -> list[str]:
    args: list[str] = []
    for driver in _configured_filter_drivers(repo_root):
        args.extend(
            [
                "-c",
                f"filter.{driver}.clean=",
                "-c",
                f"filter.{driver}.process=",
                "-c",
                f"filter.{driver}.required=false",
            ]
        )
    return args


def _git_entry_lexical_target(
    raw_entry: bytes,
    repo_root: Path,
    target_root: Path,
) -> Path:
    parts = raw_entry.split(b"/")
    if (
        not raw_entry
        or raw_entry.startswith(b"/")
        or raw_entry.endswith(b"/")
        or any(not part or part in (b".", b"..") for part in parts)
    ):
        raise ValueError(ERROR_CONTENT_SCAN_TARGET)
    if os.name == "nt" and (b"\\" in raw_entry or any(b":" in part for part in parts)):
        raise ValueError(ERROR_CONTENT_SCAN_TARGET)

    try:
        relative_path = Path(os.fsdecode(raw_entry))
    except (OSError, UnicodeError, ValueError):
        raise ValueError(ERROR_CONTENT_SCAN_TARGET) from None
    if (
        not relative_path.parts
        or relative_path.is_absolute()
        or relative_path.anchor
        or any(part in ("", ".", "..") for part in relative_path.parts)
    ):
        raise ValueError(ERROR_CONTENT_SCAN_TARGET)

    path = repo_root / relative_path
    if not (
        _path_is_lexically_under(path, repo_root)
        and _path_is_lexically_under(path, target_root)
    ):
        raise ValueError(ERROR_CONTENT_SCAN_TARGET)
    try:
        path.relative_to(repo_root)
        path.relative_to(target_root)
    except ValueError:
        raise ValueError(ERROR_CONTENT_SCAN_TARGET) from None
    return path


def _ensure_git_entry_resolved_containment(path: Path, target_root: Path) -> None:
    try:
        path.resolve(strict=False).relative_to(target_root)
    except (OSError, RuntimeError, ValueError):
        raise ValueError(ERROR_CONTENT_SCAN_TARGET) from None


def merge_policy(base: dict[str, object], override: dict[str, object]) -> dict[str, object]:
    merged = dict(base)
    for key in ("forbidden_patterns", "exclude_globs", "file_globs"):
        if key not in override:
            continue
        value = override[key]
        if not isinstance(value, list):
            raise ValueError(ERROR_CONTENT_POLICY_INVALID)
        merged[key] = value
    return merged


def _read_policy_text(path: Path) -> str:
    try:
        with path.open("rb") as handle:
            raw = handle.read(MAX_POLICY_FILE_BYTES + 1)
    except FileNotFoundError:
        raise FileNotFoundError(f"{ERROR_CONTENT_POLICY_NOT_FOUND}: {path}") from None
    except OSError:
        raise ValueError(ERROR_CONTENT_POLICY_INVALID) from None

    if len(raw) > MAX_POLICY_FILE_BYTES:
        raise ValueError(ERROR_CONTENT_POLICY_LIMIT)
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError(ERROR_CONTENT_POLICY_INVALID) from None


def load_content_policy(path: Path) -> dict[str, object]:
    try:
        loaded = load_bounded_yaml(
            _read_policy_text(path),
            construct=yaml.safe_load,
        ) or {}
        if not isinstance(loaded, dict):
            raise BoundedYamlInvalidError
        merged = merge_policy(DEFAULT_POLICY, loaded)
    except BoundedYamlLimitError:
        raise ValueError(ERROR_CONTENT_POLICY_LIMIT) from None
    except BoundedYamlInvalidError:
        raise ValueError(ERROR_CONTENT_POLICY_INVALID) from None
    except (MemoryError, OverflowError, RecursionError):
        raise ValueError(ERROR_CONTENT_POLICY_LIMIT) from None
    return merged


def normalize_patterns(raw: object, *, limit: int = MAX_POLICY_GLOB_COUNT) -> list[str]:
    if not isinstance(raw, list):
        raise ValueError(ERROR_CONTENT_POLICY_INVALID)
    if len(raw) > limit:
        raise ValueError(ERROR_CONTENT_POLICY_LIMIT)

    patterns: list[str] = []
    for item in raw:
        if not isinstance(item, str):
            raise ValueError(ERROR_CONTENT_POLICY_INVALID)
        text = item.strip()
        if not text:
            continue
        if len(text) > MAX_POLICY_GLOB_LENGTH:
            raise ValueError(ERROR_CONTENT_POLICY_LIMIT)
        patterns.append(text)
    return patterns


def build_rules(policy: dict[str, object]) -> list[dict[str, object]]:
    raw_rules = policy.get("forbidden_patterns", [])
    if not isinstance(raw_rules, list):
        raise ValueError(ERROR_CONTENT_POLICY_INVALID)
    if len(raw_rules) > MAX_POLICY_REGEX_COUNT:
        raise ValueError(ERROR_CONTENT_POLICY_LIMIT)

    rules: list[dict[str, object]] = []
    for item in raw_rules:
        if not isinstance(item, dict):
            raise ValueError(ERROR_CONTENT_POLICY_INVALID)
        raw_rule_id = item.get("id", "")
        raw_pattern = item.get("pattern", "")
        raw_severity = item.get("severity", "high")
        raw_message = item.get("message", "policy violation")
        if not all(
            isinstance(value, str)
            for value in (raw_rule_id, raw_pattern, raw_severity, raw_message)
        ):
            raise ValueError(ERROR_CONTENT_POLICY_INVALID)
        rule_id = raw_rule_id.strip()
        pattern_text = raw_pattern.strip()
        if not rule_id or not pattern_text:
            raise ValueError(ERROR_CONTENT_POLICY_INVALID)
        if any(
            len(value) > MAX_POLICY_METADATA_LENGTH
            for value in (rule_id, raw_severity, raw_message)
        ):
            raise ValueError(ERROR_CONTENT_POLICY_LIMIT)
        if len(pattern_text) > MAX_POLICY_REGEX_LENGTH:
            raise ValueError(ERROR_CONTENT_POLICY_LIMIT)
        try:
            regex = re.compile(pattern_text)
        except (OverflowError, RecursionError, re.error):
            raise ValueError(ERROR_CONTENT_POLICY_INVALID) from None
        rules.append(
            {
                "id": rule_id,
                "severity": raw_severity.strip() or "high",
                "message": raw_message.strip() or "policy violation",
                "regex": regex,
                "include_globs": normalize_patterns(item.get("include_globs", [])),
                "exclude_globs": normalize_patterns(item.get("exclude_globs", [])),
            }
        )
    return rules


def glob_matches(path: Path, pattern: str) -> bool:
    normalized_pattern = pattern.replace("\\", "/")
    normalized_path = path.as_posix()
    if normalized_pattern.endswith("/**"):
        prefix = normalized_pattern[:-3].rstrip("/")
        if prefix and (normalized_path == prefix or normalized_path.startswith(f"{prefix}/")):
            return True
    if path.match(normalized_pattern):
        return True
    if normalized_pattern.startswith("**/"):
        return path.match(normalized_pattern[3:])
    return False


class _ContentTraversalBudget:
    def __init__(self) -> None:
        self.work_items = 0
        self.glob_work_remainder = 0
        self.deadline = time.monotonic() + max(
            CONTENT_TRAVERSAL_TIMEOUT_SECONDS,
            0.0,
        )

    def charge(self, work_items: int = 1) -> None:
        if time.monotonic() >= self.deadline:
            raise RuntimeError(ERROR_CONTENT_SCAN_TIMEOUT)
        if (
            work_items < 0
            or work_items > MAX_CONTENT_SCAN_WORK_ITEMS - self.work_items
        ):
            raise ValueError(ERROR_CONTENT_SCAN_LIMIT)
        self.work_items += work_items

    def charge_glob(self, work_units: int = 1) -> None:
        if time.monotonic() >= self.deadline:
            raise RuntimeError(ERROR_CONTENT_SCAN_TIMEOUT)
        if work_units < 0 or CONTENT_GLOB_WORK_UNITS_PER_ITEM <= 0:
            raise ValueError(ERROR_CONTENT_SCAN_LIMIT)
        charged_items, self.glob_work_remainder = divmod(
            self.glob_work_remainder + work_units,
            CONTENT_GLOB_WORK_UNITS_PER_ITEM,
        )
        if charged_items:
            self.charge(charged_items)


def _budgeted_glob_matches(
    path: Path,
    pattern: str,
    budget: _ContentTraversalBudget,
) -> bool:
    pattern_parts = tuple(
        part
        for part in pattern.replace("\\", "/").split("/")
        if part not in ("", ".")
    )
    budget.charge_glob(
        max(len(path.parts), 1) * max(len(pattern_parts), 1)
    )
    return glob_matches(path, pattern)


def iter_files_under(
    root: Path,
    file_globs: Iterable[str],
    exclude_globs: Iterable[str],
    *,
    _budget: _ContentTraversalBudget | None = None,
) -> list[Path]:
    patterns = [pattern for pattern in file_globs if pattern]
    if not patterns:
        return []
    file_patterns = [
        pattern
        for pattern in patterns
        if pattern.replace("\\", "/").rstrip("/").split("/")[-1] != "**"
        and not pattern.replace("\\", "/").endswith("/")
    ]
    excluded = [pattern for pattern in exclude_globs if pattern]
    budget = _budget or _ContentTraversalBudget()
    files: set[Path] = set()
    pending = [root]

    while pending:
        current = pending.pop()
        budget.charge()
        try:
            with os.scandir(current) as entries:
                for entry in entries:
                    budget.charge()
                    path = current / entry.name
                    rel = path.relative_to(root)
                    if entry.is_dir(follow_symlinks=False):
                        if excluded and any(
                            _directory_matches_exclude(
                                rel,
                                pattern,
                                _budget=budget,
                            )
                            for pattern in excluded
                        ):
                            continue
                        if any(
                            _file_glob_reaches_directory(
                                rel,
                                pattern,
                                _budget=budget,
                            )
                            for pattern in patterns
                        ):
                            pending.append(path)
                        continue
                    if not entry.is_file(follow_symlinks=True):
                        continue
                    if excluded and any(
                        _budgeted_glob_matches(rel, pattern, budget)
                        for pattern in excluded
                    ):
                        continue
                    if any(
                        _root_glob_matches(rel, pattern, _budget=budget)
                        for pattern in file_patterns
                    ):
                        files.add(path)
                        if len(files) > MAX_CONTENT_SCAN_FILES:
                            raise ValueError(ERROR_CONTENT_SCAN_LIMIT)
        except OSError:
            raise ValueError(ERROR_CONTENT_SCAN_LIMIT) from None
    return sorted(files)


def normalize_targets(paths: Iterable[str]) -> list[Path]:
    targets: list[Path] = []
    for index, raw in enumerate(paths, start=1):
        if index > MAX_CONTENT_SCAN_FILES:
            raise ValueError(ERROR_CONTENT_SCAN_LIMIT)
        text = str(raw).strip()
        if not text:
            continue
        targets.append(Path(text).resolve())
    return targets


def collect_preregister_targets(
    targets: Iterable[str],
    file_globs: Iterable[str],
    exclude_globs: Iterable[str],
) -> list[Path]:
    collected: list[Path] = []
    normalized = normalize_targets(targets)
    budget = _ContentTraversalBudget()
    for target in normalized:
        budget.charge()
        if target.is_file():
            collected.append(target)
            if len(collected) > MAX_CONTENT_SCAN_FILES:
                raise ValueError(ERROR_CONTENT_SCAN_LIMIT)
            continue
        if target.is_dir():
            collected.extend(
                iter_files_under(
                    target,
                    file_globs,
                    exclude_globs,
                    _budget=budget,
                )
            )
            if len(collected) > MAX_CONTENT_SCAN_FILES:
                raise ValueError(ERROR_CONTENT_SCAN_LIMIT)
    return sorted(set(collected))


def _resolve_repo_scan_root(repo_root: Path, scan_dir: Path) -> tuple[Path, Path]:
    resolved_repo_root = repo_root.resolve()
    target_root = scan_dir if scan_dir.is_absolute() else (resolved_repo_root / scan_dir)
    target_root = target_root.resolve()
    try:
        target_root.relative_to(resolved_repo_root)
    except ValueError:
        raise ValueError("content scan dir must stay under repo root") from None
    return resolved_repo_root, target_root


def _directory_matches_exclude(
    path: Path,
    pattern: str,
    *,
    _budget: _ContentTraversalBudget | None = None,
) -> bool:
    if (
        _budgeted_glob_matches(path, pattern, _budget)
        if _budget is not None
        else glob_matches(path, pattern)
    ):
        return True
    if pattern.replace("\\", "/").endswith("/**"):
        descendant = path / "__agent_guard_descendant__"
        return (
            _budgeted_glob_matches(descendant, pattern, _budget)
            if _budget is not None
            else glob_matches(descendant, pattern)
        )
    return False


def _glob_pattern_parts(
    pattern: str,
    *,
    _budget: _ContentTraversalBudget | None = None,
) -> tuple[str, ...]:
    normalized = pattern.replace("\\", "/")
    if normalized.startswith("/"):
        if _budget is not None:
            _budget.charge_glob()
        return ()
    raw_parts = normalized.split("/")
    if _budget is not None:
        _budget.charge_glob(max(len(raw_parts), 1))
    pattern_parts = tuple(part for part in raw_parts if part not in ("", "."))
    if not pattern_parts:
        return ()
    return pattern_parts


def _root_glob_matches(
    path: Path,
    pattern: str,
    *,
    _budget: _ContentTraversalBudget | None = None,
) -> bool:
    pattern_parts = _glob_pattern_parts(pattern, _budget=_budget)
    if not pattern_parts:
        return False

    path_parts = path.parts
    memo: dict[tuple[int, int], bool] = {}

    def matches(path_index: int, pattern_index: int) -> bool:
        key = (path_index, pattern_index)
        if key in memo:
            return memo[key]
        if _budget is not None:
            _budget.charge_glob()
        if pattern_index == len(pattern_parts):
            result = path_index == len(path_parts)
        elif pattern_parts[pattern_index] == "**":
            result = matches(path_index, pattern_index + 1) or (
                path_index < len(path_parts) and matches(path_index + 1, pattern_index)
            )
        else:
            result = path_index < len(path_parts) and fnmatch(
                path_parts[path_index],
                pattern_parts[pattern_index],
            ) and matches(path_index + 1, pattern_index + 1)
        memo[key] = result
        return result

    try:
        return matches(0, 0)
    except RecursionError:
        raise ValueError(ERROR_CONTENT_SCAN_LIMIT) from None


def _file_glob_reaches_directory(
    path: Path,
    pattern: str,
    *,
    _budget: _ContentTraversalBudget | None = None,
) -> bool:
    pattern_parts = _glob_pattern_parts(pattern, _budget=_budget)
    if not pattern_parts:
        return False

    def closure(states: set[int]) -> set[int]:
        expanded = set(states)
        pending_states = list(states)
        while pending_states:
            state = pending_states.pop()
            if _budget is not None:
                _budget.charge_glob()
            if state < len(pattern_parts) and pattern_parts[state] == "**" and state + 1 not in expanded:
                expanded.add(state + 1)
                pending_states.append(state + 1)
        return expanded

    states = closure({0})
    for part in path.parts:
        next_states: set[int] = set()
        for state in states:
            if _budget is not None:
                _budget.charge_glob()
            if state == len(pattern_parts):
                continue
            pattern_part = pattern_parts[state]
            if pattern_part == "**":
                next_states.add(state)
            elif fnmatch(part, pattern_part):
                next_states.add(state + 1)
        states = closure(next_states)
        if not states:
            return False
    for state in states:
        if _budget is not None:
            _budget.charge_glob()
        if state < len(pattern_parts):
            return True
    return False


def _collect_registered_files(
    repo_root: Path,
    target_root: Path,
    file_globs: Iterable[str],
    exclude_globs: Iterable[str],
) -> list[Path]:
    patterns = [pattern for pattern in file_globs if pattern]
    excluded = [pattern for pattern in exclude_globs if pattern]
    files: list[Path] = []
    pending = [target_root]
    budget = _ContentTraversalBudget()

    while pending:
        current = pending.pop()
        budget.charge()
        try:
            with os.scandir(current) as entries:
                for entry in entries:
                    budget.charge()
                    path = current / entry.name
                    rel = path.relative_to(target_root)
                    if entry.is_symlink():
                        directory_excluded = any(
                            _directory_matches_exclude(
                                rel,
                                pattern,
                                _budget=budget,
                            )
                            for pattern in excluded
                        )
                        if directory_excluded:
                            continue
                        directory_reachable = any(
                            _file_glob_reaches_directory(
                                rel,
                                pattern,
                                _budget=budget,
                            )
                            for pattern in patterns
                        )
                        file_selected = bool(patterns) and any(
                            _root_glob_matches(
                                rel,
                                pattern,
                                _budget=budget,
                            )
                            for pattern in patterns
                        )
                        if not directory_reachable and not file_selected:
                            continue
                        is_directory = entry.is_dir(follow_symlinks=True)
                        if is_directory and not directory_reachable:
                            continue
                        if not is_directory and not file_selected:
                            continue
                        try:
                            resolved = path.resolve()
                            resolved.relative_to(repo_root)
                        except (OSError, RuntimeError, ValueError):
                            raise ValueError(ERROR_CONTENT_SCAN_TARGET) from None
                        if is_directory:
                            continue
                        if entry.is_file(follow_symlinks=True):
                            files.append(path)
                    elif entry.is_dir(follow_symlinks=False):
                        directory_excluded = any(
                            _directory_matches_exclude(
                                rel,
                                pattern,
                                _budget=budget,
                            )
                            for pattern in excluded
                        )
                        directory_reachable = not directory_excluded and any(
                            _file_glob_reaches_directory(
                                rel,
                                pattern,
                                _budget=budget,
                            )
                            for pattern in patterns
                        )
                        if directory_reachable:
                            pending.append(path)
                    elif entry.is_file(follow_symlinks=False):
                        if excluded and any(
                            _budgeted_glob_matches(rel, pattern, budget)
                            for pattern in excluded
                        ):
                            continue
                        if patterns and any(
                            _root_glob_matches(
                                rel,
                                pattern,
                                _budget=budget,
                            )
                            for pattern in patterns
                        ):
                            files.append(path)

                    if len(files) > MAX_CONTENT_SCAN_FILES:
                        raise ValueError(ERROR_CONTENT_SCAN_LIMIT)
        except OSError:
            raise ValueError(ERROR_CONTENT_SCAN_LIMIT) from None

    return sorted(set(files))


def collect_registered_targets(
    repo_root: Path,
    scan_dir: Path,
    file_globs: Iterable[str],
    exclude_globs: Iterable[str],
) -> list[Path]:
    repo_root, target_root = _resolve_repo_scan_root(repo_root, scan_dir)
    if not target_root.exists():
        raise RuntimeError("content scan dir not found")
    excludes = list(exclude_globs)
    paths = _collect_registered_files(repo_root, target_root, file_globs, excludes)
    for path in paths:
        try:
            path.resolve().relative_to(repo_root)
        except (OSError, RuntimeError, ValueError):
            raise ValueError(ERROR_CONTENT_SCAN_TARGET) from None
    return paths


_GIT_INDEX_METADATA_PATTERN = re.compile(
    rb"([A-Za-z?]) ([0-7]{6}) ([0-9a-f]{40}|[0-9a-f]{64}) ([0-3])"
)


def _top_scan_pathspec(rel_scan: str) -> str:
    """Return a root-wide pathspec or a literal top-relative subdirectory."""

    if not rel_scan or "\0" in rel_scan:
        raise RuntimeError(ERROR_CONTENT_SCAN_RUNTIME)
    if rel_scan == ".":
        return ":(top)"
    return f":(top,literal){rel_scan}"


def _ensure_policy_selected_index_entries_are_safe(
    repo_root: Path,
    target_root: Path,
    pathspec: str,
    patterns: Sequence[str],
    excludes: Sequence[str],
) -> None:
    output = _run_git_name_list(
        repo_root,
        [
            "ls-files",
            "--stage",
            "-v",
            "-f",
            "-z",
            "--",
            pathspec,
        ],
    )
    if output and not output.endswith(b"\0"):
        raise RuntimeError(ERROR_CONTENT_SCAN_RUNTIME)

    budget = _ContentTraversalBudget()
    selected_stage_zero: set[Path] = set()
    for record in output[:-1].split(b"\0") if output else ():
        budget.charge()
        if b"\t" not in record:
            raise RuntimeError(ERROR_CONTENT_SCAN_RUNTIME)
        raw_metadata, raw_path = record.split(b"\t", 1)
        match = _GIT_INDEX_METADATA_PATTERN.fullmatch(raw_metadata)
        if match is None:
            raise RuntimeError(ERROR_CONTENT_SCAN_RUNTIME)
        path = _git_entry_lexical_target(raw_path, repo_root, target_root)
        rel = path.relative_to(target_root)
        if excludes and any(
            _budgeted_glob_matches(rel, pattern, budget)
            for pattern in excludes
        ):
            continue
        if patterns and not any(
            _budgeted_glob_matches(rel, pattern, budget)
            for pattern in patterns
        ):
            continue

        _ensure_git_entry_resolved_containment(path, target_root)
        prefix, _mode, _object_id, stage = match.groups()
        if stage != b"0" or prefix != b"H" or path in selected_stage_zero:
            raise RuntimeError(ERROR_CONTENT_SCAN_RUNTIME)
        selected_stage_zero.add(path)
        if len(selected_stage_zero) > MAX_CONTENT_SCAN_FILES:
            raise ValueError(ERROR_CONTENT_SCAN_LIMIT)


def collect_new_targets(
    repo_root: Path,
    scan_dir: Path,
    file_globs: Iterable[str],
    exclude_globs: Iterable[str],
    since_ref: str,
    include_untracked: bool,
) -> list[Path]:
    repo_root, target_root = _resolve_repo_scan_root(repo_root, scan_dir)
    rel_scan = target_root.relative_to(repo_root).as_posix()
    pathspec = _top_scan_pathspec(rel_scan)

    listed: set[Path] = set()
    changed: set[Path] = set()
    staged: set[Path] = set()
    selected_staged: set[Path] = set()
    worktree_mismatches: set[Path] = set()
    filter_config_args: list[str] | None = None
    patterns = list(file_globs)
    excludes = list(exclude_globs)

    def selected_by_policy(path: Path) -> bool:
        try:
            rel = path.relative_to(target_root)
        except ValueError:
            return False
        if excludes and any(glob_matches(rel, pattern) for pattern in excludes):
            return False
        return not patterns or any(glob_matches(rel, pattern) for pattern in patterns)

    def add_listed_path(path: Path, *, is_staged: bool = False) -> None:
        listed.add(path)
        if len(listed) > MAX_CONTENT_SCAN_FILES:
            raise ValueError(ERROR_CONTENT_SCAN_LIMIT)
        if is_staged:
            staged.add(path)
        try:
            if path.is_file():
                changed.add(path)
        except OSError:
            raise ValueError(ERROR_CONTENT_SCAN_TARGET) from None

    def git_targets(args: Sequence[str]) -> set[Path]:
        targets: set[Path] = set()
        output = _run_git_name_list(repo_root, args)
        entry_count = 0
        for raw_entry in _git_name_list_entries(output):
            entry_count += 1
            if entry_count > MAX_CONTENT_SCAN_FILES:
                raise ValueError(ERROR_CONTENT_SCAN_LIMIT)
            path = _git_entry_lexical_target(raw_entry, repo_root, target_root)
            if not selected_by_policy(path):
                continue
            _ensure_git_entry_resolved_containment(path, target_root)
            targets.add(path)
        return targets

    def add_git_targets(args: Sequence[str], *, is_staged: bool = False) -> None:
        for path in git_targets(args):
            add_listed_path(path, is_staged=is_staged)

    def git_diff_targets(args: Sequence[str]) -> set[Path]:
        nonlocal filter_config_args
        if filter_config_args is None:
            filter_config_args = _neutralized_filter_config_args(repo_root)
        return git_targets([*filter_config_args, *args])

    def add_git_diff_targets(
        args: Sequence[str],
        *,
        is_staged: bool = False,
    ) -> None:
        for path in git_diff_targets(args):
            add_listed_path(path, is_staged=is_staged)

    resolved_since_oid: str | None = None
    resolved_head_oid: str | None = None
    if since_ref:
        resolved_since_oid = _resolve_git_commit_oid(repo_root, since_ref)
        resolved_head_oid = _resolve_git_commit_oid(repo_root, "HEAD")

    _ensure_policy_selected_index_entries_are_safe(
        repo_root,
        target_root,
        pathspec,
        patterns,
        excludes,
    )

    if resolved_since_oid is not None and resolved_head_oid is not None:
        add_git_diff_targets(
            [
                "diff",
                "--name-only",
                "-z",
                "--no-ext-diff",
                "--no-textconv",
                "--no-renames",
                "--diff-filter=AM",
                f"{resolved_since_oid}...{resolved_head_oid}",
                "--",
                pathspec,
            ]
        )
    else:
        for args, is_staged in (
            (
                [
                    "diff",
                    "--name-only",
                    "-z",
                    "--no-ext-diff",
                    "--no-textconv",
                    "--no-renames",
                    "--diff-filter=AM",
                    "--",
                    pathspec,
                ],
                False,
            ),
            (
                [
                    "diff",
                    "--cached",
                    "--name-only",
                    "-z",
                    "--no-ext-diff",
                    "--no-textconv",
                    "--no-renames",
                    "--diff-filter=AM",
                    "--",
                    pathspec,
                ],
                True,
            ),
        ):
            add_git_diff_targets(args, is_staged=is_staged)

        if include_untracked:
            add_git_targets(
                [
                    "ls-files",
                    "--others",
                    "--exclude-standard",
                    "-z",
                    "--",
                    pathspec,
                ]
            )

        if staged:
            selected_staged = {path for path in staged if selected_by_policy(path)}
            worktree_mismatches = git_diff_targets(
                [
                    "diff",
                    "--name-only",
                    "-z",
                    "--no-ext-diff",
                    "--no-textconv",
                    "--no-renames",
                    "--",
                    pathspec,
                ]
            )

    allowed = [path for path in sorted(changed) if selected_by_policy(path)]
    if not since_ref:
        if selected_staged.intersection(worktree_mismatches):
            raise RuntimeError(ERROR_CONTENT_SCAN_RUNTIME)
    return allowed


def display_path(path: Path, repo_root: Path) -> str:
    try:
        return path.relative_to(repo_root).as_posix()
    except ValueError:
        return str(path)


def rule_applies_to_path(rule: dict[str, object], path: Path, repo_root: Path) -> bool:
    rel_path = Path(display_path(path, repo_root))
    include_globs = rule.get("include_globs", [])
    exclude_globs = rule.get("exclude_globs", [])

    if isinstance(include_globs, list) and include_globs:
        if not any(glob_matches(rel_path, str(pattern)) for pattern in include_globs):
            return False

    if isinstance(exclude_globs, list) and exclude_globs:
        if any(glob_matches(rel_path, str(pattern)) for pattern in exclude_globs):
            return False

    return True


def _allowed_rule_ids(line: str) -> set[str]:
    match = re.search(r"agent-guard:\s*allow\s+([A-Za-z0-9_., -]+)", line)
    if not match:
        return set()

    return {
        item.strip()
        for item in re.split(r"[,\s]+", match.group(1))
        if item.strip()
    }


def line_allows_rule(line: str, rule_id: str) -> bool:
    allowed = _allowed_rule_ids(line)
    return "all" in allowed or rule_id in allowed


def _path_is_lexically_under(path: Path, root: Path) -> bool:
    try:
        Path(os.path.abspath(path)).relative_to(Path(os.path.abspath(root)))
    except ValueError:
        return False
    return True


def _open_repo_file_posix(repo_root: Path, relative_path: Path) -> int:
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    directory = getattr(os, "O_DIRECTORY", 0)
    if not nofollow or not directory or os.open not in os.supports_dir_fd:
        raise ValueError(ERROR_CONTENT_SCAN_TARGET)

    directory_flags = os.O_RDONLY | nofollow | directory | getattr(os, "O_CLOEXEC", 0)
    file_flags = os.O_RDONLY | nofollow | getattr(os, "O_CLOEXEC", 0)
    directory_fd: int | None = None
    file_fd: int | None = None
    try:
        directory_fd = os.open(repo_root, directory_flags)
        for component in relative_path.parts[:-1]:
            next_fd = os.open(
                component,
                directory_flags,
                dir_fd=directory_fd,
            )
            os.close(directory_fd)
            directory_fd = next_fd
        file_fd = os.open(
            relative_path.parts[-1],
            file_flags,
            dir_fd=directory_fd,
        )
        if not stat.S_ISREG(os.fstat(file_fd).st_mode):
            raise OSError
        return file_fd
    except (OSError, TypeError, ValueError):
        if file_fd is not None:
            os.close(file_fd)
        raise ValueError(ERROR_CONTENT_SCAN_TARGET) from None
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
        raise ValueError(ERROR_CONTENT_SCAN_TARGET) from None


def _open_repo_bound_file(path: Path, repo_root: Path) -> int | None:
    """Open an in-repo target safely, preserving stable internal symlink aliases."""
    if not _path_is_lexically_under(path, repo_root):
        return None

    try:
        resolved_root = repo_root.resolve(strict=True)
        resolved_path = path.resolve(strict=True)
        relative_path = resolved_path.relative_to(resolved_root)
    except (OSError, RuntimeError, ValueError):
        raise ValueError(ERROR_CONTENT_SCAN_TARGET) from None
    if not relative_path.parts:
        raise ValueError(ERROR_CONTENT_SCAN_TARGET)

    if os.name == "nt":
        return _open_repo_file_windows(resolved_root, resolved_path)
    return _open_repo_file_posix(resolved_root, relative_path)


def _read_scan_text(path: Path, repo_root: Path) -> str:
    try:
        file_fd = _open_repo_bound_file(path, repo_root)
        if file_fd is None:
            with path.open("rb") as handle:
                raw = handle.read(MAX_CONTENT_FILE_BYTES + 1)
        else:
            with os.fdopen(file_fd, "rb") as handle:
                raw = handle.read(MAX_CONTENT_FILE_BYTES + 1)
    except ValueError:
        raise
    except OSError:
        raise ValueError(ERROR_CONTENT_SCAN_LIMIT) from None
    if len(raw) > MAX_CONTENT_FILE_BYTES:
        raise ValueError(ERROR_CONTENT_SCAN_LIMIT)
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError(ERROR_CONTENT_SCAN_LIMIT) from None


def _content_finding_result_size_bytes(*values: str) -> int:
    return CONTENT_FINDING_RESULT_OVERHEAD_BYTES + sum(
        len(value.encode("utf-8", errors="surrogatepass")) for value in values
    )


def _scan_file_unbounded(
    path: Path,
    rules: list[dict[str, object]],
    repo_root: Path,
    *,
    remaining_findings: int,
    remaining_result_bytes: int,
) -> tuple[list[ContentGuardFinding], int]:
    findings: list[ContentGuardFinding] = []
    result_bytes = 0
    text = _read_scan_text(path, repo_root)
    public_path = display_path(path, repo_root)
    applicable_rules = [
        rule
        for rule in rules
        if rule_applies_to_path(rule, path, repo_root)
    ]
    for idx, line in enumerate(text.splitlines(), start=1):
        if idx > MAX_CONTENT_LINES_PER_FILE or len(line) > MAX_CONTENT_LINE_CHARS:
            raise ValueError(ERROR_CONTENT_SCAN_LIMIT)
        allowed_rules = _allowed_rule_ids(line)
        for rule in applicable_rules:
            rule_id = str(rule["id"])
            if "all" in allowed_rules or rule_id in allowed_rules:
                continue

            regex = rule["regex"]
            assert isinstance(regex, re.Pattern)
            if regex.search(line):
                if len(findings) >= remaining_findings:
                    raise ValueError(ERROR_CONTENT_SCAN_LIMIT)
                severity = str(rule["severity"])
                message = str(rule["message"])
                snippet = line.strip()[:200]
                finding_result_bytes = _content_finding_result_size_bytes(
                    public_path,
                    rule_id,
                    severity,
                    message,
                    snippet,
                )
                if finding_result_bytes > remaining_result_bytes - result_bytes:
                    raise ValueError(ERROR_CONTENT_SCAN_LIMIT)
                findings.append(
                    ContentGuardFinding(
                        file=public_path,
                        line=idx,
                        rule_id=rule_id,
                        severity=severity,
                        message=message,
                        snippet=snippet,
                    )
                )
                result_bytes += finding_result_bytes
    return findings, result_bytes


def _scan_paths_unbounded(
    paths: list[Path],
    rules: list[dict[str, object]],
    repo_root: Path,
) -> list[ContentGuardFinding]:
    findings: list[ContentGuardFinding] = []
    aggregate_result_bytes = 0
    for path in paths:
        file_findings, file_result_bytes = _scan_file_unbounded(
            path,
            rules,
            repo_root,
            remaining_findings=MAX_CONTENT_FINDINGS - len(findings),
            remaining_result_bytes=(
                MAX_CONTENT_AGGREGATE_RESULT_BYTES - aggregate_result_bytes
            ),
        )
        findings.extend(file_findings)
        aggregate_result_bytes += file_result_bytes
    return findings


def scan_file(path: Path, rules: list[dict[str, object]], repo_root: Path) -> list[ContentGuardFinding]:
    return scan_paths([path], rules, repo_root)


def scan_paths(paths: Iterable[Path], rules: list[dict[str, object]], repo_root: Path) -> list[ContentGuardFinding]:
    if len(rules) > MAX_POLICY_REGEX_COUNT:
        raise ValueError(ERROR_CONTENT_POLICY_LIMIT)

    scan_paths_list: list[Path] = []
    for path in paths:
        if len(scan_paths_list) >= MAX_CONTENT_SCAN_FILES:
            raise ValueError(ERROR_CONTENT_SCAN_LIMIT)
        scan_paths_list.append(path)

    return run_isolated_scan(
        _scan_paths_unbounded,
        scan_paths_list,
        rules,
        repo_root,
        timeout_error=ERROR_CONTENT_SCAN_TIMEOUT,
        runtime_error=ERROR_CONTENT_SCAN_RUNTIME,
        result_limit_error=ERROR_CONTENT_SCAN_LIMIT,
        safe_errors=(ERROR_CONTENT_SCAN_LIMIT, ERROR_CONTENT_SCAN_TARGET),
    )
