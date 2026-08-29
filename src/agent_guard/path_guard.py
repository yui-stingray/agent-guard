"""Where: src/agent_guard/path_guard.py
What: static scanner for repository path names that must not enter a repo.
Why: catch private artifacts and env-file leaks even when file contents are unread.
"""

from __future__ import annotations

import os
import re
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .bounded_scan import MAX_ISOLATED_MESSAGE_BYTES, run_isolated_scan
from .bounded_yaml import (
    BoundedYamlInvalidError,
    BoundedYamlLimitError,
    load_bounded_yaml,
)


# Stable, public-safe errors for untrusted policy and scan resource failures.
ERROR_PATH_POLICY_NOT_FOUND = "path policy file not found"
ERROR_PATH_POLICY_INVALID = "path policy is invalid"
ERROR_PATH_POLICY_LIMIT = "path policy exceeds configured limits"
ERROR_PATH_ALLOWED_REGEX_INVALID = "invalid allowed_path_patterns regex: <regex>"
ERROR_PATH_FORBIDDEN_REGEX_INVALID = "invalid forbidden_path_patterns regex: <regex>"
ERROR_PATH_SCAN_TARGET = "path scan target must stay under repo root"
ERROR_PATH_SCAN_LIMIT = "path scan exceeds configured limits"
ERROR_PATH_SCAN_TIMEOUT = "path scan exceeded execution budget"
ERROR_PATH_SCAN_RUNTIME = "path scan could not complete safely"

MAX_PATH_POLICY_BYTES = 256 * 1024
MAX_PATH_POLICY_LIST_ITEMS = 256
MAX_PATH_INCLUDE_TARGETS = 64
MAX_PATH_POLICY_REGEX_COUNT = 64
MAX_PATH_POLICY_REGEX_LENGTH = 4_096
MAX_PATH_POLICY_METADATA_LENGTH = 4_096
MAX_PATH_SCAN_WORK_ITEMS = 20_000
MAX_PATH_SCAN_ITEMS = 10_000
MAX_PATH_FINDINGS = 10_000
# Reserve half the isolated transport cap for pickle/container overhead.
MAX_PATH_AGGREGATE_RESULT_BYTES = MAX_ISOLATED_MESSAGE_BYTES // 2
PATH_FINDING_RESULT_OVERHEAD_BYTES = 256


DEFAULT_EXCLUDE_PREFIXES = [
    ".git",
    ".venv",
    ".venv312",
    ".venv-py312",
    "__pycache__",
    ".pytest_cache",
    "build",
    "dist",
]


@dataclass(frozen=True)
class PathGuardRule:
    rule_id: str
    severity: str
    message: str
    regex: re.Pattern[str]


@dataclass(frozen=True)
class PathGuardFinding:
    path: str
    rule_id: str
    severity: str
    message: str
    matched_pattern: str

    def to_dict(self) -> dict[str, object]:
        return {
            "path": self.path,
            "rule_id": self.rule_id,
            "severity": self.severity,
            "message": self.message,
            "matched_pattern": self.matched_pattern,
        }


def _read_policy_text(path: Path) -> str:
    try:
        with path.open("rb") as handle:
            raw = handle.read(MAX_PATH_POLICY_BYTES + 1)
    except FileNotFoundError:
        raise FileNotFoundError(f"{ERROR_PATH_POLICY_NOT_FOUND}: {path}") from None
    except OSError:
        raise ValueError(ERROR_PATH_POLICY_INVALID) from None

    if len(raw) > MAX_PATH_POLICY_BYTES:
        raise ValueError(ERROR_PATH_POLICY_LIMIT)
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError(ERROR_PATH_POLICY_INVALID) from None


def load_path_policy(path: Path) -> dict[str, Any]:
    try:
        loaded = load_bounded_yaml(_read_policy_text(path)) or {}
        if not isinstance(loaded, dict):
            raise BoundedYamlInvalidError
    except BoundedYamlLimitError:
        raise ValueError(ERROR_PATH_POLICY_LIMIT) from None
    except BoundedYamlInvalidError:
        raise ValueError(ERROR_PATH_POLICY_INVALID) from None
    except (MemoryError, OverflowError, RecursionError):
        raise ValueError(ERROR_PATH_POLICY_LIMIT) from None
    return loaded


def normalize_string_list(values: Any, *, limit: int = MAX_PATH_POLICY_LIST_ITEMS) -> list[str]:
    if not isinstance(values, list):
        raise ValueError(ERROR_PATH_POLICY_INVALID)
    if len(values) > limit:
        raise ValueError(ERROR_PATH_POLICY_LIMIT)
    out: list[str] = []
    for value in values:
        if not isinstance(value, str):
            raise ValueError(ERROR_PATH_POLICY_INVALID)
        text = value.strip()
        if len(text) > MAX_PATH_POLICY_REGEX_LENGTH:
            raise ValueError(ERROR_PATH_POLICY_LIMIT)
        if text:
            out.append(text)
    return out


def _contains_parent_traversal(path_text: str) -> bool:
    return any(part == ".." for part in re.split(r"[\\/]", path_text))


def normalize_rel_path(root: Path, path_text: str) -> Path:
    text = path_text.strip()
    if _contains_parent_traversal(text):
        raise ValueError(ERROR_PATH_SCAN_TARGET)

    resolved_root = root.resolve()
    try:
        path = Path(text)
        target = path if path.is_absolute() else resolved_root / path
        target = target.resolve(strict=False)
        target.relative_to(resolved_root)
    except (OSError, RuntimeError, ValueError):
        raise ValueError(ERROR_PATH_SCAN_TARGET) from None
    return target


def _validate_include_targets(root: Path, include_paths: Iterable[str]) -> None:
    for include_path in include_paths:
        normalize_rel_path(root, include_path)


def is_excluded(rel_path: str, excluded_prefixes: Iterable[str]) -> bool:
    return any(rel_path == prefix or rel_path.startswith(prefix + "/") for prefix in excluded_prefixes)


def iter_repo_paths(root: Path, include: list[str], exclude: list[str]) -> Iterable[str]:
    if len(include) > MAX_PATH_INCLUDE_TARGETS or len(exclude) > MAX_PATH_POLICY_LIST_ITEMS:
        raise ValueError(ERROR_PATH_POLICY_LIMIT)

    root = root.resolve()
    include_paths = include or ["."]
    exclude_prefixes = [*DEFAULT_EXCLUDE_PREFIXES, *exclude]
    seen: set[str] = set()
    scanned_work_items = 0

    for include_path in include_paths:
        target = normalize_rel_path(root, include_path)
        if not target.exists():
            continue

        candidates = [target]
        target_rel = target.relative_to(root).as_posix()
        pending = [target] if target.is_dir() and not is_excluded(target_rel, exclude_prefixes) else []
        try:
            while pending:
                current = pending.pop()
                with os.scandir(current) as entries:
                    for entry in entries:
                        scanned_work_items += 1
                        if scanned_work_items > MAX_PATH_SCAN_WORK_ITEMS:
                            raise ValueError(ERROR_PATH_SCAN_LIMIT)
                        path = current / entry.name
                        rel = path.relative_to(root).as_posix()
                        if is_excluded(rel, exclude_prefixes):
                            continue
                        candidates.append(path)
                        if entry.is_dir(follow_symlinks=False):
                            pending.append(path)
        except OSError:
            raise ValueError(ERROR_PATH_SCAN_LIMIT) from None

        for path in sorted(candidates):
            rel = path.relative_to(root).as_posix()
            if rel == "." or rel in seen or is_excluded(rel, exclude_prefixes):
                continue
            seen.add(rel)
            if len(seen) > MAX_PATH_SCAN_ITEMS:
                raise ValueError(ERROR_PATH_SCAN_LIMIT)
            yield rel


def normalize_allow_patterns(values: Any) -> list[re.Pattern[str]]:
    patterns: list[re.Pattern[str]] = []
    for text in normalize_string_list(values, limit=MAX_PATH_POLICY_REGEX_COUNT):
        if len(text) > MAX_PATH_POLICY_REGEX_LENGTH:
            raise ValueError(ERROR_PATH_POLICY_LIMIT)
        try:
            patterns.append(re.compile(text))
        except (OverflowError, RecursionError, re.error):
            raise ValueError(ERROR_PATH_ALLOWED_REGEX_INVALID) from None
    return patterns


def build_rules(values: Any) -> list[PathGuardRule]:
    if not isinstance(values, list):
        raise ValueError(ERROR_PATH_POLICY_INVALID)
    if len(values) > MAX_PATH_POLICY_REGEX_COUNT:
        raise ValueError(ERROR_PATH_POLICY_LIMIT)

    rules: list[PathGuardRule] = []
    for idx, item in enumerate(values, start=1):
        if isinstance(item, str):
            pattern_text = item.strip()
            rule_id = f"path_rule_{idx}"
            severity = "high"
            message = "forbidden path pattern found"
        elif isinstance(item, dict):
            raw_pattern = item.get("pattern", "")
            raw_rule_id = item.get("id", f"path_rule_{idx}")
            raw_severity = item.get("severity", "high")
            raw_message = item.get("message", "forbidden path pattern found")
            if not all(
                isinstance(value, str)
                for value in (raw_pattern, raw_rule_id, raw_severity, raw_message)
            ):
                raise ValueError(ERROR_PATH_POLICY_INVALID)
            pattern_text = raw_pattern.strip()
            rule_id = raw_rule_id.strip() or f"path_rule_{idx}"
            severity = raw_severity.strip() or "high"
            message = raw_message.strip() or "forbidden path pattern found"
        else:
            raise ValueError(ERROR_PATH_POLICY_INVALID)

        if pattern_text:
            if any(
                len(value) > MAX_PATH_POLICY_METADATA_LENGTH
                for value in (rule_id, severity, message)
            ):
                raise ValueError(ERROR_PATH_POLICY_LIMIT)
            if len(pattern_text) > MAX_PATH_POLICY_REGEX_LENGTH:
                raise ValueError(ERROR_PATH_POLICY_LIMIT)
            try:
                regex = re.compile(pattern_text)
            except (OverflowError, RecursionError, re.error):
                raise ValueError(ERROR_PATH_FORBIDDEN_REGEX_INVALID) from None
            rules.append(
                PathGuardRule(
                    rule_id=rule_id,
                    severity=severity,
                    message=message,
                    regex=regex,
                )
            )
    return rules


def _finding_result_size_bytes(*values: str) -> int:
    return PATH_FINDING_RESULT_OVERHEAD_BYTES + sum(
        len(value.encode("utf-8", errors="surrogatepass")) for value in values
    )


def _scan_paths_unbounded(
    root: Path,
    include_paths: list[str],
    exclude_paths: list[str],
    allowed_patterns: list[re.Pattern[str]],
    rules: list[PathGuardRule],
) -> tuple[list[PathGuardFinding], int]:
    findings: list[PathGuardFinding] = []
    aggregate_result_bytes = 0
    scanned = 0
    for rel_path in iter_repo_paths(root, include_paths, exclude_paths):
        scanned += 1
        if any(pattern.search(rel_path) for pattern in allowed_patterns):
            continue
        for rule in rules:
            if rule.regex.search(rel_path):
                if len(findings) >= MAX_PATH_FINDINGS:
                    raise ValueError(ERROR_PATH_SCAN_LIMIT)
                finding_result_bytes = _finding_result_size_bytes(
                    rel_path,
                    rule.rule_id,
                    rule.severity,
                    rule.message,
                    rule.regex.pattern,
                )
                if finding_result_bytes > (
                    MAX_PATH_AGGREGATE_RESULT_BYTES - aggregate_result_bytes
                ):
                    raise ValueError(ERROR_PATH_SCAN_LIMIT)
                findings.append(
                    PathGuardFinding(
                        path=rel_path,
                        rule_id=rule.rule_id,
                        severity=rule.severity,
                        message=rule.message,
                        matched_pattern=rule.regex.pattern,
                    )
                )
                aggregate_result_bytes += finding_result_bytes
                break
    return findings, scanned


def scan_paths(*, root: Path, policy: dict[str, Any]) -> tuple[list[PathGuardFinding], int]:
    root = root.resolve()
    raw_scan_cfg = policy.get("scan", {})
    if not isinstance(raw_scan_cfg, dict):
        raise ValueError(ERROR_PATH_POLICY_INVALID)
    scan_cfg = raw_scan_cfg
    include_paths = normalize_string_list(
        scan_cfg.get("include", []),
        limit=MAX_PATH_INCLUDE_TARGETS,
    )
    exclude_paths = normalize_string_list(scan_cfg.get("exclude", []))
    effective_include_paths = include_paths or ["."]
    _validate_include_targets(root, effective_include_paths)

    raw_policy_cfg = policy.get("policy", {})
    if not isinstance(raw_policy_cfg, dict):
        raise ValueError(ERROR_PATH_POLICY_INVALID)
    policy_cfg = raw_policy_cfg
    allowed_values = policy_cfg.get("allowed_path_patterns", [])
    forbidden_values = policy_cfg.get("forbidden_path_patterns", [])
    policy_regex_count = sum(
        len(values)
        for values in (allowed_values, forbidden_values)
        if isinstance(values, list)
    )
    if policy_regex_count > MAX_PATH_POLICY_REGEX_COUNT:
        raise ValueError(ERROR_PATH_POLICY_LIMIT)
    allowed_patterns = normalize_allow_patterns(allowed_values)
    rules = build_rules(forbidden_values)

    return run_isolated_scan(
        _scan_paths_unbounded,
        root,
        include_paths,
        exclude_paths,
        allowed_patterns,
        rules,
        timeout_error=ERROR_PATH_SCAN_TIMEOUT,
        runtime_error=ERROR_PATH_SCAN_RUNTIME,
        result_limit_error=ERROR_PATH_SCAN_LIMIT,
        safe_errors=(ERROR_PATH_SCAN_LIMIT, ERROR_PATH_SCAN_TARGET),
    )
