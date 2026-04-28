"""Where: src/agent_guard/path_guard.py
What: static scanner for repository path names that must not enter a repo.
Why: catch private artifacts and env-file leaks even when file contents are unread.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

import yaml


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


def load_path_policy(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(f"policy file not found: {path}")

    loaded = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(loaded, dict):
        raise ValueError(f"policy file must be YAML object: {path}")
    return loaded


def normalize_string_list(values: Any) -> list[str]:
    if not isinstance(values, list):
        return []
    out: list[str] = []
    for value in values:
        text = str(value).strip()
        if text:
            out.append(text)
    return out


def normalize_rel_path(root: Path, path_text: str) -> Path:
    path = Path(path_text.strip())
    return path if path.is_absolute() else (root / path).resolve()


def is_excluded(rel_path: str, excluded_prefixes: Iterable[str]) -> bool:
    return any(rel_path == prefix or rel_path.startswith(prefix + "/") for prefix in excluded_prefixes)


def iter_repo_paths(root: Path, include: list[str], exclude: list[str]) -> Iterable[str]:
    include_paths = include or ["."]
    exclude_prefixes = [*DEFAULT_EXCLUDE_PREFIXES, *exclude]
    seen: set[str] = set()

    for include_path in include_paths:
        target = normalize_rel_path(root, include_path)
        if not target.exists():
            continue

        candidates = [target, *target.rglob("*")] if target.is_dir() else [target]
        for path in candidates:
            try:
                rel = path.relative_to(root).as_posix()
            except ValueError:
                continue
            if rel == "." or rel in seen or is_excluded(rel, exclude_prefixes):
                continue
            seen.add(rel)
            yield rel


def normalize_allow_patterns(values: Any) -> list[re.Pattern[str]]:
    return [re.compile(text) for text in normalize_string_list(values)]


def build_rules(values: Any) -> list[PathGuardRule]:
    if not isinstance(values, list):
        return []

    rules: list[PathGuardRule] = []
    for idx, item in enumerate(values, start=1):
        if isinstance(item, str):
            pattern_text = item.strip()
            rule_id = f"path_rule_{idx}"
            severity = "high"
            message = "forbidden path pattern found"
        elif isinstance(item, dict):
            pattern_text = str(item.get("pattern", "")).strip()
            rule_id = str(item.get("id", f"path_rule_{idx}")).strip() or f"path_rule_{idx}"
            severity = str(item.get("severity", "high")).strip() or "high"
            message = str(item.get("message", "forbidden path pattern found")).strip() or "forbidden path pattern found"
        else:
            continue

        if pattern_text:
            rules.append(
                PathGuardRule(
                    rule_id=rule_id,
                    severity=severity,
                    message=message,
                    regex=re.compile(pattern_text),
                )
            )
    return rules


def scan_paths(*, root: Path, policy: dict[str, Any]) -> tuple[list[PathGuardFinding], int]:
    root = root.resolve()
    scan_cfg = policy.get("scan", {}) if isinstance(policy.get("scan", {}), dict) else {}
    include_paths = normalize_string_list(scan_cfg.get("include", []))
    exclude_paths = normalize_string_list(scan_cfg.get("exclude", []))

    policy_cfg = policy.get("policy", {}) if isinstance(policy.get("policy", {}), dict) else {}
    allowed_patterns = normalize_allow_patterns(policy_cfg.get("allowed_path_patterns", []))
    rules = build_rules(policy_cfg.get("forbidden_path_patterns", []))

    findings: list[PathGuardFinding] = []
    scanned = 0
    for rel_path in iter_repo_paths(root, include_paths, exclude_paths):
        scanned += 1
        if any(pattern.search(rel_path) for pattern in allowed_patterns):
            continue
        for rule in rules:
            if rule.regex.search(rel_path):
                findings.append(
                    PathGuardFinding(
                        path=rel_path,
                        rule_id=rule.rule_id,
                        severity=rule.severity,
                        message=rule.message,
                        matched_pattern=rule.regex.pattern,
                    )
                )
                break
    return findings, scanned
