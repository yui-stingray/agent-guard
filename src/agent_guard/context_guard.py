"""Where: src/agent_guard/context_guard.py
What: static scanner for agent context files such as AGENTS.md and CLAUDE.md.
Why: keep repository-level agent instructions from weakening safety controls.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

import yaml


DEFAULT_INCLUDE = [
    "AGENTS.md",
    "**/AGENTS.md",
    "CLAUDE.md",
    "**/CLAUDE.md",
    "GEMINI.md",
    "**/GEMINI.md",
    ".github/copilot-instructions.md",
    ".github/instructions/**/*.instructions.md",
    ".cursor/rules",
    ".cursor/rules/**/*.md",
    ".cursorrules",
    ".windsurfrules",
    ".windsurf/rules/**/*.md",
    ".continue/rules/**/*.md",
]

DEFAULT_EXCLUDE = [
    ".git/**",
    ".venv/**",
    ".venv312/**",
    ".venv-py312/**",
    "__pycache__/**",
    ".pytest_cache/**",
    "build/**",
    "dist/**",
    "node_modules/**",
]

DEFAULT_FORBIDDEN_PATTERNS = [
    {
        "id": "approval_bypass",
        "severity": "high",
        "pattern": r"(?i)\b(ignore|bypass|disable|skip)\b.{0,80}\b(approval|permission|policy|guardrail|safety check)\b",
        "message": "agent context must not instruct agents to bypass approval or policy checks",
    },
    {
        "id": "secret_prompt",
        "severity": "high",
        "pattern": r"(?i)\b(provide|paste|enter|write)\b.{0,80}\b(api[_ -]?key|token|password|secret)\b",
        "message": "agent context must not ask users or agents to expose plaintext secrets",
    },
    {
        "id": "destructive_command",
        "severity": "high",
        "pattern": r"(?i)(git\s+(reset\s+--hard|push\s+--force\b|clean\s+-f)|rm\s+-rf\s+(/|~|/home|/mnt/c|[A-Za-z]:\\))",
        "message": "agent context must not normalize destructive command execution",
    },
    {
        "id": "hidden_action",
        "severity": "high",
        "pattern": r"(?i)\b(hide|conceal|withhold)\b.{0,80}\b(action|change|command|from\s+(the\s+)?(user|maintainer|reviewer))\b|\bwithout\s+(telling|notifying)\s+(the\s+)?(user|maintainer|reviewer)\b",
        "message": "agent context must not instruct agents to hide actions from users or maintainers",
    },
]


@dataclass(frozen=True)
class ContextGuardFinding:
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


def load_context_policy(path: Path) -> dict[str, object]:
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


def policy_section(policy: dict[str, object]) -> dict[str, object]:
    raw = policy.get("policy", {})
    return raw if isinstance(raw, dict) else {}


def scan_section(policy: dict[str, object]) -> dict[str, object]:
    raw = policy.get("scan", {})
    return raw if isinstance(raw, dict) else {}


def has_glob_magic(pattern: str) -> bool:
    return any(char in pattern for char in "*?[")


def glob_matches(path: Path, pattern: str) -> bool:
    if path.match(pattern):
        return True
    if pattern.startswith("**/"):
        return path.match(pattern[3:])
    return False


def is_excluded(rel_path: Path, exclude: Iterable[str]) -> bool:
    return any(glob_matches(rel_path, pattern) for pattern in exclude)


def iter_context_files(*, root: Path, policy: dict[str, object]) -> list[Path]:
    root = root.resolve()
    scan_cfg = scan_section(policy)
    include = normalize_string_list(scan_cfg.get("include", [])) or DEFAULT_INCLUDE
    exclude = [*DEFAULT_EXCLUDE, *normalize_string_list(scan_cfg.get("exclude", []))]

    seen: set[Path] = set()
    files: list[Path] = []
    for pattern in include:
        candidates: Iterable[Path]
        if has_glob_magic(pattern):
            candidates = root.glob(pattern)
        else:
            target = (root / pattern).resolve()
            if target.is_dir():
                candidates = target.rglob("*")
            else:
                candidates = [target]

        for path in candidates:
            if not path.is_file():
                continue
            try:
                rel = path.resolve().relative_to(root)
            except ValueError:
                continue
            if is_excluded(rel, exclude) or path in seen:
                continue
            seen.add(path)
            files.append(path)

    return sorted(files)


def normalize_rule_patterns(policy: dict[str, object]) -> list[dict[str, object]]:
    cfg = policy_section(policy)
    raw_forbidden = cfg.get("forbidden_patterns", DEFAULT_FORBIDDEN_PATTERNS)
    if not isinstance(raw_forbidden, list):
        raise ValueError("forbidden_patterns must be a list")

    raw_extra = cfg.get("extra_forbidden_patterns", [])
    if raw_extra is None:
        raw_extra = []
    if not isinstance(raw_extra, list):
        raise ValueError("extra_forbidden_patterns must be a list")

    return [*raw_forbidden, *raw_extra]


def build_rules(policy: dict[str, object]) -> list[dict[str, object]]:
    rules: list[dict[str, object]] = []
    for item in normalize_rule_patterns(policy):
        if not isinstance(item, dict):
            continue
        rule_id = str(item.get("id", "")).strip()
        pattern_text = str(item.get("pattern", "")).strip()
        if not rule_id or not pattern_text:
            continue
        try:
            regex = re.compile(pattern_text)
        except re.error as exc:
            raise ValueError(f"invalid forbidden_patterns regex for {rule_id!r}: {exc}") from exc
        rules.append(
            {
                "id": rule_id,
                "severity": str(item.get("severity", "high")).strip() or "high",
                "message": str(item.get("message", "policy violation")).strip() or "policy violation",
                "regex": regex,
            }
        )
    return rules


def read_text(path: Path) -> str | None:
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return None
    except Exception:
        return None
    if "\x00" in text:
        return None
    return text


def display_path(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return str(path)


def line_allows_rule(line: str, rule_id: str) -> bool:
    match = re.search(r"agent-guard:\s*allow\s+([A-Za-z0-9_., -]+)", line)
    if not match:
        return False
    allowed = {
        item.strip()
        for item in re.split(r"[,\s]+", match.group(1))
        if item.strip()
    }
    return "all" in allowed or rule_id in allowed


def scan_context_files(*, root: Path, policy: dict[str, object]) -> tuple[list[ContextGuardFinding], int]:
    root = root.resolve()
    rules = build_rules(policy)
    paths = iter_context_files(root=root, policy=policy)

    findings: list[ContextGuardFinding] = []
    for path in paths:
        text = read_text(path)
        if text is None:
            continue
        rel = display_path(path, root)
        for lineno, line in enumerate(text.splitlines(), start=1):
            for rule in rules:
                rule_id = str(rule["id"])
                if line_allows_rule(line, rule_id):
                    continue
                regex = rule["regex"]
                assert isinstance(regex, re.Pattern)
                if regex.search(line):
                    findings.append(
                        ContextGuardFinding(
                            file=rel,
                            line=lineno,
                            rule_id=rule_id,
                            severity=str(rule["severity"]),
                            message=str(rule["message"]),
                            snippet=line.strip()[:200],
                        )
                    )
    return findings, len(paths)
