"""Where: src/agent_guard/content_guard.py
What: static scanner for dangerous patterns in agent-facing text content.
Why: keep skill docs and similar Markdown content from drifting into unsafe instructions.
"""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Sequence

import yaml


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


def run_git(repo_root: Path, args: Sequence[str]) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo_root), *args],
        text=True,
        capture_output=True,
        check=False,
        timeout=15,
    )
    if result.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} failed: {result.stderr.strip()}")
    return result.stdout


def merge_policy(base: dict[str, object], override: dict[str, object]) -> dict[str, object]:
    merged = dict(base)
    for key in ("forbidden_patterns", "exclude_globs", "file_globs"):
        value = override.get(key)
        if isinstance(value, list):
            merged[key] = value
    return merged


def load_content_policy(path: Path) -> dict[str, object]:
    if not path.exists():
        raise FileNotFoundError(f"policy file not found: {path}")

    loaded = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(loaded, dict):
        raise ValueError(f"policy file must be YAML object: {path}")
    return merge_policy(DEFAULT_POLICY, loaded)


def normalize_patterns(raw: object) -> list[str]:
    if not isinstance(raw, list):
        return []
    return [str(item).strip() for item in raw if str(item).strip()]


def build_rules(policy: dict[str, object]) -> list[dict[str, object]]:
    raw_rules = policy.get("forbidden_patterns", [])
    if not isinstance(raw_rules, list):
        raise ValueError("forbidden_patterns must be a list")

    rules: list[dict[str, object]] = []
    for item in raw_rules:
        if not isinstance(item, dict):
            continue
        rule_id = str(item.get("id", "")).strip()
        pattern_text = str(item.get("pattern", "")).strip()
        if not rule_id or not pattern_text:
            continue
        rules.append(
            {
                "id": rule_id,
                "severity": str(item.get("severity", "high")).strip() or "high",
                "message": str(item.get("message", "policy violation")).strip() or "policy violation",
                "regex": re.compile(pattern_text),
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


def iter_files_under(root: Path, file_globs: Iterable[str], exclude_globs: Iterable[str]) -> list[Path]:
    files: list[Path] = []
    for pattern in file_globs:
        files.extend(path for path in root.glob(pattern) if path.is_file())
    dedup = sorted(set(files))

    excluded = [pattern for pattern in exclude_globs if pattern]
    if not excluded:
        return dedup

    kept: list[Path] = []
    for path in dedup:
        rel = path.relative_to(root)
        if any(glob_matches(rel, pattern) for pattern in excluded):
            continue
        kept.append(path)
    return kept


def normalize_targets(paths: Iterable[str]) -> list[Path]:
    targets: list[Path] = []
    for raw in paths:
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
    for target in normalized:
        if target.is_file():
            collected.append(target)
            continue
        if target.is_dir():
            collected.extend(iter_files_under(target, file_globs, exclude_globs))
    return sorted(set(collected))


def collect_registered_targets(
    repo_root: Path,
    scan_dir: Path,
    file_globs: Iterable[str],
    exclude_globs: Iterable[str],
) -> list[Path]:
    target_root = scan_dir if scan_dir.is_absolute() else (repo_root / scan_dir)
    target_root = target_root.resolve()
    if not target_root.exists():
        raise RuntimeError(f"scan dir not found: {target_root}")
    return iter_files_under(target_root, file_globs, exclude_globs)


def collect_new_targets(
    repo_root: Path,
    scan_dir: Path,
    file_globs: Iterable[str],
    exclude_globs: Iterable[str],
    since_ref: str,
    include_untracked: bool,
) -> list[Path]:
    target_root = scan_dir if scan_dir.is_absolute() else (repo_root / scan_dir)
    target_root = target_root.resolve()

    try:
        rel_scan = str(target_root.relative_to(repo_root))
    except ValueError:
        rel_scan = str(scan_dir)

    changed: set[Path] = set()

    if since_ref:
        output = run_git(repo_root, ["diff", "--name-only", "--diff-filter=AM", f"{since_ref}...HEAD", "--", rel_scan])
        for line in output.splitlines():
            path = (repo_root / line.strip()).resolve()
            if path.is_file():
                changed.add(path)
    else:
        for args in (
            ["diff", "--name-only", "--diff-filter=AM", "--", rel_scan],
            ["diff", "--cached", "--name-only", "--diff-filter=AM", "--", rel_scan],
        ):
            output = run_git(repo_root, args)
            for line in output.splitlines():
                path = (repo_root / line.strip()).resolve()
                if path.is_file():
                    changed.add(path)

        if include_untracked:
            output = run_git(repo_root, ["ls-files", "--others", "--exclude-standard", "--", rel_scan])
            for line in output.splitlines():
                path = (repo_root / line.strip()).resolve()
                if path.is_file():
                    changed.add(path)

    allowed: list[Path] = []
    patterns = list(file_globs)
    excludes = list(exclude_globs)
    for path in sorted(changed):
        try:
            rel = path.relative_to(target_root)
        except ValueError:
            continue
        if excludes and any(glob_matches(rel, pattern) for pattern in excludes):
            continue
        if patterns and not any(glob_matches(rel, pattern) for pattern in patterns):
            continue
        allowed.append(path)
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


def scan_file(path: Path, rules: list[dict[str, object]], repo_root: Path) -> list[ContentGuardFinding]:
    findings: list[ContentGuardFinding] = []
    text = path.read_text(encoding="utf-8")
    for idx, line in enumerate(text.splitlines(), start=1):
        for rule in rules:
            if not rule_applies_to_path(rule, path, repo_root):
                continue

            rule_id = str(rule["id"])
            if line_allows_rule(line, rule_id):
                continue

            regex = rule["regex"]
            assert isinstance(regex, re.Pattern)
            if regex.search(line):
                findings.append(
                    ContentGuardFinding(
                        file=display_path(path, repo_root),
                        line=idx,
                        rule_id=rule_id,
                        severity=str(rule["severity"]),
                        message=str(rule["message"]),
                        snippet=line.strip()[:200],
                    )
                )
    return findings


def scan_paths(paths: Iterable[Path], rules: list[dict[str, object]], repo_root: Path) -> list[ContentGuardFinding]:
    findings: list[ContentGuardFinding] = []
    for path in paths:
        findings.extend(scan_file(path, rules, repo_root))
    return findings
