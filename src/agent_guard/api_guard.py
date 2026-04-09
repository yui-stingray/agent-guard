"""Where: src/agent_guard/api_guard.py
What: static scanner for forbidden API endpoint usage inside a repository.
Why: keep CLI-first or otherwise bounded integration rules enforceable in CI and hooks.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

import yaml

URL_PATTERN = re.compile(r"https://[^\s\"'`<>()]+")


@dataclass(frozen=True)
class ApiGuardFinding:
    path: str
    line: int
    url: str
    matched_forbidden_pattern: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "line": self.line,
            "url": self.url,
            "matched_forbidden_pattern": self.matched_forbidden_pattern,
        }


def load_yaml_policy(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(f"policy file not found: {path}")

    loaded = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(loaded, dict):
        raise ValueError(f"policy file must be YAML object: {path}")
    return loaded


def normalize_rel_path(root: Path, path_text: str) -> Path:
    path = Path(path_text.strip())
    return path if path.is_absolute() else (root / path).resolve()


def normalize_string_list(values: Any) -> list[str]:
    if not isinstance(values, list):
        return []
    out: list[str] = []
    for value in values:
        text = str(value).strip()
        if text:
            out.append(text)
    return out


def normalize_pattern_list(values: Any) -> list[re.Pattern[str]]:
    return [re.compile(text) for text in normalize_string_list(values)]


def is_excluded(rel_path: str, excluded_prefixes: list[str]) -> bool:
    return any(rel_path == prefix or rel_path.startswith(prefix + "/") for prefix in excluded_prefixes)


def iter_scan_files(root: Path, include: list[str], exclude: list[str]) -> Iterable[Path]:
    for include_path in include:
        target = normalize_rel_path(root, include_path)
        if not target.exists():
            continue
        if target.is_file():
            rel = target.resolve().relative_to(root).as_posix()
            if not is_excluded(rel, exclude):
                yield target
            continue
        for path in sorted(target.rglob("*")):
            if not path.is_file():
                continue
            rel = path.resolve().relative_to(root).as_posix()
            if is_excluded(rel, exclude):
                continue
            yield path


def read_text(path: Path) -> str | None:
    try:
        content = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return None
    except Exception:
        return None
    if "\x00" in content:
        return None
    return content


def normalize_url(raw_url: str) -> str:
    return raw_url.rstrip(".,);]")


def scan_urls(*, root: Path, policy: dict[str, Any]) -> list[ApiGuardFinding]:
    scan_cfg = policy.get("scan", {}) if isinstance(policy.get("scan", {}), dict) else {}
    include_paths = normalize_string_list(scan_cfg.get("include", []))
    exclude_paths = normalize_string_list(scan_cfg.get("exclude", []))

    policy_cfg = policy.get("policy", {}) if isinstance(policy.get("policy", {}), dict) else {}
    allowed_patterns = normalize_pattern_list(policy_cfg.get("allowed_api_patterns", []))
    forbidden_patterns = normalize_pattern_list(policy_cfg.get("forbidden_api_patterns", []))

    findings: list[ApiGuardFinding] = []
    for path in iter_scan_files(root, include_paths, exclude_paths):
        content = read_text(path)
        if content is None:
            continue

        rel_path = path.resolve().relative_to(root).as_posix()
        for lineno, line in enumerate(content.splitlines(), start=1):
            for match in URL_PATTERN.finditer(line):
                url = normalize_url(match.group(0))

                if any(pattern.search(url) for pattern in allowed_patterns):
                    continue

                for forbidden in forbidden_patterns:
                    if forbidden.search(url):
                        findings.append(
                            ApiGuardFinding(
                                path=rel_path,
                                line=lineno,
                                url=url,
                                matched_forbidden_pattern=forbidden.pattern,
                            )
                        )
                        break
    return findings
