"""Where: src/agent_guard/context_guard.py
What: static scanner for agent context files such as AGENTS.md and CLAUDE.md.
Why: keep repository-level agent instructions from weakening safety controls.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Literal, Sequence

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
        "pattern": r"(?i)(?:\b(ignore|bypass|disable|skip)\b|(?<!not )(?<!never )\buse\s+b\s+y\s+p\s+a\s+s\s+s\b).{0,80}\b(approval|permission|policy|guardrail|safety checks?)\b",
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
    {
        "id": "disable_safety_tools",
        "severity": "high",
        "pattern": r"(?i)\b(disable|turn\s+off|skip|bypass)\b.{0,80}\b(agent-guard|agent-policy|safety\s+check|guardrails?|policy\s+check|evidence\s+gate)\b",
        "message": "agent context must not instruct agents to disable repository safety tools",
    },
    {
        "id": "skip_verification",
        "severity": "medium",
        "pattern": r"(?i)\b(never|do\s+not|don't|skip)\b.{0,80}\b(run|perform|execute)\b.{0,40}\b(tests?|pytest|lint|typecheck|build|verification|smoke\s+checks?)\b|(?:テスト|検証).{0,20}(?:実行しない|行わない)",
        "message": "agent context should not normalize skipping verification",
    },
    {
        "id": "ignore_test_failures",
        "severity": "high",
        "pattern": r"(?i)\b(ignore|hide|suppress|dismiss)\b.{0,80}\b(failing|failed|broken)\b.{0,40}\b(tests?|checks?|ci|lint|build)\b",
        "message": "agent context must not instruct agents to ignore failing verification",
    },
    {
        "id": "force_merge_without_review",
        "severity": "high",
        "pattern": r"(?i)\b(merge|land|approve)\b.{0,80}\b(without|no)\b.{0,40}\b(review|maintainer|approval)\b|\b(no|without)\b.{0,40}\b(review|maintainer|approval)\b.{0,80}\b(merge|land|approve)\b",
        "message": "agent context must not bypass maintainer review for merges",
    },
    {
        "id": "credential_persistence",
        "severity": "high",
        "pattern": r"(?i)\b(save|store|commit|log)\b.{0,80}\b(api[_ -]?key|token|password|secret|credential)\b",
        "message": "agent context must not ask agents to persist plaintext credentials",
    },
    {
        "id": "unrestricted_network",
        "severity": "medium",
        "pattern": r"(?i)\b(always|automatically|auto|without\s+approval|without\s+review)\b.{0,80}\b(allow|permit|enable)\b.{0,40}\b(network\s+access|internet\s+access|web\s+access|external\s+api|remote\s+access)\b",
        "message": "agent context should not broadly auto-allow network access",
    },
    {
        "id": "untrusted_instruction_priority",
        "severity": "medium",
        "pattern": r"(?i)\b(issue|comment|web\s+page|website|prompt|user\s+message|external\s+content)\b.{0,80}\b(overrides?|takes?\s+priority|supersedes?)\b.{0,80}\b(AGENTS\.md|CLAUDE\.md|policy|repository\s+instructions?)\b",
        "message": "agent context should not let untrusted content override repository policy",
    },
    {
        "id": "raw_evidence_publication",
        "severity": "high",
        "pattern": r"(?i)\b(publish|post|upload|share)\b.{0,80}\b(raw|full|complete)\b.{0,40}\b(logs?|transcripts?|prompts?|tool\s+output|workflow\s+output|evidence)\b",
        "message": "agent context must not publish raw logs, prompts, or evidence",
    },
    {
        "id": "policy_self_modification",
        "severity": "high",
        "pattern": r"(?i)\b(modify|rewrite|edit|update)\b.{0,80}\b(AGENTS\.md|CLAUDE\.md|agent\s+instructions?|policy\s+files?)\b.{0,80}\b(without|no)\b.{0,40}\b(review|approval|maintainer)\b",
        "message": "agent context must not authorize unreviewed policy or instruction changes",
    },
    {
        "id": "sandbox_escape",
        "severity": "high",
        "pattern": r"(?i)\b(disable|bypass|escape|ignore)\b.{0,80}\b(sandbox|container|isolation|permission\s+profile)\b",
        "message": "agent context must not instruct agents to bypass sandbox boundaries",
    },
    {
        "id": "permission_self_escalation",
        "severity": "high",
        "pattern": r"(?i)\b(grant|give|assume|escalate)\b.{0,80}\b(admin|root|sudo|write\s+access|maintainer\s+access|elevated\s+permissions?)\b",
        "message": "agent context must not instruct agents to self-escalate permissions",
    },
    {
        "id": "audit_trail_removal",
        "severity": "high",
        "pattern": r"(?i)\b(delete|remove|erase|clean)\b.{0,80}\b(audit\s+logs?|logs?|evidence|trace|history)\b.{0,80}\b(after|before)\b.{0,40}\b(review|reporting|completion|commit)\b",
        "message": "agent context must not remove audit trails to avoid review",
    },
    {
        "id": "private_data_exfiltration",
        "severity": "high",
        "pattern": r"(?i)\b(send|upload|post|exfiltrate|copy)\b.{0,80}\b(secrets?|tokens?|credentials?|private\s+data|local\s+paths?|environment\s+variables?)\b.{0,80}\b(to|into)\b.{0,40}\b(url|webhook|external|remote|public)\b|(?:秘密情報|トークン).{0,40}(?:外部URL|外部|URL).{0,40}(?:アップロード|送信)",
        "message": "agent context must not move private data to external destinations",
    },
    {
        "id": "user_impersonation",
        "severity": "high",
        "pattern": r"(?i)\b(commit|push|comment|approve|merge)\b.{0,80}\b(as|on\s+behalf\s+of)\b.{0,40}\b(the\s+)?user\b.{0,80}\b(without|no)\b.{0,40}\b(approval|review|telling|consent)\b",
        "message": "agent context must not authorize impersonating a user without approval",
    },
    {
        "id": "unsafe_release_publication",
        "severity": "high",
        "pattern": r"(?i)\b(publish|release|deploy)\b.{0,80}\b(without|no)\b.{0,40}\b(review|approval|verification|ci|tests?)\b",
        "message": "agent context must not authorize unreviewed publication or release",
    },
    {
        "id": "delegate_policy_bypass",
        "severity": "high",
        "pattern": r"(?i)(?<!not )(?<!never )\b(delegate|handoff|ask\s+another\s+agent|spawn\s+agent|subagent)\b.{0,80}\b(bypass|avoid|skip)\b.{0,80}\b(approval|policy|guardrail|review)\b",
        "message": "agent context must not use delegation to bypass review or policy boundaries",
    },
    {
        "id": "unsafe_tool_auto_allow",
        "severity": "high",
        "pattern": r"(?i)(?<!not )(?<!never )\b(always|automatically|auto)\b.{0,80}\b(allow|approve|permit)\b.{0,40}\b(all|any)\b.{0,20}\b(tools?|commands?|capabilities)\b",
        "message": "agent context must not broadly auto-allow all tools or commands",
    },
    {
        "id": "unreviewed_agent_output",
        "severity": "high",
        "pattern": r"(?i)(?<!not )(?<!never )\b(apply|merge|execute|trust)\b.{0,80}\b(agent|model|llm|ai)\b.{0,80}\b(output|patch(?:es)?|changes?)\b.{0,80}\b(without|no)\b.{0,40}\b(review|verification|tests?)\b",
        "message": "agent context must not accept agent output without review or verification",
    },
    {
        "id": "unsafe_background_agent",
        "severity": "medium",
        "pattern": r"(?i)(?<!not )(?<!never )\b(run|keep|start)\b.{0,80}\b(background|daemon|persistent)\b.{0,80}\b(without|no)\b.{0,40}\b(approval|notice|reporting|review)\b",
        "message": "agent context should not authorize unreviewed background or persistent agent activity",
    },
    {
        "id": "unreviewed_suppression",
        "severity": "high",
        "pattern": r"(?i)(?<!not )(?<!never )\b(add|insert|use)\b.{0,80}\b(agent-guard:\s*allow|allowlist|suppression)\b.{0,80}\b(without|no)\b.{0,40}\b(review|approval)\b",
        "message": "agent context must not authorize unreviewed guard suppressions",
    },
]

CONTEXT_INVENTORY_SCHEMA_VERSION = "agent-guard.context_inventory.v1"
BOUNDARY_CATEGORIES = [
    "approval_boundary",
    "tool_permission_boundary",
    "network_boundary",
    "secret_handling",
    "destructive_action_boundary",
    "local_verification",
]

EVIDENCE_RULES = [
    {
        "category": "approval_boundary",
        "rule_id": "approval_boundary_mention",
        "pattern": r"(?i)\b(approval|approve|permission|policy|guardrail|human review|maintainer review)\b",
    },
    {
        "category": "tool_permission_boundary",
        "rule_id": "tool_permission_boundary_mention",
        "pattern": r"(?i)\b(tool|bash|shell|network|write|edit|filesystem|file system)\b.{0,80}\b(allow|deny|approval|permission|policy)\b|\b(allow|deny|approval|permission|policy)\b.{0,80}\b(tool|bash|shell|network|write|edit|filesystem|file system)\b",
    },
    {
        "category": "network_boundary",
        "rule_id": "network_boundary_mention",
        "pattern": r"(?i)\b(network|internet|web|http|https|external api|remote)\b.{0,80}\b(allow|deny|approval|permission|policy|offline)\b|\b(allow|deny|approval|permission|policy|offline)\b.{0,80}\b(network|internet|web|http|https|external api|remote)\b",
    },
    {
        "category": "secret_handling",
        "rule_id": "secret_handling_mention",
        "pattern": r"(?i)\b(secrets?|tokens?|api[_ -]?keys?|passwords?|credentials?)\b",
    },
    {
        "category": "destructive_action_boundary",
        "rule_id": "destructive_action_boundary_mention",
        "pattern": r"(?i)(git\s+(reset\s+--hard|push\s+--force\b|clean\s+-f)|rm\s+-rf\b|destructive)",
    },
    {
        "category": "local_verification",
        "rule_id": "local_verification_mention",
        "pattern": r"(?i)\b(test|pytest|lint|typecheck|build|verify|verification|smoke check|ci)\b",
    },
]

ReadStatus = Literal["scanned", "binary", "decode_error", "read_error"]


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


@dataclass(frozen=True)
class ContextEvidence:
    evidence_id: str
    category: str
    rule_id: str
    line: int

    def to_dict(self) -> dict[str, object]:
        return {
            "evidence_id": self.evidence_id,
            "category": self.category,
            "rule_id": self.rule_id,
            "line": self.line,
        }


@dataclass(frozen=True)
class ContextInventoryEntry:
    path: str
    kind: str
    read_status: ReadStatus
    size_bytes: int
    line_count: int | None
    evidence: tuple[ContextEvidence, ...]

    def to_dict(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "path": self.path,
            "kind": self.kind,
            "read_status": self.read_status,
            "size_bytes": self.size_bytes,
            "evidence": [item.to_dict() for item in self.evidence],
        }
        if self.line_count is not None:
            payload["line_count"] = self.line_count
        return payload


@dataclass(frozen=True)
class ContextInventory:
    context_files: tuple[ContextInventoryEntry, ...]
    permission_boundaries: tuple[dict[str, object], ...]

    @property
    def evidence_count(self) -> int:
        return sum(len(item.evidence) for item in self.context_files)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": CONTEXT_INVENTORY_SCHEMA_VERSION,
            "context_files": [item.to_dict() for item in self.context_files],
            "permission_boundaries": list(self.permission_boundaries),
        }


def load_context_policy(path: Path) -> dict[str, object]:
    if not path.exists():
        raise FileNotFoundError(f"policy file not found: {path}")

    try:
        loaded = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise ValueError(f"context policy YAML is not parseable: {path}") from exc
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


def _relative_path_is_opaque(
    path: Path,
    opaque_directories: Sequence[str],
) -> bool:
    relative = path.as_posix()
    return any(
        relative == opaque or relative.startswith(f"{opaque.rstrip('/')}/")
        for opaque in opaque_directories
    )


def _directory_is_excluded(path: Path, exclude: Iterable[str]) -> bool:
    return is_excluded(path, exclude) or is_excluded(path / "__agent_guard_probe__", exclude)


def _is_within_relative_path(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def _context_glob_matches(path: Path, pattern: str) -> bool:
    if glob_matches(path, pattern):
        return True
    variants = {pattern}
    pending = [pattern]
    while pending and len(variants) < 32:
        current = pending.pop()
        start = 0
        while len(variants) < 32:
            index = current.find("**/", start)
            if index < 0:
                break
            candidate = current[:index] + current[index + 3 :]
            if candidate not in variants:
                variants.add(candidate)
                pending.append(candidate)
            start = index + 1
    return any(path.match(candidate) for candidate in variants)


def _context_candidate_matches(
    *,
    alias_path: Path,
    resolved_path: Path,
    include: Sequence[str],
    literal_directories: Sequence[tuple[Path, Path]],
) -> bool:
    for pattern in include:
        if _context_glob_matches(alias_path, pattern) or _context_glob_matches(
            resolved_path,
            pattern,
        ):
            return True
    return any(
        _is_within_relative_path(alias_path, alias_root)
        or _is_within_relative_path(resolved_path, resolved_root)
        for alias_root, resolved_root in literal_directories
    )


def _iter_context_files_pruned(
    *,
    root: Path,
    include: Sequence[str],
    exclude: Sequence[str],
    opaque_directories: Sequence[str],
) -> list[Path]:
    literal_directories: list[tuple[Path, Path]] = []
    for pattern in include:
        if has_glob_magic(pattern):
            continue
        target = root / pattern
        try:
            resolved_target = target.resolve(strict=True)
            resolved_relative = resolved_target.relative_to(root)
        except (OSError, RuntimeError, ValueError):
            continue
        if target.is_dir() and not (
            _relative_path_is_opaque(Path(pattern), opaque_directories)
            or _relative_path_is_opaque(resolved_relative, opaque_directories)
        ):
            literal_directories.append((Path(pattern), resolved_relative))

    files: list[Path] = []
    seen_files: set[Path] = set()
    pending: list[tuple[Path, frozenset[Path]]] = [(root, frozenset())]
    while pending:
        current, ancestors = pending.pop()
        try:
            resolved_current = current.resolve(strict=True)
            resolved_current.relative_to(root)
        except (OSError, RuntimeError, ValueError):
            continue
        if resolved_current in ancestors:
            continue
        child_ancestors = ancestors | {resolved_current}
        try:
            children = sorted(current.iterdir(), reverse=True)
        except OSError:
            continue
        for path in children:
            try:
                alias_relative = path.relative_to(root)
                resolved_path = path.resolve(strict=True)
                resolved_relative = resolved_path.relative_to(root)
            except (OSError, RuntimeError, ValueError):
                continue
            if (
                _relative_path_is_opaque(alias_relative, opaque_directories)
                or _relative_path_is_opaque(resolved_relative, opaque_directories)
            ):
                continue
            try:
                is_directory = path.is_dir()
                is_file = path.is_file()
            except OSError:
                continue
            if is_directory:
                if _directory_is_excluded(alias_relative, exclude) or _directory_is_excluded(
                    resolved_relative,
                    exclude,
                ):
                    continue
                pending.append((path, child_ancestors))
                continue
            if not is_file or is_excluded(alias_relative, exclude) or is_excluded(
                resolved_relative,
                exclude,
            ):
                continue
            if resolved_path in seen_files or not _context_candidate_matches(
                alias_path=alias_relative,
                resolved_path=resolved_relative,
                include=include,
                literal_directories=literal_directories,
            ):
                continue
            seen_files.add(resolved_path)
            files.append(path)
    return sorted(files)


def iter_context_files(
    *,
    root: Path,
    policy: dict[str, object],
    opaque_directories: Sequence[str] = (),
) -> list[Path]:
    root = root.resolve()
    scan_cfg = scan_section(policy)
    include = normalize_string_list(scan_cfg.get("include", [])) or DEFAULT_INCLUDE
    exclude = [*DEFAULT_EXCLUDE, *normalize_string_list(scan_cfg.get("exclude", []))]
    if opaque_directories:
        return _iter_context_files_pruned(
            root=root,
            include=include,
            exclude=exclude,
            opaque_directories=opaque_directories,
        )

    seen: set[Path] = set()
    files: list[Path] = []
    for pattern in include:
        candidates: Iterable[Path]
        if has_glob_magic(pattern):
            candidates = root.glob(pattern)
        else:
            target = root / pattern
            try:
                target.resolve().relative_to(root)
            except (OSError, RuntimeError, ValueError):
                continue
            if target.is_dir():
                candidates = target.rglob("*")
            else:
                candidates = [target]

        for path in candidates:
            if not path.is_file():
                continue
            try:
                alias_rel = path.relative_to(root)
                resolved_path = path.resolve()
                resolved_rel = resolved_path.relative_to(root)
            except (OSError, RuntimeError, ValueError):
                continue
            if (
                is_excluded(alias_rel, exclude)
                or is_excluded(resolved_rel, exclude)
                or resolved_path in seen
            ):
                continue
            seen.add(resolved_path)
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


def context_kind(rel_path: str) -> str:
    name = Path(rel_path).name
    if name == "AGENTS.md":
        return "agents_md"
    if name == "CLAUDE.md":
        return "claude"
    if name == "GEMINI.md":
        return "gemini"
    if rel_path == ".github/copilot-instructions.md" or (
        rel_path.startswith(".github/instructions/") and rel_path.endswith(".instructions.md")
    ):
        return "copilot"
    if rel_path == ".cursorrules" or rel_path == ".cursor/rules" or rel_path.startswith(".cursor/rules/"):
        return "cursor"
    if rel_path == ".windsurfrules" or rel_path.startswith(".windsurf/rules/"):
        return "windsurf"
    if rel_path.startswith(".continue/rules/"):
        return "continue"
    return "unknown"


def read_inventory_bytes(path: Path) -> bytes | None:
    try:
        return path.read_bytes()
    except Exception:
        return None


def stat_size_bytes(path: Path) -> int:
    try:
        return path.stat().st_size
    except Exception:
        return 0


def read_inventory_text(path: Path) -> tuple[ReadStatus, bytes, str | None]:
    data = read_inventory_bytes(path)
    if data is None:
        return "read_error", b"", None
    if b"\x00" in data:
        return "binary", data, None
    try:
        return "scanned", data, data.decode("utf-8")
    except UnicodeDecodeError:
        return "decode_error", data, None


def evidence_id(*, category: str, rule_id: str, rel_path: str, line: int) -> str:
    return f"{category}:{rel_path}:{line}:{rule_id}"


def collect_context_evidence(*, rel_path: str, text: str) -> tuple[ContextEvidence, ...]:
    compiled = [
        {
            "category": str(item["category"]),
            "rule_id": str(item["rule_id"]),
            "regex": re.compile(str(item["pattern"])),
        }
        for item in EVIDENCE_RULES
    ]

    evidence: list[ContextEvidence] = []
    seen: set[tuple[str, str, int]] = set()
    for lineno, line in enumerate(text.splitlines(), start=1):
        for rule in compiled:
            regex = rule["regex"]
            assert isinstance(regex, re.Pattern)
            if not regex.search(line):
                continue
            category = str(rule["category"])
            rule_id = str(rule["rule_id"])
            key = (category, rule_id, lineno)
            if key in seen:
                continue
            seen.add(key)
            evidence.append(
                ContextEvidence(
                    evidence_id=evidence_id(category=category, rule_id=rule_id, rel_path=rel_path, line=lineno),
                    category=category,
                    rule_id=rule_id,
                    line=lineno,
                )
            )
    return tuple(sorted(evidence, key=lambda item: (item.category, item.line, item.rule_id)))


def boundary_summary(context_files: tuple[ContextInventoryEntry, ...]) -> tuple[dict[str, object], ...]:
    by_category: dict[str, list[str]] = {category: [] for category in BOUNDARY_CATEGORIES}
    for entry in context_files:
        for item in entry.evidence:
            by_category.setdefault(item.category, []).append(item.evidence_id)

    summary: list[dict[str, object]] = []
    for category in BOUNDARY_CATEGORIES:
        evidence_ids = sorted(set(by_category.get(category, [])))
        summary.append(
            {
                "category": category,
                "status": "present" if evidence_ids else "missing",
                "evidence_ids": evidence_ids,
            }
        )
    return tuple(summary)


def collect_context_inventory(
    *,
    root: Path,
    policy: dict[str, object],
    opaque_directories: Sequence[str] = (),
) -> ContextInventory:
    root = root.resolve()
    entries: list[ContextInventoryEntry] = []
    for path in iter_context_files(
        root=root,
        policy=policy,
        opaque_directories=opaque_directories,
    ):
        rel = display_path(path, root)
        read_status, data, text = read_inventory_text(path)
        line_count = len(text.splitlines()) if text is not None else None
        evidence = collect_context_evidence(rel_path=rel, text=text) if text is not None else ()
        size_bytes = stat_size_bytes(path) if read_status == "read_error" else len(data)
        entries.append(
            ContextInventoryEntry(
                path=rel,
                kind=context_kind(rel),
                read_status=read_status,
                size_bytes=size_bytes,
                line_count=line_count,
                evidence=evidence,
            )
        )

    context_files = tuple(sorted(entries, key=lambda item: item.path))
    return ContextInventory(
        context_files=context_files,
        permission_boundaries=boundary_summary(context_files),
    )


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
