"""Where: src/agent_guard/context_guard.py
What: static scanner for agent context files such as AGENTS.md and CLAUDE.md.
Why: keep repository-level agent instructions from weakening safety controls.
"""

from __future__ import annotations

import json
import fnmatch
import os
import re
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Literal, Sequence

import yaml

from .bounded_repo_reader import (
    BoundedRepoContainmentError,
    BoundedRepoFile,
    BoundedRepoFileNotFoundError,
    BoundedRepoLimitError,
    BoundedRepoReceipt,
    BoundedRepoReadError,
    DistinctInputBudget,
    read_bounded_bytes,
    read_repo_bound_bytes,
)
from .bounded_scan import MAX_ISOLATED_MESSAGE_BYTES, run_isolated_scan
from .bounded_yaml import (
    BoundedYamlInvalidError,
    BoundedYamlLimitError,
    load_bounded_yaml,
)


ERROR_CONTEXT_POLICY_NOT_FOUND = "policy file not found"
ERROR_CONTEXT_POLICY_INVALID = "context policy YAML is not parseable"
ERROR_CONTEXT_POLICY_LIMIT = "context policy exceeds configured limits"
ERROR_CONTEXT_SCAN_TARGET = "context scan target must stay under repo root"
ERROR_CONTEXT_SCAN_LIMIT = "context scan exceeds configured limits"
ERROR_CONTEXT_SCAN_TIMEOUT = "context scan exceeded execution budget"
ERROR_CONTEXT_SCAN_RUNTIME = "context scan could not complete safely"
MAX_CONTEXT_POLICY_BYTES = 256 * 1024
# Match the general API policy list ceiling for repository-controlled selectors.
MAX_CONTEXT_POLICY_LIST_ITEMS = 256
MAX_CONTEXT_POLICY_REGEX_COUNT = 64
MAX_CONTEXT_POLICY_REGEX_LENGTH = 4_096
# Reuse established policy ceilings for repository-controlled path selectors.
MAX_CONTEXT_GLOB_LENGTH = MAX_CONTEXT_POLICY_REGEX_LENGTH
MAX_CONTEXT_GLOB_COMPONENTS = MAX_CONTEXT_POLICY_LIST_ITEMS
# Match API/content scanner selection and per-file ceilings.
MAX_CONTEXT_SCAN_FILES = 10_000
MAX_CONTEXT_FILE_BYTES = 1_048_576
MAX_CONTEXT_GLOB_WORK_UNITS = MAX_CONTEXT_SCAN_FILES * MAX_CONTEXT_GLOB_COMPONENTS
# Match the workflow scanner's aggregate distinct-input ceiling.
MAX_CONTEXT_DISTINCT_INPUT_BYTES = 16 * 1024 * 1024
# Reserve half the isolated transport cap for container/serialization overhead.
MAX_CONTEXT_AGGREGATE_RESULT_BYTES = MAX_ISOLATED_MESSAGE_BYTES // 2


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
        "pattern": r"(?i)(?:\b(ignore|bypass|disable|skip)\b|\buse\s+b\s+y\s+p\s+a\s+s\s+s\b).{0,80}\b(approval|permission|policy|guardrail|safety checks?)\b",
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
        "pattern": r"(?i)\b(delegate|handoff|ask\s+another\s+agent|spawn\s+agent|subagent)\b.{0,80}\b(bypass|avoid|skip)\b.{0,80}\b(approval|policy|guardrail|review)\b",
        "message": "agent context must not use delegation to bypass review or policy boundaries",
    },
    {
        "id": "unsafe_tool_auto_allow",
        "severity": "high",
        "pattern": r"(?i)\b(always|automatically|auto)\b.{0,80}\b(allow|approve|permit)\b.{0,40}\b(all|any)\b.{0,20}\b(tools?|commands?|capabilities)\b",
        "message": "agent context must not broadly auto-allow all tools or commands",
    },
    {
        "id": "unreviewed_agent_output",
        "severity": "high",
        "pattern": r"(?i)\b(apply|merge|execute|trust)\b.{0,80}\b(agent|model|llm|ai)\b.{0,80}\b(output|patch(?:es)?|changes?)\b.{0,80}\b(without|no)\b.{0,40}\b(review|verification|tests?)\b",
        "message": "agent context must not accept agent output without review or verification",
    },
    {
        "id": "unsafe_background_agent",
        "severity": "medium",
        "pattern": r"(?i)\b(run|keep|start)\b.{0,80}\b(background|daemon|persistent)\b.{0,80}\b(without|no)\b.{0,40}\b(approval|notice|reporting|review)\b",
        "message": "agent context should not authorize unreviewed background or persistent agent activity",
    },
    {
        "id": "unreviewed_suppression",
        "severity": "high",
        "pattern": r"(?i)\b(add|insert|use)\b.{0,80}\b(agent-guard:\s*allow|allowlist|suppression)\b.{0,80}\b(without|no)\b.{0,40}\b(review|approval)\b",
        "message": "agent context must not authorize unreviewed guard suppressions",
    },
]

_SAFE_NEGATION_RULE_IDS = frozenset(
    {
        "approval_bypass",
        "secret_prompt",
        "destructive_command",
        "disable_safety_tools",
        "ignore_test_failures",
        "delegate_policy_bypass",
        "unsafe_tool_auto_allow",
        "unreviewed_agent_output",
        "unsafe_background_agent",
        "unreviewed_suppression",
    }
)
_SAFE_NEGATION_BOUNDARY = re.compile(
    r"(?i)(?:[,.;!?]|\b(?:and|but|however|nor|or|then|while|yet)\b)"
)
_SAFE_NEGATION_INLINE_MARKUP = r"(?:[*_]{1,3}|`)?"
_SAFE_NEGATION_NEGATOR = (
    r"(?:never|do\s+not|don't|"
    r"(?:(?:(?:the\s+)?agents?|you)\s+)?(?:must|shall|should)\s+not)"
)
_SAFE_NEGATION_PREFIX_TEXT = (
    r"\s*(?:(?:[-*+>]|[0-9]+[.)])\s+)?"
    r"(?:[*_]{1,3})?"
    r"(?:(?:important|note|warning|caution)\s*:\s*)?"
    r"(?:[*_]{1,3})?\s*"
    rf"(?:please\s+)?{_SAFE_NEGATION_NEGATOR}\s+(?:ever\s+)?"
)
_SAFE_NEGATION_DIRECT_PREFIX = re.compile(
    rf"(?i){_SAFE_NEGATION_PREFIX_TEXT}{_SAFE_NEGATION_INLINE_MARKUP}"
)
_SAFE_NEGATION_COMMAND_PREFIX = re.compile(
    rf"(?i){_SAFE_NEGATION_PREFIX_TEXT}(?:(?:execute|invoke|run|use)\s+)?"
    rf"{_SAFE_NEGATION_INLINE_MARKUP}"
)
_SAFE_NEGATION_ANALYSIS_MARKUP = re.compile(r"[*_`]")
_SAFE_NEGATION_SENTENCE_BOUNDARY = re.compile(r"(?:[;!?]|(?<!\d)\.)")
_SAFE_NEGATION_CLAUSE_BOUNDARY = re.compile(
    r"(?i)(?:,\s*(?!provided\b)|\b(?:and|but|however|otherwise|then|while|yet)\b)"
)
_SAFE_NEGATION_ANY_ACTION = re.compile(
    r"(?i)\b(?:ask\s+another\s+agent|turn\s+off|always|automatically|"
    r"auto|provide|paste|enter|write|execute|invoke|run|git|rm|ignore|"
    r"hide|suppress|dismiss|bypass|disable|skip|delegate|handoff|"
    r"spawn\s+agent|subagent|apply|merge|trust|keep|start|add|insert|use)\b"
)
_SAFE_NEGATION_ATTRIBUTION_SOURCE = (
    r'(?:[A-Za-z0-9][A-Za-z0-9_-]*|"[^"\r\n]+"|\'[^\'\r\n]+\'|'
    r"\([^()\r\n]+\)|"
    r"\[[^\[\]\r\n]+\])"
)
_SAFE_NEGATION_SAFE_LEADING = re.compile(
    rf"(?i)(?:[\s,]*|\s*[0-9]+\.\s*|"
    rf"\s*provided\s+by(?:\s+|(?=[\"(\[]))"
    rf"{_SAFE_NEGATION_ATTRIBUTION_SOURCE}\s*,\s*)"
)
_SAFE_NEGATION_ATTRIBUTION_CLAUSE = re.compile(
    rf"(?i)\s*provided\s+by(?:\s+|(?=[\"(\[]))"
    rf"{_SAFE_NEGATION_ATTRIBUTION_SOURCE}\s*"
)
_SAFE_NEGATION_BENIGN_PRECEDING_CLAUSE = re.compile(
    r"(?i)\s*run\s+(?:the\s+)?tests?\s+first\s*"
)

_SAFE_NEGATION_APPROVAL_ACTION = (
    r"(?:(?:ignore|bypass|disable|skip)"
    r"(?:\s+(?:or|nor)\s+(?:ignore|bypass|disable|skip))*\s+"
    r"(?:(?:a|an|the|all|any)\s+)?"
    r"(?:approval|permission|policy)(?:\s+(?:checks?|gates?))?|"
    r"(?:ignore|bypass|disable|skip)"
    r"(?:\s+(?:or|nor)\s+(?:ignore|bypass|disable|skip))*\s+"
    r"(?:(?:a|an|the|all|any)\s+)?(?:guardrails?|safety\s+checks?)|"
    r"use\s+b\s+y\s+p\s+a\s+s\s+s\s+(?:for\s+)?"
    r"(?:(?:a|an|the|all|any)\s+)?"
    r"(?:approval|permission|policy|guardrails?|safety\s+checks?))"
)
_SAFE_NEGATION_SECRET_OBJECT = (
    r"(?:(?:a|an|the|any|this|that|your|our|their|plaintext|raw|"
    r"provided|requested)\s+)*"
    r"(?:api[_ -]?key|token|password|secret)"
)
_SAFE_NEGATION_SECRET_ACTION = (
    r"(?:(?:provide|paste|enter|write)"
    r"(?:\s+(?:or|nor)\s+(?:provide|paste|enter|write))*\s+"
    rf"{_SAFE_NEGATION_SECRET_OBJECT}"
    rf"(?:\s+(?:or|nor)\s+{_SAFE_NEGATION_SECRET_OBJECT})*"
    rf"(?:\s*,?\s*provided\s+by(?:\s+|(?=[\"(\[]))"
    rf"{_SAFE_NEGATION_ATTRIBUTION_SOURCE})?)"
)
_SAFE_NEGATION_DESTRUCTIVE_ACTION = (
    r"(?:(?:execute|invoke|run|use)\s+)?"
    r"(?:git\s+(?:reset\s+--hard|push\s+--force\b|clean\s+-f)|"
    r"rm\s+-rf\s+(?:/|~|/home|/mnt/c|[A-Za-z]:\\))"
)
_SAFE_NEGATION_DISABLE_OBJECT = (
    r"(?:(?:a|an|the|all|any)\s+)?"
    r"(?:agent-guard|agent-policy|safety\s+checks?|guardrails?|"
    r"policy\s+checks?|evidence\s+gate)"
)
_SAFE_NEGATION_DISABLE_ACTION = (
    r"(?:(?:disable|turn\s+off|skip|bypass)"
    r"(?:\s+(?:or|nor)\s+(?:disable|turn\s+off|skip|bypass))*\s+"
    rf"{_SAFE_NEGATION_DISABLE_OBJECT}"
    rf"(?:\s+(?:or|nor)\s+{_SAFE_NEGATION_DISABLE_OBJECT})*)"
)
_SAFE_NEGATION_IGNORE_FAILURE_ACTION = (
    r"(?:(?:ignore|hide|suppress|dismiss)"
    r"(?:\s+(?:or|nor)\s+(?:ignore|hide|suppress|dismiss))*\s+"
    r"(?:failing|failed|broken)\s+(?:tests?|checks?|ci|lint|build))"
)
_SAFE_NEGATION_DELEGATE_ACTION = (
    r"(?:(?:delegate(?:\s+to\s+(?:a|an|another|the)\s+agent)?|"
    r"handoff(?:\s+to\s+(?:a|an|another|the)\s+agent)?|"
    r"ask\s+another\s+agent|spawn\s+agent|subagent)"
    r"\s+(?:to\s+)?(?:bypass|avoid|skip)\s+(?:the\s+)?"
    r"(?:approval|policy|guardrail|review)(?:\s+(?:checks?|gates?))?)"
)
_SAFE_NEGATION_TOOL_ALLOW_ACTION = (
    r"(?:(?:always|automatically|auto)\s+(?:allow|approve|permit)\s+"
    r"(?:all|any)\s+(?:tools?|commands?|capabilities)"
    r"(?:\s+for\s+every\s+task)?)"
)
_SAFE_NEGATION_AGENT_OUTPUT_ACTION = (
    r"(?:(?:apply|merge|execute|trust)\s+"
    r"(?:(?:a|an|the|any|ai)\s+)*(?:agent|model|llm|ai)\s+"
    r"(?:output|patches?|changes?)\s+(?:without|no)\s+"
    r"(?:review|verification|tests?))"
)
_SAFE_NEGATION_BACKGROUND_ACTION = (
    r"(?:(?:run|keep|start)\s+(?:(?:a|an|the)\s+)?"
    r"(?:(?:persistent|background|daemon)\s+)*"
    r"(?:agent|activity|job|process)(?:\s+(?:running|active))?\s+"
    r"(?:without|no)\s+(?:approval|notice|reporting|review))"
)
_SAFE_NEGATION_SUPPRESSION_ACTION = (
    r"(?:(?:add|insert|use)\s+(?:(?:a|an|the)\s+)?"
    r"(?:agent-guard:\s*allow(?:\s+(?:allowlist|suppression))?|"
    r"allowlist|suppression)\s+(?:without|no)\s+(?:review|approval))"
)
_SAFE_NEGATION_RECOGNIZED_ACTION = (
    rf"(?:{_SAFE_NEGATION_APPROVAL_ACTION}|{_SAFE_NEGATION_SECRET_ACTION}|"
    rf"{_SAFE_NEGATION_DESTRUCTIVE_ACTION}|{_SAFE_NEGATION_DISABLE_ACTION}|"
    rf"{_SAFE_NEGATION_IGNORE_FAILURE_ACTION}|{_SAFE_NEGATION_DELEGATE_ACTION}|"
    rf"{_SAFE_NEGATION_TOOL_ALLOW_ACTION}|{_SAFE_NEGATION_AGENT_OUTPUT_ACTION}|"
    rf"{_SAFE_NEGATION_BACKGROUND_ACTION}|{_SAFE_NEGATION_SUPPRESSION_ACTION})"
)
_SAFE_NEGATION_STRENGTHENING_SUFFIX = (
    r"(?:\s+(?:under\s+any\s+circumstances|for\s+any\s+reason))?"
)
_SAFE_NEGATION_RECOGNIZED_BODY = re.compile(
    rf"(?i){_SAFE_NEGATION_RECOGNIZED_ACTION}"
    rf"(?:\s+(?:or|nor)\s+{_SAFE_NEGATION_RECOGNIZED_ACTION})*"
    rf"{_SAFE_NEGATION_STRENGTHENING_SUFFIX}\s*"
)
_SAFE_NEGATION_RECOGNIZED_ACTION_CLAUSE = re.compile(
    rf"(?i)\s*{_SAFE_NEGATION_RECOGNIZED_ACTION}\s*"
)

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
    _input_receipts: tuple[BoundedRepoReceipt, ...] = field(
        default=(),
        repr=False,
        compare=False,
    )
    _input_aliases: tuple[tuple[str, str], ...] = field(
        default=(),
        repr=False,
        compare=False,
    )

    @property
    def evidence_count(self) -> int:
        return sum(len(item.evidence) for item in self.context_files)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": CONTEXT_INVENTORY_SCHEMA_VERSION,
            "context_files": [item.to_dict() for item in self.context_files],
            "permission_boundaries": list(self.permission_boundaries),
        }


def _read_context_policy_text(
    path: Path,
    *,
    _input_budget: DistinctInputBudget | None = None,
) -> str:
    try:
        opened = read_bounded_bytes(path, max_bytes=MAX_CONTEXT_POLICY_BYTES)
        if _input_budget is not None:
            _input_budget.charge(opened)
        raw = opened.data
    except BoundedRepoFileNotFoundError:
        raise FileNotFoundError(f"{ERROR_CONTEXT_POLICY_NOT_FOUND}: {path}") from None
    except BoundedRepoLimitError:
        raise ValueError(ERROR_CONTEXT_POLICY_LIMIT) from None
    except (BoundedRepoContainmentError, BoundedRepoReadError):
        raise ValueError(ERROR_CONTEXT_POLICY_INVALID) from None
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError(ERROR_CONTEXT_POLICY_INVALID) from None


def load_context_policy(
    path: Path,
    *,
    _input_budget: DistinctInputBudget | None = None,
) -> dict[str, object]:
    try:
        loaded = load_bounded_yaml(
            _read_context_policy_text(path, _input_budget=_input_budget),
            construct=yaml.safe_load,
        )
        if loaded is None:
            loaded = {}
        if not isinstance(loaded, dict):
            raise BoundedYamlInvalidError
    except BoundedYamlLimitError:
        raise ValueError(ERROR_CONTEXT_POLICY_LIMIT) from None
    except BoundedYamlInvalidError:
        raise ValueError(ERROR_CONTEXT_POLICY_INVALID) from None
    except (MemoryError, OverflowError, RecursionError):
        raise ValueError(ERROR_CONTEXT_POLICY_LIMIT) from None
    return loaded


def normalize_string_list(
    values: Any,
    *,
    limit: int = MAX_CONTEXT_POLICY_LIST_ITEMS,
) -> list[str]:
    if not isinstance(values, list):
        raise ValueError(ERROR_CONTEXT_POLICY_INVALID)
    if len(values) > limit:
        raise ValueError(ERROR_CONTEXT_POLICY_LIMIT)
    out: list[str] = []
    for value in values:
        if not isinstance(value, str):
            raise ValueError(ERROR_CONTEXT_POLICY_INVALID)
        text = value.strip()
        if len(text) > MAX_CONTEXT_GLOB_LENGTH:
            raise ValueError(ERROR_CONTEXT_POLICY_LIMIT)
        if text:
            out.append(text)
    return out


def policy_section(policy: dict[str, object]) -> dict[str, object]:
    raw = policy.get("policy", {})
    if not isinstance(raw, dict):
        raise ValueError(ERROR_CONTEXT_POLICY_INVALID)
    return raw


def scan_section(policy: dict[str, object]) -> dict[str, object]:
    raw = policy.get("scan", {})
    if not isinstance(raw, dict):
        raise ValueError(ERROR_CONTEXT_POLICY_INVALID)
    return raw


def has_glob_magic(pattern: str) -> bool:
    return any(char in pattern for char in "*?[")


@dataclass(frozen=True)
class GlobPattern:
    parts: tuple[str, ...]
    component_regexes: tuple[re.Pattern[str] | None, ...]
    globstar_count: int
    globstar_index: int | None


class _ContextGlobWorkBudget:
    def __init__(self) -> None:
        self.used = 0

    def charge(self) -> None:
        if self.used >= MAX_CONTEXT_GLOB_WORK_UNITS:
            raise ValueError(ERROR_CONTEXT_SCAN_LIMIT)
        self.used += 1


def _compile_glob_pattern(pattern: str) -> GlobPattern:
    if len(pattern) > MAX_CONTEXT_GLOB_LENGTH:
        raise ValueError(ERROR_CONTEXT_POLICY_LIMIT)
    parts = tuple(Path(pattern).parts)
    if len(parts) > MAX_CONTEXT_GLOB_COMPONENTS:
        raise ValueError(ERROR_CONTEXT_POLICY_LIMIT)
    if os.name == "nt":
        parts = tuple(part.casefold() for part in parts)
    try:
        component_regexes = tuple(
            None if part == "**" else re.compile(fnmatch.translate(part))
            for part in parts
        )
    except re.error:
        raise ValueError(ERROR_CONTEXT_POLICY_LIMIT) from None
    globstar_count = parts.count("**")
    return GlobPattern(
        parts=parts,
        component_regexes=component_regexes,
        globstar_count=globstar_count,
        globstar_index=parts.index("**") if globstar_count == 1 else None,
    )


def _path_parts(path: Path) -> tuple[str, ...]:
    parts = tuple(path.parts)
    if os.name == "nt":
        return tuple(part.casefold() for part in parts)
    return parts


def _component_matches(
    path_part: str,
    pattern: GlobPattern,
    pattern_index: int,
    *,
    work_budget: _ContextGlobWorkBudget | None,
) -> bool:
    if work_budget is not None:
        work_budget.charge()
    regex = pattern.component_regexes[pattern_index]
    return regex is not None and regex.fullmatch(path_part) is not None


def _glob_parts_match(
    path_parts: tuple[str, ...],
    pattern_parts: GlobPattern,
    *,
    work_budget: _ContextGlobWorkBudget | None = None,
) -> bool:
    if work_budget is not None:
        work_budget.charge()
    parts = pattern_parts.parts
    if not parts:
        return False
    if pattern_parts.globstar_count == 0:
        if len(parts) > len(path_parts):
            return False
        return all(
            _component_matches(
                path_part,
                pattern_parts,
                pattern_index,
                work_budget=work_budget,
            )
            for pattern_index, path_part in enumerate(
                path_parts[-len(parts) :],
            )
        )
    if pattern_parts.globstar_count == 1:
        globstar = pattern_parts.globstar_index
        assert globstar is not None
        prefix = parts[:globstar]
        suffix = parts[globstar + 1 :]
        if len(suffix) > len(path_parts):
            return False
        if suffix and not all(
            _component_matches(
                path_part,
                pattern_parts,
                globstar + 1 + suffix_index,
                work_budget=work_budget,
            )
            for suffix_index, path_part in enumerate(
                path_parts[-len(suffix) :],
            )
        ):
            return False
        prefix_end = len(path_parts) - len(suffix)
        if not prefix:
            return True
        for start in range(prefix_end - len(prefix), -1, -1):
            if all(
                _component_matches(
                    path_part,
                    pattern_parts,
                    pattern_index,
                    work_budget=work_budget,
                )
                for pattern_index, path_part in enumerate(
                    path_parts[start : start + len(prefix)],
                )
            ):
                return True
        return False

    pending = [(len(path_parts), len(parts))]
    seen: set[tuple[int, int]] = set()
    while pending:
        path_count, pattern_count = pending.pop()
        state = (path_count, pattern_count)
        if state in seen:
            continue
        seen.add(state)
        if work_budget is not None:
            work_budget.charge()
        if pattern_count == 0:
            return True
        pattern_part = parts[pattern_count - 1]
        if pattern_part == "**":
            pending.append((path_count, pattern_count - 1))
            if path_count:
                pending.append((path_count - 1, pattern_count))
            continue
        if path_count and _component_matches(
            path_parts[path_count - 1],
            pattern_parts,
            pattern_count - 1,
            work_budget=work_budget,
        ):
            pending.append((path_count - 1, pattern_count - 1))
    return False


def glob_matches(path: Path, pattern: str) -> bool:
    return _glob_parts_match(
        _path_parts(path),
        _compile_glob_pattern(pattern),
        work_budget=_ContextGlobWorkBudget(),
    )


def is_excluded(rel_path: Path, exclude: Iterable[str]) -> bool:
    path_parts = _path_parts(rel_path)
    work_budget = _ContextGlobWorkBudget()
    return any(
        _glob_parts_match(
            path_parts,
            _compile_glob_pattern(pattern),
            work_budget=work_budget,
        )
        for pattern in exclude
    )


def _is_excluded_compiled(
    rel_path: Path,
    exclude: Sequence[GlobPattern],
    *,
    work_budget: _ContextGlobWorkBudget,
) -> bool:
    path_parts = _path_parts(rel_path)
    return any(
        _glob_parts_match(path_parts, pattern, work_budget=work_budget)
        for pattern in exclude
    )


def _relative_path_is_opaque(
    path: Path,
    opaque_directories: Sequence[str],
) -> bool:
    relative = path.as_posix()
    return any(
        relative == opaque or relative.startswith(f"{opaque.rstrip('/')}/")
        for opaque in opaque_directories
    )


def _directory_is_excluded(
    path: Path,
    exclude: Sequence[GlobPattern],
    *,
    work_budget: _ContextGlobWorkBudget,
) -> bool:
    return _is_excluded_compiled(
        path,
        exclude,
        work_budget=work_budget,
    ) or _is_excluded_compiled(
        path / "__agent_guard_probe__",
        exclude,
        work_budget=work_budget,
    )


def _has_excluded_ancestor(
    path: Path,
    exclude: Sequence[GlobPattern],
    *,
    work_budget: _ContextGlobWorkBudget,
) -> bool:
    for parent in path.parents:
        if parent == Path("."):
            break
        if _directory_is_excluded(
            parent,
            exclude,
            work_budget=work_budget,
        ):
            return True
    return False


def _is_within_relative_path(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def _context_candidate_matches(
    *,
    alias_path: Path,
    resolved_path: Path,
    include: Sequence[GlobPattern],
    literal_files: Sequence[tuple[Path, Path]],
    literal_directories: Sequence[tuple[Path, Path]],
    work_budget: _ContextGlobWorkBudget,
) -> bool:
    for pattern in include:
        if _glob_parts_match(
            _path_parts(alias_path),
            pattern,
            work_budget=work_budget,
        ) or _glob_parts_match(
            _path_parts(resolved_path),
            pattern,
            work_budget=work_budget,
        ):
            return True
    if any(
        alias_path == alias_file or resolved_path == resolved_file
        for alias_file, resolved_file in literal_files
    ):
        return True
    return any(
        _is_within_relative_path(alias_path, alias_root)
        or _is_within_relative_path(resolved_path, resolved_root)
        for alias_root, resolved_root in literal_directories
    )


def _alias_context_candidate_matches(
    path: Path,
    *,
    include: Sequence[GlobPattern],
    literal_files: Sequence[tuple[Path, Path]],
    literal_directories: Sequence[tuple[Path, Path]],
    work_budget: _ContextGlobWorkBudget,
) -> bool:
    path_parts = _path_parts(path)
    return any(
        _glob_parts_match(path_parts, pattern, work_budget=work_budget)
        for pattern in include
    ) or any(
        path == alias_file
        for alias_file, _resolved_file in literal_files
    ) or any(
        _is_within_relative_path(path, alias_root)
        for alias_root, _resolved_root in literal_directories
    )


def _append_context_file(
    files: list[Path],
    seen_files: set[Path],
    *,
    path: Path,
    resolved_path: Path,
) -> None:
    if resolved_path in seen_files:
        return
    if len(files) >= MAX_CONTEXT_SCAN_FILES:
        raise ValueError(ERROR_CONTEXT_SCAN_LIMIT)
    seen_files.add(resolved_path)
    files.append(path)


def _compile_context_selection(
    *,
    root: Path,
    include: Sequence[str],
    exclude: Sequence[str],
    opaque_directories: Sequence[str],
) -> tuple[
    tuple[GlobPattern, ...],
    tuple[GlobPattern, ...],
    tuple[tuple[Path, Path], ...],
    tuple[tuple[Path, Path], ...],
]:
    compiled_include: list[GlobPattern] = []
    for pattern in include:
        compiled_pattern = _compile_glob_pattern(pattern)
        if has_glob_magic(pattern):
            compiled_include.append(compiled_pattern)
    compiled_exclude = tuple(_compile_glob_pattern(pattern) for pattern in exclude)
    selection_work_budget = _ContextGlobWorkBudget()
    literal_files: list[tuple[Path, Path]] = []
    literal_directories: list[tuple[Path, Path]] = []
    for pattern in include:
        if has_glob_magic(pattern):
            continue
        literal_path = Path(pattern)
        if _relative_path_is_opaque(literal_path, opaque_directories):
            continue
        if _directory_is_excluded(
            literal_path,
            compiled_exclude,
            work_budget=selection_work_budget,
        ) or _has_excluded_ancestor(
            literal_path,
            compiled_exclude,
            work_budget=selection_work_budget,
        ):
            continue
        target = root / literal_path
        try:
            resolved_target = target.resolve(strict=True)
            resolved_relative = resolved_target.relative_to(root)
        except ValueError:
            raise ValueError(ERROR_CONTEXT_SCAN_TARGET) from None
        except (OSError, RuntimeError):
            try:
                target.lstat()
            except FileNotFoundError:
                continue
            except (OSError, RuntimeError):
                raise ValueError(ERROR_CONTEXT_SCAN_TARGET) from None
            raise ValueError(ERROR_CONTEXT_SCAN_TARGET) from None
        try:
            target_stat = target.stat()
        except (OSError, RuntimeError):
            raise ValueError(ERROR_CONTEXT_SCAN_TARGET) from None
        if stat.S_ISDIR(target_stat.st_mode) and not (
            _relative_path_is_opaque(Path(pattern), opaque_directories)
            or _relative_path_is_opaque(resolved_relative, opaque_directories)
        ):
            literal_directories.append((literal_path, resolved_relative))
        elif stat.S_ISREG(target_stat.st_mode) and not _relative_path_is_opaque(
            resolved_relative,
            opaque_directories,
        ):
            literal_files.append((literal_path, resolved_relative))
    return (
        tuple(compiled_include),
        compiled_exclude,
        tuple(literal_files),
        tuple(literal_directories),
    )


def _context_selector_patterns(
    policy: dict[str, object],
) -> tuple[list[str], list[str]]:
    scan_cfg = scan_section(policy)
    include = normalize_string_list(scan_cfg.get("include", [])) or DEFAULT_INCLUDE
    exclude = [*DEFAULT_EXCLUDE, *normalize_string_list(scan_cfg.get("exclude", []))]
    return include, exclude


def _iter_context_files_pruned(
    *,
    root: Path,
    include: Sequence[str],
    exclude: Sequence[str],
    opaque_directories: Sequence[str],
) -> list[Path]:
    (
        compiled_include,
        compiled_exclude,
        literal_files,
        literal_directories,
    ) = _compile_context_selection(
        root=root,
        include=include,
        exclude=exclude,
        opaque_directories=opaque_directories,
    )
    glob_work_budget = _ContextGlobWorkBudget()

    files: list[Path] = []
    seen_files: set[Path] = set()
    for alias_relative, _resolved_relative in literal_files:
        path = root / alias_relative
        if _relative_path_is_opaque(alias_relative, opaque_directories):
            continue
        if _directory_is_excluded(
            alias_relative,
            compiled_exclude,
            work_budget=glob_work_budget,
        ) or _has_excluded_ancestor(
            alias_relative,
            compiled_exclude,
            work_budget=glob_work_budget,
        ):
            continue
        try:
            resolved_path = path.resolve(strict=True)
            resolved_relative = resolved_path.relative_to(root)
        except ValueError:
            raise ValueError(ERROR_CONTEXT_SCAN_TARGET) from None
        except (OSError, RuntimeError):
            raise ValueError(ERROR_CONTEXT_SCAN_TARGET) from None
        if _relative_path_is_opaque(resolved_relative, opaque_directories):
            continue
        if _is_excluded_compiled(
            resolved_relative,
            compiled_exclude,
            work_budget=glob_work_budget,
        ) or _has_excluded_ancestor(
            resolved_relative,
            compiled_exclude,
            work_budget=glob_work_budget,
        ):
            continue
        try:
            path_stat = path.stat()
        except (OSError, RuntimeError):
            raise ValueError(ERROR_CONTEXT_SCAN_TARGET) from None
        if not stat.S_ISREG(path_stat.st_mode):
            continue
        _append_context_file(
            files,
            seen_files,
            path=path,
            resolved_path=resolved_path,
        )

    if not compiled_include and not literal_directories:
        return sorted(files)

    visited_entries = 0
    pending: list[tuple[Path, frozenset[Path]]] = [(root, frozenset())]
    while pending:
        current, ancestors = pending.pop()
        try:
            resolved_current = current.resolve(strict=True)
            resolved_current.relative_to(root)
        except ValueError:
            raise ValueError(ERROR_CONTEXT_SCAN_TARGET) from None
        except (OSError, RuntimeError):
            raise ValueError(ERROR_CONTEXT_SCAN_TARGET) from None
        if resolved_current in ancestors:
            continue
        child_ancestors = ancestors | {resolved_current}
        children: list[Path] = []
        try:
            with os.scandir(current) as entries:
                for entry in entries:
                    if visited_entries >= MAX_CONTEXT_SCAN_FILES:
                        raise ValueError(ERROR_CONTEXT_SCAN_LIMIT)
                    visited_entries += 1
                    children.append(current / entry.name)
        except ValueError:
            raise
        except OSError:
            raise ValueError(ERROR_CONTEXT_SCAN_TARGET) from None
        for path in sorted(children, reverse=True):
            try:
                alias_relative = path.relative_to(root)
            except ValueError:
                raise ValueError(ERROR_CONTEXT_SCAN_TARGET) from None
            if _relative_path_is_opaque(alias_relative, opaque_directories):
                continue
            if _directory_is_excluded(
                alias_relative,
                compiled_exclude,
                work_budget=glob_work_budget,
            ) or _is_excluded_compiled(
                alias_relative,
                compiled_exclude,
                work_budget=glob_work_budget,
            ):
                continue
            try:
                resolved_path = path.resolve(strict=True)
                resolved_relative = resolved_path.relative_to(root)
            except ValueError:
                if _alias_context_candidate_matches(
                    path=alias_relative,
                    include=compiled_include,
                    literal_files=literal_files,
                    literal_directories=literal_directories,
                    work_budget=glob_work_budget,
                ):
                    raise ValueError(ERROR_CONTEXT_SCAN_TARGET) from None
                continue
            except (OSError, RuntimeError):
                if _alias_context_candidate_matches(
                    path=alias_relative,
                    include=compiled_include,
                    literal_files=literal_files,
                    literal_directories=literal_directories,
                    work_budget=glob_work_budget,
                ):
                    raise ValueError(ERROR_CONTEXT_SCAN_TARGET) from None
                continue
            if _relative_path_is_opaque(resolved_relative, opaque_directories):
                continue
            try:
                path_stat = path.stat()
            except (OSError, RuntimeError):
                if _context_candidate_matches(
                    alias_path=alias_relative,
                    resolved_path=resolved_relative,
                    include=compiled_include,
                    literal_files=literal_files,
                    literal_directories=literal_directories,
                    work_budget=glob_work_budget,
                ):
                    raise ValueError(ERROR_CONTEXT_SCAN_TARGET) from None
                continue
            is_directory = stat.S_ISDIR(path_stat.st_mode)
            is_file = stat.S_ISREG(path_stat.st_mode)
            if is_directory:
                if _directory_is_excluded(
                    alias_relative,
                    compiled_exclude,
                    work_budget=glob_work_budget,
                ) or _directory_is_excluded(
                    resolved_relative,
                    compiled_exclude,
                    work_budget=glob_work_budget,
                ):
                    continue
                pending.append((path, child_ancestors))
                continue
            if not is_file or _is_excluded_compiled(
                resolved_relative,
                compiled_exclude,
                work_budget=glob_work_budget,
            ):
                continue
            if not _context_candidate_matches(
                alias_path=alias_relative,
                resolved_path=resolved_relative,
                include=compiled_include,
                literal_files=literal_files,
                literal_directories=literal_directories,
                work_budget=glob_work_budget,
            ):
                continue
            _append_context_file(
                files,
                seen_files,
                path=path,
                resolved_path=resolved_path,
            )
    return sorted(files)


def iter_context_files(
    *,
    root: Path,
    policy: dict[str, object],
    opaque_directories: Sequence[str] = (),
) -> list[Path]:
    try:
        root = root.resolve(strict=True)
    except (OSError, RuntimeError):
        raise ValueError(ERROR_CONTEXT_SCAN_TARGET) from None
    include, exclude = _context_selector_patterns(policy)
    return _iter_context_files_pruned(
        root=root,
        include=include,
        exclude=exclude,
        opaque_directories=opaque_directories,
    )


def _validate_context_snapshot_selection(
    *,
    root: Path,
    alias_path: Path,
    opened: BoundedRepoFile,
    compiled_include: Sequence[GlobPattern],
    compiled_exclude: Sequence[GlobPattern],
    literal_files: Sequence[tuple[Path, Path]],
    literal_directories: Sequence[tuple[Path, Path]],
    opaque_directories: Sequence[str],
    work_budget: _ContextGlobWorkBudget,
) -> tuple[str, str]:
    try:
        alias_relative = Path(os.path.abspath(alias_path)).relative_to(root)
    except ValueError:
        raise ValueError(ERROR_CONTEXT_SCAN_TARGET) from None
    resolved_relative = Path(opened.relative_path)
    if (
        _relative_path_is_opaque(alias_relative, opaque_directories)
        or _relative_path_is_opaque(resolved_relative, opaque_directories)
        or _is_excluded_compiled(
            alias_relative,
            compiled_exclude,
            work_budget=work_budget,
        )
        or _is_excluded_compiled(
            resolved_relative,
            compiled_exclude,
            work_budget=work_budget,
        )
        or _has_excluded_ancestor(
            alias_relative,
            compiled_exclude,
            work_budget=work_budget,
        )
        or _has_excluded_ancestor(
            resolved_relative,
            compiled_exclude,
            work_budget=work_budget,
        )
        or not _context_candidate_matches(
            alias_path=alias_relative,
            resolved_path=resolved_relative,
            include=compiled_include,
            literal_files=literal_files,
            literal_directories=literal_directories,
            work_budget=work_budget,
        )
    ):
        raise ValueError(ERROR_CONTEXT_SCAN_TARGET)
    return opened.relative_path, alias_relative.as_posix()


def normalize_rule_patterns(policy: dict[str, object]) -> list[dict[str, object]]:
    cfg = policy_section(policy)
    raw_forbidden = cfg.get("forbidden_patterns", DEFAULT_FORBIDDEN_PATTERNS)
    if not isinstance(raw_forbidden, list):
        raise ValueError(ERROR_CONTEXT_POLICY_INVALID)

    raw_extra = cfg.get("extra_forbidden_patterns", [])
    if raw_extra is None:
        raw_extra = []
    if not isinstance(raw_extra, list):
        raise ValueError(ERROR_CONTEXT_POLICY_INVALID)

    return [*raw_forbidden, *raw_extra]


def build_rules(policy: dict[str, object]) -> list[dict[str, object]]:
    rules: list[dict[str, object]] = []
    cfg = policy_section(policy)
    uses_default_patterns = "forbidden_patterns" not in cfg
    raw_rules = normalize_rule_patterns(policy)
    if len(raw_rules) > MAX_CONTEXT_POLICY_REGEX_COUNT:
        raise ValueError(ERROR_CONTEXT_POLICY_LIMIT)
    for rule_index, item in enumerate(raw_rules):
        if not isinstance(item, dict):
            raise ValueError(ERROR_CONTEXT_POLICY_INVALID)
        raw_rule_id = item.get("id", "")
        raw_pattern = item.get("pattern", "")
        raw_severity = item.get("severity", "high")
        raw_message = item.get("message", "policy violation")
        if not all(
            isinstance(value, str)
            for value in (raw_rule_id, raw_pattern, raw_severity, raw_message)
        ):
            raise ValueError(ERROR_CONTEXT_POLICY_INVALID)
        rule_id = raw_rule_id.strip()
        pattern_text = raw_pattern.strip()
        if not rule_id or not pattern_text:
            continue
        if len(pattern_text) > MAX_CONTEXT_POLICY_REGEX_LENGTH:
            raise ValueError(ERROR_CONTEXT_POLICY_LIMIT)
        try:
            regex = re.compile(pattern_text)
        except (OverflowError, RecursionError, re.error):
            raise ValueError(ERROR_CONTEXT_POLICY_INVALID) from None
        rules.append(
            {
                "id": rule_id,
                "severity": raw_severity.strip() or "high",
                "message": raw_message.strip() or "policy violation",
                "regex": regex,
                "default_rule": (
                    uses_default_patterns
                    and rule_index < len(DEFAULT_FORBIDDEN_PATTERNS)
                ),
                "safe_negation": (
                    uses_default_patterns
                    and rule_index < len(DEFAULT_FORBIDDEN_PATTERNS)
                    and rule_id in _SAFE_NEGATION_RULE_IDS
                ),
            }
        )
    return rules


def read_text(
    path: Path,
    *,
    root: Path | None = None,
    max_bytes: int = MAX_CONTEXT_FILE_BYTES,
) -> str | None:
    try:
        allowed_root = path.parent if root is None else root
        data = read_repo_bound_bytes(path, allowed_root, max_bytes=max_bytes).data
    except BoundedRepoLimitError:
        raise ValueError(ERROR_CONTEXT_SCAN_LIMIT) from None
    except BoundedRepoContainmentError:
        raise ValueError(ERROR_CONTEXT_SCAN_TARGET) from None
    except (BoundedRepoFileNotFoundError, BoundedRepoReadError):
        raise ValueError(ERROR_CONTEXT_SCAN_TARGET) from None
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if "\x00" in text:
        return None
    return text


def display_path(path: Path, root: Path) -> str:
    try:
        return path.resolve(strict=True).relative_to(root.resolve(strict=True)).as_posix()
    except (OSError, RuntimeError, ValueError):
        try:
            return Path(path).absolute().relative_to(Path(root).absolute()).as_posix()
        except (OSError, ValueError):
            return path.name or "<context-file>"


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


def _read_inventory_file(
    path: Path,
    *,
    root: Path | None = None,
    max_bytes: int = MAX_CONTEXT_FILE_BYTES,
) -> BoundedRepoFile:
    try:
        allowed_root = path.parent if root is None else root
        return read_repo_bound_bytes(path, allowed_root, max_bytes=max_bytes)
    except BoundedRepoLimitError:
        raise ValueError(ERROR_CONTEXT_SCAN_LIMIT) from None
    except BoundedRepoContainmentError:
        raise ValueError(ERROR_CONTEXT_SCAN_TARGET) from None
    except (BoundedRepoFileNotFoundError, BoundedRepoReadError):
        raise ValueError(ERROR_CONTEXT_SCAN_TARGET) from None


def read_inventory_bytes(
    path: Path,
    *,
    root: Path | None = None,
    max_bytes: int = MAX_CONTEXT_FILE_BYTES,
) -> bytes:
    return _read_inventory_file(path, root=root, max_bytes=max_bytes).data


def read_inventory_text(
    path: Path,
    *,
    root: Path | None = None,
    max_bytes: int = MAX_CONTEXT_FILE_BYTES,
    _input_budget: DistinctInputBudget | None = None,
) -> tuple[ReadStatus, bytes, str | None]:
    read_status, opened, text = _read_inventory_snapshot(
        path,
        root=root,
        max_bytes=max_bytes,
        _input_budget=_input_budget,
    )
    return read_status, opened.data, text


def _read_inventory_snapshot(
    path: Path,
    *,
    root: Path | None = None,
    max_bytes: int = MAX_CONTEXT_FILE_BYTES,
    _input_budget: DistinctInputBudget | None = None,
) -> tuple[ReadStatus, BoundedRepoFile, str | None]:
    opened = _read_inventory_file(path, root=root, max_bytes=max_bytes)
    data = opened.data
    if _input_budget is not None:
        try:
            _input_budget.charge(opened)
        except BoundedRepoLimitError:
            raise ValueError(ERROR_CONTEXT_SCAN_LIMIT) from None
        except BoundedRepoReadError:
            raise ValueError(ERROR_CONTEXT_SCAN_TARGET) from None
    if b"\x00" in data:
        return "binary", opened, None
    try:
        return "scanned", opened, data.decode("utf-8")
    except UnicodeDecodeError:
        return "decode_error", opened, None


def evidence_id(*, category: str, rule_id: str, rel_path: str, line: int) -> str:
    return f"{category}:{rel_path}:{line}:{rule_id}"


def collect_context_evidence(
    *,
    rel_path: str,
    text: str,
    _result_budget: _ContextInventoryResultBudget | None = None,
) -> tuple[ContextEvidence, ...]:
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
            item = ContextEvidence(
                evidence_id=evidence_id(category=category, rule_id=rule_id, rel_path=rel_path, line=lineno),
                category=category,
                rule_id=rule_id,
                line=lineno,
            )
            if _result_budget is not None:
                _result_budget.add_evidence(item, entry_evidence_count=len(evidence))
            evidence.append(item)
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


def _canonical_json_size(value: object) -> int:
    return len(
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8", errors="surrogatepass")
    )


class _ContextInventoryResultBudget:
    """Track the exact compact-JSON size of inventory-owned public fields."""

    def __init__(self) -> None:
        empty_inventory = ContextInventory(
            context_files=(),
            permission_boundaries=boundary_summary(()),
        )
        self.used = _canonical_json_size(empty_inventory.to_dict())
        self.entry_count = 0
        self.evidence_counts = {category: 0 for category in BOUNDARY_CATEGORIES}
        if self.used > MAX_CONTEXT_AGGREGATE_RESULT_BYTES:
            raise ValueError(ERROR_CONTEXT_SCAN_LIMIT)

    def _consume(self, amount: int) -> None:
        if amount > MAX_CONTEXT_AGGREGATE_RESULT_BYTES - self.used:
            raise ValueError(ERROR_CONTEXT_SCAN_LIMIT)
        self.used += amount

    def add_entry(self, entry: ContextInventoryEntry) -> None:
        self._consume(_canonical_json_size(entry.to_dict()) + (1 if self.entry_count else 0))
        self.entry_count += 1

    def add_evidence(self, item: ContextEvidence, *, entry_evidence_count: int) -> None:
        entry_delta = _canonical_json_size(item.to_dict()) + (1 if entry_evidence_count else 0)
        category_count = self.evidence_counts[item.category]
        boundary_delta = _canonical_json_size(item.evidence_id) + (1 if category_count else 0)
        self._consume(entry_delta + boundary_delta)
        self.evidence_counts[item.category] = category_count + 1


class _ContextFindingResultBudget:
    def __init__(self) -> None:
        self.used = _canonical_json_size([])
        self.count = 0
        if self.used > MAX_CONTEXT_AGGREGATE_RESULT_BYTES:
            raise ValueError(ERROR_CONTEXT_SCAN_LIMIT)

    def add(self, finding: ContextGuardFinding) -> None:
        amount = _canonical_json_size(finding.to_dict()) + (1 if self.count else 0)
        if amount > MAX_CONTEXT_AGGREGATE_RESULT_BYTES - self.used:
            raise ValueError(ERROR_CONTEXT_SCAN_LIMIT)
        self.used += amount
        self.count += 1


def collect_context_inventory(
    *,
    root: Path,
    policy: dict[str, object],
    opaque_directories: Sequence[str] = (),
    _input_budget: DistinctInputBudget | None = None,
) -> ContextInventory:
    root = root.resolve()
    entries: list[ContextInventoryEntry] = []
    input_budget = _input_budget or DistinctInputBudget(
        max_bytes=MAX_CONTEXT_DISTINCT_INPUT_BYTES
    )
    result_budget = _ContextInventoryResultBudget()
    receipts: list[BoundedRepoReceipt] = []
    aliases: list[tuple[str, str]] = []
    paths = iter_context_files(
        root=root,
        policy=policy,
        opaque_directories=opaque_directories,
    )
    include, exclude = _context_selector_patterns(policy)
    (
        compiled_include,
        compiled_exclude,
        literal_files,
        literal_directories,
    ) = _compile_context_selection(
        root=root,
        include=include,
        exclude=exclude,
        opaque_directories=opaque_directories,
    )
    selection_work_budget = _ContextGlobWorkBudget()
    for path in paths:
        read_status, opened, text = _read_inventory_snapshot(
            path,
            root=root,
            max_bytes=MAX_CONTEXT_FILE_BYTES,
            _input_budget=input_budget,
        )
        rel, alias_path = _validate_context_snapshot_selection(
            root=root,
            alias_path=path,
            opened=opened,
            compiled_include=compiled_include,
            compiled_exclude=compiled_exclude,
            literal_files=literal_files,
            literal_directories=literal_directories,
            opaque_directories=opaque_directories,
            work_budget=selection_work_budget,
        )
        data = opened.data
        receipts.append(opened.receipt())
        aliases.append((opened.relative_path, alias_path))
        line_count = len(text.splitlines()) if text is not None else None
        empty_entry = ContextInventoryEntry(
            path=rel,
            kind=context_kind(rel),
            read_status=read_status,
            size_bytes=len(data),
            line_count=line_count,
            evidence=(),
        )
        result_budget.add_entry(empty_entry)
        evidence = (
            collect_context_evidence(
                rel_path=rel,
                text=text,
                _result_budget=result_budget,
            )
            if text is not None
            else ()
        )
        entries.append(
            ContextInventoryEntry(
                path=empty_entry.path,
                kind=empty_entry.kind,
                read_status=empty_entry.read_status,
                size_bytes=empty_entry.size_bytes,
                line_count=empty_entry.line_count,
                evidence=evidence,
            )
        )

    context_files = tuple(sorted(entries, key=lambda item: item.path))
    inventory = ContextInventory(
        context_files=context_files,
        permission_boundaries=boundary_summary(context_files),
        _input_receipts=tuple(sorted(receipts, key=lambda item: item.relative_path)),
        _input_aliases=tuple(sorted(aliases)),
    )
    if _canonical_json_size(inventory.to_dict()) > MAX_CONTEXT_AGGREGATE_RESULT_BYTES:
        raise ValueError(ERROR_CONTEXT_SCAN_LIMIT)
    return inventory


def _safe_negation_prefix_is_complete(
    segment: str,
    *,
    action_start: int,
) -> bool:
    clause_start = 0
    for boundary in _SAFE_NEGATION_BOUNDARY.finditer(
        segment,
        0,
        action_start,
    ):
        clause_start = boundary.end()

    if _SAFE_NEGATION_SAFE_LEADING.fullmatch(segment, 0, clause_start) is None:
        return False
    return bool(
        _SAFE_NEGATION_DIRECT_PREFIX.fullmatch(
            segment,
            clause_start,
            action_start,
        )
        or _SAFE_NEGATION_COMMAND_PREFIX.fullmatch(
            segment,
            clause_start,
            action_start,
        )
    )


def _segment_is_complete_unconditional_prohibition(segment: str) -> bool:
    action = _SAFE_NEGATION_ANY_ACTION.search(segment)
    if action is None or not _safe_negation_prefix_is_complete(
        segment,
        action_start=action.start(),
    ):
        return False
    return (
        _SAFE_NEGATION_RECOGNIZED_BODY.fullmatch(
            segment,
            action.start(),
        )
        is not None
    )


def _iter_safe_negation_clauses(line: str) -> Iterable[str]:
    for sentence in _SAFE_NEGATION_SENTENCE_BOUNDARY.split(line):
        yield from _SAFE_NEGATION_CLAUSE_BOUNDARY.split(sentence)


def _is_safe_attribution_clause(clause: str) -> bool:
    return _SAFE_NEGATION_ATTRIBUTION_CLAUSE.fullmatch(clause) is not None


def _is_benign_preceding_clause(clause: str) -> bool:
    return _SAFE_NEGATION_BENIGN_PRECEDING_CLAUSE.fullmatch(clause) is not None


def _line_is_complete_unconditional_prohibitions(line: str) -> bool:
    normalized = _SAFE_NEGATION_ANALYSIS_MARKUP.sub(
        "",
        line.replace("\u2019", "'"),
    )
    saw_prohibition = False
    segment_cache: dict[str, bool] = {}
    for clause in _iter_safe_negation_clauses(normalized):
        if not clause.strip() or _is_safe_attribution_clause(clause):
            continue
        if not saw_prohibition and _is_benign_preceding_clause(clause):
            continue
        is_complete = segment_cache.get(clause)
        if is_complete is None:
            is_complete = _segment_is_complete_unconditional_prohibition(clause)
            segment_cache[clause] = is_complete
        if not is_complete:
            return False
        saw_prohibition = True
    return saw_prohibition


def _safe_negation_is_complete(
    line: str,
    *,
    regex: re.Pattern[str],
) -> bool:
    normalized = _SAFE_NEGATION_ANALYSIS_MARKUP.sub(
        "",
        line.replace("\u2019", "'"),
    )
    saw_rule_match = False
    clause_cache: dict[str, tuple[bool, bool, bool]] = {}
    for clause in _iter_safe_negation_clauses(normalized):
        if not clause.strip() or _is_safe_attribution_clause(clause):
            continue
        if not saw_rule_match and _is_benign_preceding_clause(clause):
            continue
        cached = clause_cache.get(clause)
        if cached is None:
            has_rule_match = regex.search(clause) is not None
            is_complete = _segment_is_complete_unconditional_prohibition(clause)
            has_other_recognized_action = (
                not has_rule_match
                and _SAFE_NEGATION_RECOGNIZED_ACTION_CLAUSE.fullmatch(clause)
                is not None
            )
            cached = (
                has_rule_match,
                is_complete,
                has_other_recognized_action,
            )
            clause_cache[clause] = cached
        has_rule_match, is_complete, has_other_recognized_action = cached
        if has_rule_match:
            saw_rule_match = True
            if not is_complete:
                return False
            continue
        if has_other_recognized_action or is_complete:
            continue
        return False
    return saw_rule_match


def _rule_matches_line(line: str, rule: dict[str, object]) -> bool:
    regex = rule["regex"]
    assert isinstance(regex, re.Pattern)
    if not bool(rule.get("safe_negation")):
        return regex.search(line) is not None

    normalized = line.replace("\u2019", "'")
    if regex.search(normalized) is None:
        return False
    return not _safe_negation_is_complete(
        normalized,
        regex=regex,
    )


def _matching_rule_indices(
    line: str,
    rules: list[dict[str, object]],
) -> tuple[int, ...]:
    matches: list[int] = []
    complete_default_prohibitions = _line_is_complete_unconditional_prohibitions(
        line
    )
    for index, rule in enumerate(rules):
        if complete_default_prohibitions and bool(rule.get("default_rule")):
            continue
        if _rule_matches_line(line, rule):
            matches.append(index)
    return tuple(matches)


def _scan_context_files_unbounded(
    root: Path,
    policy: dict[str, object],
    _input_budget: DistinctInputBudget | None = None,
) -> tuple[list[ContextGuardFinding], int]:
    root = root.resolve()
    rules = build_rules(policy)
    paths = iter_context_files(root=root, policy=policy)
    include, exclude = _context_selector_patterns(policy)
    (
        compiled_include,
        compiled_exclude,
        literal_files,
        literal_directories,
    ) = _compile_context_selection(
        root=root,
        include=include,
        exclude=exclude,
        opaque_directories=(),
    )
    selection_work_budget = _ContextGlobWorkBudget()

    findings: list[ContextGuardFinding] = []
    input_budget = _input_budget or DistinctInputBudget(
        max_bytes=MAX_CONTEXT_DISTINCT_INPUT_BYTES
    )
    result_budget = _ContextFindingResultBudget()
    for path in paths:
        _, opened, text = _read_inventory_snapshot(
            path,
            root=root,
            max_bytes=MAX_CONTEXT_FILE_BYTES,
            _input_budget=input_budget,
        )
        rel, _alias_path = _validate_context_snapshot_selection(
            root=root,
            alias_path=path,
            opened=opened,
            compiled_include=compiled_include,
            compiled_exclude=compiled_exclude,
            literal_files=literal_files,
            literal_directories=literal_directories,
            opaque_directories=(),
            work_budget=selection_work_budget,
        )
        if text is None:
            continue
        rule_match_cache: dict[str, tuple[int, ...]] = {}
        for lineno, line in enumerate(text.splitlines(), start=1):
            matching_indices = rule_match_cache.get(line)
            if matching_indices is None:
                matching_indices = _matching_rule_indices(line, rules)
                rule_match_cache[line] = matching_indices
            for index in matching_indices:
                rule = rules[index]
                finding = ContextGuardFinding(
                    file=rel,
                    line=lineno,
                    rule_id=str(rule["id"]),
                    severity=str(rule["severity"]),
                    message=str(rule["message"]),
                    snippet=line.strip()[:200],
                )
                result_budget.add(finding)
                findings.append(finding)
    return findings, len(paths)


def _scan_context_files_with_inventory_unbounded(
    root: Path,
    policy: dict[str, object],
    _input_budget: DistinctInputBudget | None = None,
) -> tuple[list[ContextGuardFinding], int, ContextInventory]:
    root = root.resolve()
    input_budget = _input_budget or DistinctInputBudget(
        max_bytes=MAX_CONTEXT_DISTINCT_INPUT_BYTES
    )
    rules = build_rules(policy)
    paths = iter_context_files(root=root, policy=policy)
    include, exclude = _context_selector_patterns(policy)
    (
        compiled_include,
        compiled_exclude,
        literal_files,
        literal_directories,
    ) = _compile_context_selection(
        root=root,
        include=include,
        exclude=exclude,
        opaque_directories=(),
    )
    selection_work_budget = _ContextGlobWorkBudget()
    findings: list[ContextGuardFinding] = []
    entries: list[ContextInventoryEntry] = []
    receipts: list[BoundedRepoReceipt] = []
    aliases: list[tuple[str, str]] = []
    finding_budget = _ContextFindingResultBudget()
    inventory_budget = _ContextInventoryResultBudget()
    for path in paths:
        read_status, opened, text = _read_inventory_snapshot(
            path,
            root=root,
            max_bytes=MAX_CONTEXT_FILE_BYTES,
            _input_budget=input_budget,
        )
        rel, alias_path = _validate_context_snapshot_selection(
            root=root,
            alias_path=path,
            opened=opened,
            compiled_include=compiled_include,
            compiled_exclude=compiled_exclude,
            literal_files=literal_files,
            literal_directories=literal_directories,
            opaque_directories=(),
            work_budget=selection_work_budget,
        )
        data = opened.data
        receipts.append(opened.receipt())
        aliases.append((opened.relative_path, alias_path))
        lines = text.splitlines() if text is not None else None
        line_count = len(lines) if lines is not None else None
        empty_entry = ContextInventoryEntry(
            path=rel,
            kind=context_kind(rel),
            read_status=read_status,
            size_bytes=len(data),
            line_count=line_count,
            evidence=(),
        )
        inventory_budget.add_entry(empty_entry)
        evidence = (
            collect_context_evidence(
                rel_path=rel,
                text=text,
                _result_budget=inventory_budget,
            )
            if text is not None
            else ()
        )
        entries.append(
            ContextInventoryEntry(
                path=empty_entry.path,
                kind=empty_entry.kind,
                read_status=empty_entry.read_status,
                size_bytes=empty_entry.size_bytes,
                line_count=empty_entry.line_count,
                evidence=evidence,
            )
        )
        if lines is None:
            continue
        rule_match_cache: dict[str, tuple[int, ...]] = {}
        for lineno, line in enumerate(lines, start=1):
            matching_indices = rule_match_cache.get(line)
            if matching_indices is None:
                matching_indices = _matching_rule_indices(line, rules)
                rule_match_cache[line] = matching_indices
            for index in matching_indices:
                rule = rules[index]
                finding = ContextGuardFinding(
                    file=rel,
                    line=lineno,
                    rule_id=str(rule["id"]),
                    severity=str(rule["severity"]),
                    message=str(rule["message"]),
                    snippet=line.strip()[:200],
                )
                finding_budget.add(finding)
                findings.append(finding)
    context_files = tuple(sorted(entries, key=lambda item: item.path))
    inventory = ContextInventory(
        context_files=context_files,
        permission_boundaries=boundary_summary(context_files),
        _input_receipts=tuple(sorted(receipts, key=lambda item: item.relative_path)),
        _input_aliases=tuple(sorted(aliases)),
    )
    combined_result = {
        "findings": [item.to_dict() for item in findings],
        "scanned_files": len(paths),
        "inventory": inventory.to_dict(),
    }
    if _canonical_json_size(combined_result) > MAX_CONTEXT_AGGREGATE_RESULT_BYTES:
        raise ValueError(ERROR_CONTEXT_SCAN_LIMIT)
    return findings, len(paths), inventory


def scan_context_files(
    *,
    root: Path,
    policy: dict[str, object],
    _input_budget: DistinctInputBudget | None = None,
) -> tuple[list[ContextGuardFinding], int]:
    return run_isolated_scan(
        _scan_context_files_unbounded,
        root,
        policy,
        _input_budget,
        timeout_error=ERROR_CONTEXT_SCAN_TIMEOUT,
        runtime_error=ERROR_CONTEXT_SCAN_RUNTIME,
        result_limit_error=ERROR_CONTEXT_SCAN_LIMIT,
        safe_errors=(
            ERROR_CONTEXT_POLICY_INVALID,
            ERROR_CONTEXT_POLICY_LIMIT,
            ERROR_CONTEXT_SCAN_LIMIT,
            ERROR_CONTEXT_SCAN_TARGET,
        ),
    )


def scan_context_files_with_inventory(
    *,
    root: Path,
    policy: dict[str, object],
    _input_budget: DistinctInputBudget | None = None,
) -> tuple[list[ContextGuardFinding], int, ContextInventory]:
    result = run_isolated_scan(
        _scan_context_files_with_inventory_unbounded,
        root,
        policy,
        _input_budget,
        timeout_error=ERROR_CONTEXT_SCAN_TIMEOUT,
        runtime_error=ERROR_CONTEXT_SCAN_RUNTIME,
        result_limit_error=ERROR_CONTEXT_SCAN_LIMIT,
        safe_errors=(
            ERROR_CONTEXT_POLICY_INVALID,
            ERROR_CONTEXT_POLICY_LIMIT,
            ERROR_CONTEXT_SCAN_LIMIT,
            ERROR_CONTEXT_SCAN_TARGET,
        ),
    )
    if _input_budget is not None:
        try:
            for receipt in result[2]._input_receipts:
                _input_budget.charge_receipt(receipt)
        except BoundedRepoLimitError:
            raise ValueError(ERROR_CONTEXT_SCAN_LIMIT) from None
        except BoundedRepoReadError:
            raise ValueError(ERROR_CONTEXT_SCAN_TARGET) from None
    return result
