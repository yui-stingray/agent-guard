"""Where: src/agent_guard/report_sarif.py
What: SARIF adapter for sanitized evidence reports.
Why: keep SARIF result shaping separate from Markdown and GitHub annotation output.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping

from .report_core import as_mapping, as_sequence, positive_line_number, redact_text
from .taxonomy import risk_themes_for_finding


def sarif_artifact_uri(value: object) -> str:
    text = redact_text("-" if value in (None, "") else str(value)).strip().replace("\\", "/")
    if not text or text == "-" or text.startswith("/") or text.startswith("<"):
        return "agent-guard-evidence"
    if re.match(r"^[A-Za-z]:/", text) or text.startswith("//"):
        return "agent-guard-evidence"
    parts = [part for part in text.split("/") if part and part != "."]
    if not parts:
        return "agent-guard-evidence"
    if ".." in parts:
        return parts[-1] or "agent-guard-evidence"
    return "/".join(parts)


def sarif_region(line: object) -> dict[str, int]:
    line_number = positive_line_number(line)
    return {"startLine": int(line_number) if line_number else 1}


def sarif_level(severity: object) -> str:
    return "error" if str(severity).lower() == "high" else "warning"


def sarif_rule_id(scanner: str, raw_rule_id: object) -> str:
    rule = re.sub(r"[^A-Za-z0-9_.-]+", "_", str(raw_rule_id or "finding")).strip("_")
    scanner_id = re.sub(r"[^A-Za-z0-9_.-]+", "_", scanner).strip("_") or "agent_guard"
    return f"agent-guard.{scanner_id}.{rule or 'finding'}"


def sarif_fingerprint(*, rule_id: str, uri: str, line: object, message: str) -> str:
    seed = f"{rule_id}\0{uri}\0{positive_line_number(line) or '1'}\0{message}"
    return hashlib.sha256(seed.encode("utf-8")).hexdigest()


def append_sarif_result(
    *,
    results: list[dict[str, object]],
    rules: dict[str, dict[str, object]],
    scanner: str,
    rule_id: object,
    severity: object,
    message: object,
    file: object = "",
    line: object = "",
    risk_themes: list[dict[str, str]] | None = None,
) -> None:
    sarif_id = sarif_rule_id(scanner, rule_id)
    uri = sarif_artifact_uri(file)
    text = redact_text(str(message or f"{scanner} finding: {rule_id or 'finding'}"))
    rule = rules.setdefault(
        sarif_id,
        {
            "id": sarif_id,
            "shortDescription": {"text": redact_text(str(rule_id or "finding"))},
        },
    )
    if risk_themes:
        rule.setdefault("properties", {})["owasp_agentic_risk_themes"] = risk_themes
    results.append(
        {
            "ruleId": sarif_id,
            "level": sarif_level(severity),
            "message": {"text": text},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": uri},
                        "region": sarif_region(line),
                    }
                }
            ],
            "partialFingerprints": {
                "primaryLocationLineHash": sarif_fingerprint(
                    rule_id=sarif_id,
                    uri=uri,
                    line=line,
                    message=text,
                )
            },
        }
    )


def render_sarif_report(payload: Mapping[str, object]) -> str:
    """Render a minimal SARIF 2.1.0 adapter from sanitized report evidence."""

    tool = as_mapping(payload.get("tool"))
    rules: dict[str, dict[str, object]] = {}
    results: list[dict[str, object]] = []

    if payload.get("status") == "error":
        append_sarif_result(
            results=results,
            rules=rules,
            scanner="report",
            rule_id="configuration_error",
            severity="high",
            message=f"agent-guard report error: {payload.get('error', 'unknown error')}",
            file="agent-guard-evidence",
        )

    for item in as_sequence(payload.get("findings")):
        finding = as_mapping(item)
        rule_id = finding.get("rule_id", "context")
        append_sarif_result(
            results=results,
            rules=rules,
            scanner="context",
            rule_id=rule_id,
            severity=finding.get("severity", "high"),
            message=f"context finding: {rule_id}",
            file=finding.get("file", ""),
            line=finding.get("line", ""),
            risk_themes=risk_themes_for_finding("context", finding),
        )

    sections = (
        ("path", "path", "path guard finding"),
        ("content", "content", "content guard finding"),
        ("api", "api", "api guard finding"),
        ("mcp_config", "mcp", "mcp config finding"),
        ("context_lock", "context-lock", "context lock coverage"),
        ("digest", "digest", "digest drift"),
        ("workflow", "workflow", "workflow drift"),
        ("policy_spec_drift", "drift", "policy/spec drift"),
        ("conformance", "conformance", "conformance finding"),
    )
    for section_name, scanner, label in sections:
        section = as_mapping(payload.get(section_name))
        for item in as_sequence(section.get("findings")):
            finding = as_mapping(item)
            raw_rule_id = (
                finding.get("rule_id")
                or finding.get("check_id")
                or finding.get("category")
                or section_name
            )
            file_value = finding.get("file", finding.get("path", "agent-guard-evidence"))
            message_suffix = finding.get("reason") or finding.get("status") or raw_rule_id
            append_sarif_result(
                results=results,
                rules=rules,
                scanner=scanner,
                rule_id=raw_rule_id,
                severity=finding.get("severity", "high"),
                message=f"{label}: {message_suffix}",
                file=file_value,
                line=finding.get("line", ""),
                risk_themes=risk_themes_for_finding(section_name, finding),
            )

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": str(tool.get("name", "agent-guard")),
                        "informationUri": "https://github.com/yui-stingray/agent-guard",
                        "rules": [rules[key] for key in sorted(rules)],
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(
        sarif,
        allow_nan=False,
        ensure_ascii=False,
        sort_keys=True,
    ) + "\n"
