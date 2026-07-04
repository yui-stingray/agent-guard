"""Where: bench/alignment/run.py
What: ASI taxonomy completeness check for stable guard-emitted IDs and labels.
Why: keep reported risk-theme metadata from silently drifting as guards change.
"""

from __future__ import annotations

import argparse
import ast
from datetime import datetime, timezone
import inspect
import json
from pathlib import Path
from types import ModuleType
from typing import Any

from agent_guard import conformance, context_guard, content_guard, drift_guard, mcp_guard, taxonomy
from agent_guard.report_sarif import render_sarif_report


ALIGNMENT_SCHEMA_VERSION = "agent-guard.alignment.v1"
SARIF_SCHEMA_PATH = Path(__file__).resolve().parent / "schemas" / "sarif-schema-2.1.0.json"
DRIFT_BASELINE_CLASSIFICATION_PATHS = {
    ".agent-guard/content-policy.yaml",
    ".agent-guard/context-digest-policy.yaml",
    ".github/workflows/ci.yml",
    ".pre-commit-hooks.yaml",
    "action.yml",
    "guard-surface.txt",
}
DRIFT_STATIC_REASON_LABELS = {
    "invalid_workflow_policy",
    "missing_agent_guard_policy",
    "missing_readme_guard_command",
    "missing_required_context_boundary",
    "missing_required_file",
    "missing_required_file_entry",
    "missing_required_workflow_command",
}
WORKFLOW_REASON_LABELS = {
    "missing_required_file",
    "missing_required_workflow_command",
}
MCP_RULE_IDS = {
    "mcp_config_risky_pattern",
    "mcp_policy_missing",
}
DIGEST_STATUS_LABELS = {
    "missing",
    "mismatch",
}
CONTEXT_LOCK_RULE_IDS = {
    "context_lock_missing",
    "context_lock_partial",
    "context_lock_file_missing",
    "context_lock_mismatch",
}


def _ids_from_rules(rules: object) -> set[str]:
    if not isinstance(rules, list):
        return set()
    return {
        str(item.get("id", "")).strip()
        for item in rules
        if isinstance(item, dict) and str(item.get("id", "")).strip()
    }


def _literal_values_for_key(module: ModuleType, key_name: str) -> set[str]:
    tree = ast.parse(inspect.getsource(module))
    values: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Dict):
            for key, value in zip(node.keys, node.values):
                if (
                    isinstance(key, ast.Constant)
                    and key.value == key_name
                    and isinstance(value, ast.Constant)
                    and isinstance(value.value, str)
                ):
                    values.add(value.value)
        if isinstance(node, ast.Call):
            for keyword in node.keywords:
                if (
                    keyword.arg == key_name
                    and isinstance(keyword.value, ast.Constant)
                    and isinstance(keyword.value.value, str)
                ):
                    values.add(keyword.value.value)
    return values


def _check_mapping(name: str, emitted: set[str], mapped: set[str]) -> dict[str, object]:
    missing = sorted(emitted - mapped)
    return {
        "name": name,
        "status": "ok" if not missing else "violation",
        "emitted_count": len(emitted),
        "mapped_count": len(emitted & mapped),
        "missing_count": len(missing),
        "missing": missing,
    }


def _check_theme_references() -> dict[str, object]:
    theme_ids = set(taxonomy.OWASP_AGENTIC_TOP10)
    emitted: set[str] = set()
    mapping_names = [
        "API_CATEGORY_THEMES",
        "CONFORMANCE_RULE_THEMES",
        "CONTENT_RULE_THEMES",
        "CONTEXT_LOCK_RULE_THEMES",
        "CONTEXT_RULE_THEMES",
        "DIGEST_STATUS_THEMES",
        "DRIFT_CLASSIFICATION_THEMES",
        "EVIDENCE_CATEGORY_THEMES",
        "EVIDENCE_RULE_THEMES",
        "MCP_RISK_PATTERN_THEMES",
        "MCP_RULE_THEMES",
        "WORKFLOW_REASON_THEMES",
    ]
    for name in mapping_names:
        mapping = getattr(taxonomy, name)
        for values in mapping.values():
            emitted.update(str(value) for value in values)
    return _check_mapping("taxonomy_theme_references", emitted, theme_ids)


def load_official_sarif_schema() -> dict[str, Any]:
    loaded = json.loads(SARIF_SCHEMA_PATH.read_text(encoding="utf-8"))
    if not isinstance(loaded, dict):
        raise ValueError("official SARIF schema must be a JSON object")
    return loaded


def official_sarif_schema_errors(payload: object) -> list[str]:
    try:
        import jsonschema  # type: ignore[import-not-found]
    except Exception as exc:  # pragma: no cover - dev dependency is present in CI.
        return [f"jsonschema unavailable: {type(exc).__name__}"]

    schema = load_official_sarif_schema()
    validator = jsonschema.Draft4Validator(schema)
    errors = sorted(validator.iter_errors(payload), key=lambda error: (list(error.path), error.message))
    return [f"{_json_path(error.path)}: {error.message}" for error in errors]


def _json_path(parts: object) -> str:
    path = "$"
    for part in parts:
        if isinstance(part, int):
            path += f"[{part}]"
        else:
            path += f".{part}"
    return path


def _sarif_sample_report_payload() -> dict[str, object]:
    return {
        "tool": {"name": "agent-guard"},
        "status": "violation",
        "findings": [
            {
                "rule_id": "approval_bypass",
                "severity": "high",
                "file": "AGENTS.md",
                "line": 1,
            }
        ],
        "mcp_config": {
            "findings": [
                {
                    "rule_id": "mcp_config_risky_pattern",
                    "severity": "high",
                    "path": ".mcp.json",
                    "reason": "unpinned_package",
                }
            ]
        },
    }


def _check_sarif_schema_validation() -> dict[str, object]:
    sarif_payload = json.loads(render_sarif_report(_sarif_sample_report_payload()))
    errors = official_sarif_schema_errors(sarif_payload)
    return {
        "name": "sarif_official_schema_validation",
        "status": "ok" if not errors else "violation",
        "emitted_count": 1,
        "mapped_count": 0 if errors else 1,
        "missing_count": len(errors),
        "missing": errors,
    }


def _drift_classification_labels() -> set[str]:
    labels = {
        *drift_guard.CONTEXT_RULE_CLASSIFICATIONS.values(),
        *drift_guard.CONTEXT_LOCK_CLASSIFICATIONS.values(),
        *DRIFT_STATIC_REASON_LABELS,
        "baseline_review_required",
        "context_lock_drift",
        "unsafe_context_instruction",
    }
    labels.update(drift_guard.classify_baseline_trust_path(path) for path in DRIFT_BASELINE_CLASSIFICATION_PATHS)
    return labels


def build_alignment_result(*, repo_root: Path | str = ".") -> dict[str, Any]:
    del repo_root
    context_rule_ids = _ids_from_rules(context_guard.DEFAULT_FORBIDDEN_PATTERNS)
    context_evidence_rules = {
        str(item.get("rule_id", "")).strip()
        for item in context_guard.EVIDENCE_RULES
        if isinstance(item, dict) and str(item.get("rule_id", "")).strip()
    }
    content_rule_ids = _ids_from_rules(content_guard.DEFAULT_POLICY.get("forbidden_patterns", []))
    conformance_rule_ids = _literal_values_for_key(conformance, "rule_id")
    conformance_rule_ids.discard("mcp_config_risky_pattern")

    checks = [
        _check_mapping("context_default_rules", context_rule_ids, set(taxonomy.CONTEXT_RULE_THEMES)),
        _check_mapping(
            "drift_context_rule_classifications",
            context_rule_ids,
            set(drift_guard.CONTEXT_RULE_CLASSIFICATIONS),
        ),
        _check_mapping(
            "context_evidence_categories",
            set(context_guard.BOUNDARY_CATEGORIES),
            set(taxonomy.EVIDENCE_CATEGORY_THEMES),
        ),
        _check_mapping("context_evidence_rules", context_evidence_rules, set(taxonomy.EVIDENCE_RULE_THEMES)),
        _check_mapping("content_default_rules", content_rule_ids, set(taxonomy.CONTENT_RULE_THEMES)),
        _check_mapping("api_categories", {"forbidden_api"}, set(taxonomy.API_CATEGORY_THEMES)),
        _check_mapping("mcp_rule_ids", MCP_RULE_IDS, set(taxonomy.MCP_RULE_THEMES)),
        _check_mapping(
            "mcp_risk_pattern_labels",
            {*mcp_guard.DEFAULT_FORBIDDEN_RISKY_PATTERNS, "parse_error"},
            set(taxonomy.MCP_RISK_PATTERN_THEMES),
        ),
        _check_mapping("context_lock_rule_ids", CONTEXT_LOCK_RULE_IDS, set(taxonomy.CONTEXT_LOCK_RULE_THEMES)),
        _check_mapping("digest_status_labels", DIGEST_STATUS_LABELS, set(taxonomy.DIGEST_STATUS_THEMES)),
        _check_mapping("workflow_reason_labels", WORKFLOW_REASON_LABELS, set(taxonomy.WORKFLOW_REASON_THEMES)),
        _check_mapping("conformance_rule_ids", conformance_rule_ids, set(taxonomy.CONFORMANCE_RULE_THEMES)),
        _check_mapping(
            "drift_classification_labels",
            _drift_classification_labels(),
            set(taxonomy.DRIFT_CLASSIFICATION_THEMES),
        ),
        _check_theme_references(),
        _check_sarif_schema_validation(),
    ]
    missing_count = sum(int(check["missing_count"]) for check in checks)
    emitted_count = sum(int(check["emitted_count"]) for check in checks)
    return {
        "schema_version": ALIGNMENT_SCHEMA_VERSION,
        "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "status": "ok" if missing_count == 0 else "violation",
        "summary": {
            "check_count": len(checks),
            "emitted_count": emitted_count,
            "missing_count": missing_count,
        },
        "checks": checks,
    }


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Check ASI taxonomy completeness for guard-emitted IDs.")
    parser.add_argument("--repo-root", type=Path, default=Path("."), help="Repository root, reserved for future checks.")
    parser.add_argument("--out", type=Path, default=None, help="Optional path to write JSON results.")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    result = build_alignment_result(repo_root=args.repo_root)
    if args.out is not None:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, sort_keys=True))
    return 0 if result["status"] == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())
