"""Where: src/agent_guard/consumer/__init__.py
What: packaged evidence consumer API for sanitized agent-guard reports.
Why: let downstream wrappers import the consumer instead of copying example code.
"""

from __future__ import annotations

from ._bindings import validate_agent_policy_audit_event_files
from ._bundle import (
    ALLOWED_EVIDENCE_ARTIFACT_NAMES,
    validate_evidence_bundle,
)
from ._cli import main, parse_args
from ._redaction import (
    FORBIDDEN_PUBLIC_KEYS,
    LOCAL_PATH_RE,
    RAW_URL_RE,
    SECRET_VALUE_RE,
    SHA256_VALUE_RE,
    validate_public_evidence_shape,
    validate_public_text_shape,
)
from ._report import validate_report
from ._schema import (
    REPORT_SCHEMA,
    load_payload,
    load_report_schema,
    require,
    require_int,
    require_mapping,
    require_sequence,
    schema_condition_matches,
    validate_against_schema,
    value_has_json_type,
)
from ._sections import (
    MCP_POLICY_CONFORMANCE_RULES,
    REQUIRED_MCP_RISK_LABELS,
    REVIEWED_MCP_POLICY_PATH,
    validate_conformance,
    validate_evidence_pack_manifest,
    validate_gate_counts,
    validate_public_report_consistency,
    validate_surface_inventory,
)

__all__ = [
    "ALLOWED_EVIDENCE_ARTIFACT_NAMES",
    "FORBIDDEN_PUBLIC_KEYS",
    "LOCAL_PATH_RE",
    "MCP_POLICY_CONFORMANCE_RULES",
    "RAW_URL_RE",
    "REPORT_SCHEMA",
    "REQUIRED_MCP_RISK_LABELS",
    "REVIEWED_MCP_POLICY_PATH",
    "SECRET_VALUE_RE",
    "SHA256_VALUE_RE",
    "load_payload",
    "load_report_schema",
    "main",
    "parse_args",
    "require",
    "require_int",
    "require_mapping",
    "require_sequence",
    "schema_condition_matches",
    "validate_against_schema",
    "validate_agent_policy_audit_event_files",
    "validate_conformance",
    "validate_evidence_bundle",
    "validate_evidence_pack_manifest",
    "validate_gate_counts",
    "validate_public_evidence_shape",
    "validate_public_report_consistency",
    "validate_public_text_shape",
    "validate_report",
    "validate_surface_inventory",
    "value_has_json_type",
]
