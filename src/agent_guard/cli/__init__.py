"""Where: src/agent_guard/cli/__init__.py
What: keep the public CLI imports and observed exports explicit.
Why: expose one normal entry module without splitting function identity.
"""

from __future__ import annotations

# Preserve the already observable facade names during this migration.
import importlib.util
import sys
from pathlib import Path

from . import _entry as _legacy
from ._entry import (
    PACKAGE_VERSION,
    add_api_parser,
    add_conformance_parser,
    add_content_parser,
    add_context_parser,
    add_digest_parser,
    add_drift_parser,
    add_evidence_pack_parser,
    add_mcp_parser,
    add_path_parser,
    add_render_report_parser,
    add_report_parser,
    add_surface_parser,
    add_workflow_parser,
    annotations,
    argparse,
    build_parser,
    main,
    run_api_check,
    run_conformance_check,
    run_content_check,
    run_context_check,
    run_context_inventory,
    run_context_lock,
    run_digest_check,
    run_drift_check,
    run_evidence_pack_manifest,
    run_init,
    run_mcp_check,
    run_path_check,
    run_report,
    run_report_render,
    run_surface_delta,
    run_surface_inventory,
    run_workflow_check,
    safe_policy_path,
    scrub_report_error_message,
)

# Preserve old function pickle references after importing this public facade.
sys.modules["agent_guard._legacy_cli"] = _legacy

__all__ = [
    "PACKAGE_VERSION",
    "add_api_parser",
    "add_conformance_parser",
    "add_content_parser",
    "add_context_parser",
    "add_digest_parser",
    "add_drift_parser",
    "add_evidence_pack_parser",
    "add_mcp_parser",
    "add_path_parser",
    "add_render_report_parser",
    "add_report_parser",
    "add_surface_parser",
    "add_workflow_parser",
    "annotations",
    "argparse",
    "build_parser",
    "main",
    "run_api_check",
    "run_conformance_check",
    "run_content_check",
    "run_context_check",
    "run_context_inventory",
    "run_context_lock",
    "run_digest_check",
    "run_drift_check",
    "run_evidence_pack_manifest",
    "run_init",
    "run_mcp_check",
    "run_path_check",
    "run_report",
    "run_report_render",
    "run_surface_delta",
    "run_surface_inventory",
    "run_workflow_check",
    "safe_policy_path",
    "scrub_report_error_message",
]
