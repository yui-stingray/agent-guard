"""Where: src/agent_guard/__init__.py
What: public API for the first agent-guard extractions.
Why: keep the import surface explicit while the package is still young.
"""

from __future__ import annotations

from .api_guard import ApiGuardFinding, scan_urls
from .context_guard import ContextGuardFinding, scan_context_files
from .content_guard import ContentGuardFinding, scan_paths as scan_content_paths
from .digest_guard import DigestGuardFinding, scan_digests
from .mcp_guard import build_mcp_config_report
from .path_guard import PathGuardFinding, scan_paths as scan_repo_paths
from .workflow_guard import WorkflowGuardFinding, scan_workflow_policy

scan_paths = scan_content_paths

__all__ = [
    "scan_urls",
    "ApiGuardFinding",
    "scan_context_files",
    "ContextGuardFinding",
    "scan_paths",
    "scan_content_paths",
    "ContentGuardFinding",
    "scan_repo_paths",
    "PathGuardFinding",
    "scan_digests",
    "DigestGuardFinding",
    "build_mcp_config_report",
    "scan_workflow_policy",
    "WorkflowGuardFinding",
]

__version__ = "0.2.4"
