"""Where: src/agent_guard/__init__.py
What: public API for the first agent-guard extractions.
Why: keep the import surface explicit while the package is still young.
"""

from __future__ import annotations

from .api_guard import ApiGuardFinding, scan_urls
from .content_guard import ContentGuardFinding, scan_paths

__all__ = ["scan_urls", "ApiGuardFinding", "scan_paths", "ContentGuardFinding"]

__version__ = "0.1.0"
