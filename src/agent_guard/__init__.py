"""Where: src/agent_guard/__init__.py
What: public API for the first agent-guard extraction.
Why: keep the import surface explicit while the package is still young.
"""

from __future__ import annotations

from .api_guard import ApiGuardFinding, scan_urls

__all__ = ["scan_urls", "ApiGuardFinding"]

__version__ = "0.1.0"
