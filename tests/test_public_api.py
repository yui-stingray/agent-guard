"""Where: tests/test_public_api.py
What: import-surface checks for scanner functions and finding types.
Why: release builds should not hide newly documented scanners from library callers.
"""

from __future__ import annotations

import agent_guard


def test_public_api_exports_all_scanners() -> None:
    assert callable(agent_guard.scan_urls)
    assert callable(agent_guard.scan_context_files)
    assert callable(agent_guard.scan_paths)
    assert callable(agent_guard.scan_content_paths)
    assert callable(agent_guard.scan_repo_paths)
    assert callable(agent_guard.scan_digests)


def test_scan_paths_alias_preserves_content_guard_backcompat() -> None:
    assert agent_guard.scan_paths is agent_guard.scan_content_paths
