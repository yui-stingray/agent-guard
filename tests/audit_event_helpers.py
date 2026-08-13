"""Shared valid agent-policy audit-event fixtures for binding contract tests."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def audit_event_payload(
    *,
    capability: str = "read",
    context: dict[str, Any] | None = None,
    mode: str = "auto_allow",
    reason: str = "repo_policy",
    matched_repo: str | None = "example/repo",
) -> dict[str, Any]:
    return {
        "repo": "example/repo",
        "capability": capability,
        "context": {} if context is None else context,
        "decision": {
            "mode": mode,
            "reason": reason,
            "matched_repo": matched_repo,
        },
    }


def write_audit_event(path: Path, **overrides: Any) -> None:
    path.write_text(
        json.dumps(audit_event_payload(**overrides), sort_keys=True) + "\n",
        encoding="utf-8",
    )
