"""Where: src/agent_guard/context_lock.py
What: build digest policy checks from discovered agent context files.
Why: connect context inventory to digest drift checks without emitting raw context content.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Any

import yaml

from .context_guard import ContextInventory


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def context_lock_check_id(path: str, used_ids: set[str]) -> str:
    slug = re.sub(r"[^a-z0-9]+", "_", path.lower()).strip("_")
    base = f"context_{slug}" if slug else "context_file"
    candidate = base
    suffix = 2
    while candidate in used_ids:
        candidate = f"{base}_{suffix}"
        suffix += 1
    used_ids.add(candidate)
    return candidate


def build_context_digest_policy(*, root: Path, inventory: ContextInventory) -> dict[str, Any]:
    root = root.resolve()
    used_ids: set[str] = set()
    checks: list[dict[str, str]] = []

    if not inventory.context_files:
        raise ValueError("no agent context files discovered")

    for entry in inventory.context_files:
        target = (root / entry.path).resolve()
        try:
            relative_path = target.relative_to(root).as_posix()
        except ValueError:
            raise ValueError(f"context file path escapes root: {entry.path}") from None

        if not target.is_file():
            raise FileNotFoundError(f"context file not found: {entry.path}")

        checks.append(
            {
                "id": context_lock_check_id(relative_path, used_ids),
                "path": relative_path,
                "sha256": sha256_file(target),
            }
        )

    return {"checks": checks}


def dump_digest_policy_yaml(policy: dict[str, Any]) -> str:
    return yaml.safe_dump(policy, sort_keys=False)
