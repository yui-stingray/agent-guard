"""Where: src/agent_guard/cli/__init__.py
What: package shim for the legacy CLI implementation during extraction.
Why: allow incremental subcommand modules while preserving the public CLI import path.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

_LEGACY_MODULE_NAME = "agent_guard._legacy_cli"
_LEGACY_PATH = Path(__file__).resolve().parents[1] / "cli.py"
_SPEC = importlib.util.spec_from_file_location(_LEGACY_MODULE_NAME, _LEGACY_PATH)
if _SPEC is None or _SPEC.loader is None:
    raise ImportError(f"cannot load legacy CLI implementation from {_LEGACY_PATH}")

_legacy = importlib.util.module_from_spec(_SPEC)
sys.modules[_LEGACY_MODULE_NAME] = _legacy
_SPEC.loader.exec_module(_legacy)

for _name, _value in vars(_legacy).items():
    if not _name.startswith("_"):
        globals()[_name] = _value

__all__ = sorted(_name for _name in vars(_legacy) if not _name.startswith("_"))

