"""Where: src/sitecustomize.py
What: opt-in coverage.py startup hook for repository test subprocesses.
Why: let COVERAGE_PROCESS_START capture subprocess-driven CLI tests.
"""

from __future__ import annotations

import os

if os.environ.get("COVERAGE_PROCESS_START"):
    try:
        import coverage
    except ImportError:
        pass
    else:
        coverage.process_startup()
