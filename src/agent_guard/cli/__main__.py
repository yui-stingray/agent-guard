"""Where: src/agent_guard/cli/__main__.py
What: python -m entrypoint for the CLI package shim.
Why: preserve subprocess tests that execute `python -m agent_guard.cli`.
"""

from __future__ import annotations

from . import main


if __name__ == "__main__":
    raise SystemExit(main())
