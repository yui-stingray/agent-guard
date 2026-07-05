"""Where: src/agent_guard/consumer/__main__.py
What: module entry point for the packaged evidence consumer.
Why: let CI invoke the existing fail-closed report validator without a copied shim.
"""

from __future__ import annotations

from ._cli import main


if __name__ == "__main__":
    raise SystemExit(main())
