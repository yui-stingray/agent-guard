"""Where: examples/evidence_consumer.py
What: backward-compatible shim for the packaged evidence consumer.
Why: keep old imports and CLI usage working while callers migrate to agent_guard.consumer.

Deprecated: import from agent_guard.consumer instead.
"""

from __future__ import annotations

from agent_guard.consumer import *  # noqa: F401,F403
from agent_guard.consumer import main


if __name__ == "__main__":
    raise SystemExit(main())
