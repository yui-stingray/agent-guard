"""Where: src/agent_guard/cli_registry.py
What: shared registry of public agent-guard CLI command pairs.
Why: keep static command evidence tied to the real CLI contract.
"""

from __future__ import annotations


AGENT_GUARD_COMMANDS: dict[str, tuple[str, ...]] = {
    "api": ("check",),
    "content": ("check",),
    "context": ("check", "inventory", "lock"),
    "conformance": ("check",),
    "digest": ("check",),
    "drift": ("check",),
    "evidence-pack": ("manifest",),
    "init": ("",),
    "mcp": ("check",),
    "path": ("check",),
    "report": ("",),
    "render-report": ("",),
    "surface": ("inventory",),
    "workflow": ("check",),
}
AGENT_GUARD_SCANNERS = frozenset(AGENT_GUARD_COMMANDS)
AGENT_GUARD_SUBCOMMANDS = frozenset(
    command for commands in AGENT_GUARD_COMMANDS.values() for command in commands if command
)
AGENT_GUARD_COMMAND_TOKENS = AGENT_GUARD_SCANNERS | AGENT_GUARD_SUBCOMMANDS


def is_agent_guard_cli_command(scanner: str, command: str) -> bool:
    return command in AGENT_GUARD_COMMANDS.get(scanner, ())
