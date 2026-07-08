"""Where: bench/evidence/fixture_repo.py
What: generated fixture repository for evidence integrity checks.
Why: keep benchmark runtime fixtures deterministic and isolated from repo state.
"""

from __future__ import annotations

import json
from pathlib import Path


SEEDED_VALUES = (
    "ghp_FAKE000000000000000000000000000000",
    "AKIAFAKE000000000000",
    "sk-FAKE000000000000000000000000000000",
    "/home/alice/private/project",
    "alice@example.invalid",
)
MCP_POLICY = """schema_version: agent-guard.mcp_policy.v1
policy:
  fail_on_parse_error: true
  forbidden_risky_patterns:
    - broad_authorization_scope
    - filesystem_root_reference
    - inline_authorization_value
    - inline_env_value
    - instruction_like_description
    - latest_package
    - secret_shaped_inline_value
    - unsafe_url_scheme
    - unpinned_package
"""
WORKFLOW_POLICY = """schema_version: agent-guard.workflow_policy.v1
required_files:
  - .agent-guard/context-policy.yaml
  - .agent-guard/path-policy.yaml
  - .agent-guard/content-policy.yaml
  - .agent-guard/mcp-policy.yaml
  - .agent-guard/workflow-policy.yaml
"""
README = """# Evidence Fixture
agent-guard surface inventory --root . --context-policy .agent-guard/context-policy.yaml
agent-guard context check --root . --policy .agent-guard/context-policy.yaml
agent-guard workflow check --root . --policy .agent-guard/workflow-policy.yaml
agent-guard mcp check --root . --policy .agent-guard/mcp-policy.yaml
agent-guard drift check --root .
agent-guard report --root . --context-policy .agent-guard/context-policy.yaml
"""
AGENTS = """# Agent Instructions
Maintainer approval is required for risky changes.
Secrets, tokens, passwords, and credentials must stay private.
Run tests and lint verification before completion.
"""


def write_fixture_repo(root: Path) -> None:
    policy_dir = root / ".agent-guard"
    policy_dir.mkdir(parents=True, exist_ok=True)
    (root / "docs").mkdir(parents=True, exist_ok=True)
    (root / "AGENTS.md").write_text(AGENTS, encoding="utf-8")
    (root / "README.md").write_text(README, encoding="utf-8")
    (root / "docs" / "secrets.md").write_text("\n".join(SEEDED_VALUES) + "\n", encoding="utf-8")
    (root / ".mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "redaction": {
                        "command": "node",
                        "args": ["server.js", "--token", SEEDED_VALUES[0]],
                        "env": {"OPENAI_API_KEY": SEEDED_VALUES[2]},
                    }
                }
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    (policy_dir / "context-policy.yaml").write_text("{}\n", encoding="utf-8")
    (policy_dir / "path-policy.yaml").write_text("{}\n", encoding="utf-8")
    (policy_dir / "content-policy.yaml").write_text("{}\n", encoding="utf-8")
    (policy_dir / "mcp-policy.yaml").write_text(MCP_POLICY, encoding="utf-8")
    (policy_dir / "workflow-policy.yaml").write_text(WORKFLOW_POLICY, encoding="utf-8")
