"""Where: src/agent_guard/profiles.py
What: named conformance profiles for agent-guard evidence.
Why: keep adoption levels deterministic without turning policies into prose.
"""

from __future__ import annotations

from typing import Any


PROFILE_NAMES = ("minimal", "recommended", "strict")

PROFILE_REQUIREMENTS: dict[str, dict[str, tuple[Any, ...]]] = {
    "minimal": {
        "gates": ("context", "surface_inventory"),
        "surfaces": ("agent_context",),
        "policy_files": (".agent-guard/context-policy.yaml", ".agent-guard/workflow-policy.yaml"),
        "readme_commands": (
            (
                "readme_context_guard",
                "agent-guard context check --root . --policy .agent-guard/context-policy.yaml",
            ),
            (
                "readme_surface_inventory",
                "agent-guard surface inventory --root . --context-policy .agent-guard/context-policy.yaml",
            ),
        ),
        "workflow_commands": (("context", "check"), ("surface", "inventory")),
        "boundary_categories": ("secret_handling", "local_verification"),
        "report_sections": (),
        "artifact_roles": (),
    },
    "recommended": {
        "gates": ("context", "surface_inventory", "path", "content", "workflow", "policy_spec_drift"),
        "surfaces": ("agent_context", "policy_file", "workflow_file", "workflow_reference"),
        "policy_files": (
            ".agent-guard/context-policy.yaml",
            ".agent-guard/path-policy.yaml",
            ".agent-guard/content-policy.yaml",
            ".agent-guard/workflow-policy.yaml",
        ),
        "readme_commands": (
            (
                "readme_surface_inventory",
                "agent-guard surface inventory --root . --context-policy .agent-guard/context-policy.yaml",
            ),
            (
                "readme_context_guard",
                "agent-guard context check --root . --policy .agent-guard/context-policy.yaml",
            ),
            (
                "readme_workflow_guard",
                "agent-guard workflow check --root . --policy .agent-guard/workflow-policy.yaml",
            ),
            ("readme_drift_guard", "agent-guard drift check --root ."),
            (
                "readme_report_with_drift",
                "agent-guard report --root . --context-policy .agent-guard/context-policy.yaml",
            ),
        ),
        "workflow_commands": (
            ("context", "check"),
            ("path", "check"),
            ("content", "check"),
            ("surface", "inventory"),
            ("workflow", "check"),
            ("drift", "check"),
            ("report", ""),
        ),
        "boundary_categories": ("approval_boundary", "secret_handling", "local_verification"),
        "report_sections": (),
        "artifact_roles": (),
    },
    "strict": {
        "gates": (
            "context",
            "surface_inventory",
            "path",
            "content",
            "context_lock",
            "digest",
            "workflow",
            "policy_spec_drift",
        ),
        "surfaces": (
            "agent_context",
            "policy_file",
            "workflow_file",
            "workflow_reference",
            "documented_guard_command",
            "evidence_artifact_reference",
        ),
        "policy_files": (
            ".agent-guard/context-policy.yaml",
            ".agent-guard/path-policy.yaml",
            ".agent-guard/content-policy.yaml",
            ".agent-guard/context-digest-policy.yaml",
            ".agent-guard/workflow-policy.yaml",
        ),
        "readme_commands": (
            (
                "readme_surface_inventory",
                "agent-guard surface inventory --root . --context-policy .agent-guard/context-policy.yaml",
            ),
            (
                "readme_context_guard",
                "agent-guard context check --root . --policy .agent-guard/context-policy.yaml",
            ),
            (
                "readme_context_lock_coverage",
                "agent-guard context lock --root . --policy .agent-guard/context-policy.yaml --check --digest-policy .agent-guard/context-digest-policy.yaml",
            ),
            (
                "readme_digest_guard",
                "agent-guard digest check --root . --policy .agent-guard/context-digest-policy.yaml",
            ),
            (
                "readme_workflow_guard",
                "agent-guard workflow check --root . --policy .agent-guard/workflow-policy.yaml",
            ),
            ("readme_drift_guard", "agent-guard drift check --root ."),
            (
                "readme_report_with_drift",
                "agent-guard report --root . --context-policy .agent-guard/context-policy.yaml",
            ),
        ),
        "workflow_commands": (
            ("context", "check"),
            ("context", "lock"),
            ("digest", "check"),
            ("path", "check"),
            ("content", "check"),
            ("surface", "inventory"),
            ("workflow", "check"),
            ("drift", "check"),
            ("report", ""),
        ),
        "boundary_categories": (
            "approval_boundary",
            "tool_permission_boundary",
            "network_boundary",
            "secret_handling",
            "destructive_action_boundary",
            "local_verification",
        ),
        "report_sections": ("evidence_pack_manifest",),
        "artifact_roles": ("report",),
    },
}


def normalize_profile_name(name: str) -> str:
    profile = str(name).strip().lower() or "recommended"
    if profile not in PROFILE_REQUIREMENTS:
        raise ValueError(f"unknown conformance profile: {name}")
    return profile


def profile_requirements(name: str) -> dict[str, tuple[Any, ...]]:
    return PROFILE_REQUIREMENTS[normalize_profile_name(name)]
