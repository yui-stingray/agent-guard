"""Validate explicitly supplied agent-policy audit events against report bindings."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from ..evidence_pack import (
    build_agent_policy_audit_event_binding,
    validate_agent_policy_audit_event_binding_shape,
    validate_agent_policy_audit_event_profile,
)
from ._schema import require, require_mapping, require_sequence


ERROR_AUDIT_EVENT_BINDING_INVALID = "agent-policy audit event binding is invalid"


def _bound_audit_event_artifacts(report: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    manifest = report.get("evidence_pack_manifest")
    if manifest is None:
        return []
    manifest_obj = require_mapping(manifest, ERROR_AUDIT_EVENT_BINDING_INVALID)
    artifacts = require_sequence(
        manifest_obj.get("artifacts"),
        ERROR_AUDIT_EVENT_BINDING_INVALID,
    )
    return [
        require_mapping(item, ERROR_AUDIT_EVENT_BINDING_INVALID)
        for item in artifacts
        if isinstance(item, Mapping) and item.get("role") == "agent-policy-audit-event"
    ]


def validate_agent_policy_audit_event_files(
    report: Mapping[str, Any],
    paths: Sequence[Path],
    *,
    event_profile: str,
) -> None:
    """Pair each path positionally with the same-index bound audit artifact."""

    artifacts = _bound_audit_event_artifacts(report)
    if not artifacts:
        require(not paths and not event_profile, ERROR_AUDIT_EVENT_BINDING_INVALID)
        return
    try:
        profile = validate_agent_policy_audit_event_profile(event_profile)
    except ValueError:
        raise ValueError(ERROR_AUDIT_EVENT_BINDING_INVALID) from None
    require(len(paths) == len(artifacts), ERROR_AUDIT_EVENT_BINDING_INVALID)

    for artifact, path in zip(artifacts, paths, strict=True):
        try:
            expected = validate_agent_policy_audit_event_binding_shape(
                artifact.get("content_binding")
            )
            actual = build_agent_policy_audit_event_binding(
                path,
                event_profile=profile,
            )
        except ValueError:
            raise ValueError(ERROR_AUDIT_EVENT_BINDING_INVALID) from None
        require(
            expected.get("event_profile") == profile and actual == expected,
            ERROR_AUDIT_EVENT_BINDING_INVALID,
        )
