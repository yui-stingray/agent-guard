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


def _audit_event_artifacts(
    report: Mapping[str, Any],
) -> tuple[str, list[Mapping[str, Any]]]:
    manifest = report.get("evidence_pack_manifest")
    if manifest is None:
        return "", []
    manifest_obj = require_mapping(manifest, ERROR_AUDIT_EVENT_BINDING_INVALID)
    manifest_version = manifest_obj.get("schema_version")
    require(
        manifest_version
        in {
            "agent-guard.evidence_pack_manifest.v1",
            "agent-guard.evidence_pack_manifest.v2",
        },
        ERROR_AUDIT_EVENT_BINDING_INVALID,
    )
    artifacts = require_sequence(
        manifest_obj.get("artifacts"),
        ERROR_AUDIT_EVENT_BINDING_INVALID,
    )
    return str(manifest_version), [
        require_mapping(item, ERROR_AUDIT_EVENT_BINDING_INVALID)
        for item in artifacts
        if isinstance(item, Mapping)
        and item.get("role") == "agent-policy-audit-event"
    ]


def validate_agent_policy_audit_event_files(
    report: Mapping[str, Any],
    paths: Sequence[Path],
    *,
    event_profile: str,
) -> None:
    """Pair each path positionally with the same-index bound audit artifact."""

    manifest_version, artifacts = _audit_event_artifacts(report)
    if manifest_version == "agent-guard.evidence_pack_manifest.v1":
        require(not paths and not event_profile, ERROR_AUDIT_EVENT_BINDING_INVALID)
        return
    if not manifest_version:
        report_metadata = report.get("report")
        is_v2_report = (
            isinstance(report_metadata, Mapping)
            and report_metadata.get("schema_version")
            == "agent-guard.report_evidence.v2"
        )
        require(
            not is_v2_report and not paths and not event_profile,
            ERROR_AUDIT_EVENT_BINDING_INVALID,
        )
        return
    require(
        manifest_version == "agent-guard.evidence_pack_manifest.v2" and bool(artifacts),
        ERROR_AUDIT_EVENT_BINDING_INVALID,
    )
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
