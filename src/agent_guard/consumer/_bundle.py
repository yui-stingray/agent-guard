"""Where: src/agent_guard/consumer/_bundle.py
What: validate the allowlisted public evidence artifact bundle.
Why: let CI consumers reuse the example's fail-closed bundle contract.
"""

from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
from importlib import resources
from itertools import islice
import json
import os
from pathlib import Path
from typing import Any

from ..report_render import render_report_output
from ._redaction import validate_public_evidence_shape, validate_public_text_shape
from ._report import validate_report
from ._schema import (
    DuplicateJSONKeyError,
    load_json_text,
    load_report_schema,
    require,
    require_int,
    require_mapping,
    require_sequence,
    validate_against_schema,
)
from ._sections import (
    validate_conformance,
    validate_evidence_pack_manifest,
    validate_surface_inventory,
)


ALLOWED_EVIDENCE_ARTIFACT_NAMES = frozenset(
    {
        "agent-guard-report.json",
        "agent-guard-report.md",
        "agent-guard-results.sarif",
        "agent-guard-annotations.txt",
        "agent-guard-conformance.json",
        "agent-guard-evidence-pack.json",
        "agent-surface-inventory.json",
    }
)
RESULT_SCHEMA = "agent-guard.result.v1.schema.json"
CONFORMANCE_SCHEMA = "agent-guard.conformance.v1.schema.json"
EVIDENCE_PACK_SCHEMA = "agent-guard.evidence_pack_manifest.v1.schema.json"

ERROR_PUBLIC_BUNDLE_INVALID = "public evidence bundle is invalid"
ERROR_PUBLIC_BUNDLE_LIMIT = "public evidence bundle exceeds configured limits"

MAX_EVIDENCE_DIRECTORY_ENTRIES = len(ALLOWED_EVIDENCE_ARTIFACT_NAMES)
MAX_REPORT_JSON_BYTES = 1 * 1024 * 1024
MAX_SARIF_JSON_BYTES = 4 * 1024 * 1024
MAX_ENVELOPE_JSON_BYTES = 1 * 1024 * 1024
MAX_MARKDOWN_BYTES = 1 * 1024 * 1024
MAX_ANNOTATIONS_BYTES = 1 * 1024 * 1024


def _read_limited_bytes(path: Path, *, limit: int) -> bytes:
    try:
        with path.open("rb") as handle:
            raw = handle.read(limit + 1)
    except OSError:
        raise ValueError(ERROR_PUBLIC_BUNDLE_INVALID) from None
    if len(raw) > limit:
        raise ValueError(ERROR_PUBLIC_BUNDLE_LIMIT)
    return raw


def _read_limited_text(path: Path, *, limit: int) -> str:
    return _decode_utf8(_read_limited_bytes(path, limit=limit))


def _decode_utf8(raw: bytes) -> str:
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError(ERROR_PUBLIC_BUNDLE_INVALID) from None


def _load_limited_json(path: Path, *, limit: int) -> object:
    return _load_json_text(_read_limited_text(path, limit=limit))


def _load_json_text(text: str) -> object:
    try:
        return load_json_text(text)
    except (DuplicateJSONKeyError, json.JSONDecodeError, RecursionError):
        raise ValueError(ERROR_PUBLIC_BUNDLE_INVALID) from None


def _load_limited_payload(path: Path, *, limit: int) -> dict[str, Any]:
    payload = _load_limited_json(path, limit=limit)
    require(isinstance(payload, dict), ERROR_PUBLIC_BUNDLE_INVALID)
    return payload


def _read_bundle_entries(evidence_dir: Path) -> tuple[Path, ...]:
    try:
        with os.scandir(evidence_dir) as directory_entries:
            entries = tuple(
                evidence_dir / entry.name
                for entry in islice(directory_entries, MAX_EVIDENCE_DIRECTORY_ENTRIES + 1)
            )
    except OSError:
        raise ValueError(ERROR_PUBLIC_BUNDLE_INVALID) from None
    require(len(entries) <= MAX_EVIDENCE_DIRECTORY_ENTRIES, ERROR_PUBLIC_BUNDLE_LIMIT)
    return entries


def _load_packaged_schema(name: str) -> dict[str, Any]:
    text = resources.files("agent_guard.schemas").joinpath(name).read_text(encoding="utf-8")
    payload = json.loads(text)
    require(isinstance(payload, dict), "packaged schema must be an object")
    return payload


def _validate_result_envelope(
    payload: dict[str, Any],
    *,
    scanner: str,
    command: str,
    report: Mapping[str, Any],
) -> None:
    validate_against_schema(_load_packaged_schema(RESULT_SCHEMA), payload, path="$.artifact")
    require(payload.get("scanner") == scanner, "artifact scanner mismatch")
    require(payload.get("command") == command, "artifact command mismatch")
    require(payload.get("tool") == report.get("tool"), "artifact tool mismatch")
    findings = require_sequence(payload.get("findings"), "$.artifact.findings")
    finding_count = payload.get("finding_count")
    require(
        isinstance(finding_count, int) and not isinstance(finding_count, bool),
        "artifact finding_count must be an integer",
    )
    require(finding_count == len(findings), "artifact finding_count mismatch")
    summary = require_mapping(payload.get("summary"), "$.artifact.summary")
    require(summary.get("finding_count") == finding_count, "artifact summary mismatch")
    status = payload.get("status")
    exit_code = payload.get("exit_code")
    if status == "ok":
        require(exit_code == 0, "ok artifact must have exit code 0")
    else:
        require(isinstance(exit_code, int) and exit_code != 0, "failing artifact needs nonzero exit code")
    validate_public_evidence_shape(payload, path="$.artifact")


def _report_artifact_policy(report: Mapping[str, Any]) -> dict[str, str]:
    manifest = require_mapping(report.get("evidence_pack_manifest"), "$.evidence_pack_manifest")
    artifacts = require_sequence(manifest.get("artifacts"), "$.evidence_pack_manifest.artifacts")
    report_paths: list[str] = []
    for index, raw_artifact in enumerate(artifacts):
        artifact = require_mapping(raw_artifact, f"$.evidence_pack_manifest.artifacts[{index}]")
        if artifact.get("role") != "report":
            continue
        path = artifact.get("path")
        require(isinstance(path, str), "evidence-pack report artifact path is invalid")
        report_paths.append(path)
    require(len(report_paths) == 1, "evidence-pack manifest must claim exactly one report artifact")
    return {"path": report_paths[0]}


def _matches_report_artifact_policy(policy: object, report: Mapping[str, Any]) -> bool:
    report_artifact_policy = _report_artifact_policy(report)
    return policy == report_artifact_policy or policy == {"path": "<external-policy>"}


def _validate_success_envelope(
    payload: Mapping[str, Any],
    *,
    artifact: str,
    scanned_count: int,
    scanned_unit: str,
) -> None:
    findings = require_sequence(payload.get("findings"), "$.artifact.findings")
    summary = require_mapping(payload.get("summary"), "$.artifact.summary")
    require(payload.get("status") == "ok", f"{artifact} artifact status mismatch")
    require(payload.get("exit_code") == 0, f"{artifact} artifact exit code mismatch")
    require(payload.get("finding_count") == 0, f"{artifact} artifact finding_count mismatch")
    require(len(findings) == 0, f"{artifact} artifact findings mismatch")
    require(summary.get("finding_count") == 0, f"{artifact} artifact summary mismatch")
    require(summary.get("scanned_count") == scanned_count, f"{artifact} artifact scanned_count mismatch")
    require(summary.get("scanned_unit") == scanned_unit, f"{artifact} artifact scanned_unit mismatch")


def _validate_conformance_envelope(
    payload: Mapping[str, Any],
    conformance: Mapping[str, Any],
) -> None:
    findings = require_sequence(payload.get("findings"), "$.artifact.findings")
    summary = require_mapping(payload.get("summary"), "$.artifact.summary")
    status = conformance.get("status")
    finding_count = conformance.get("finding_count")

    require(payload.get("status") == status, "conformance artifact status mismatch")
    require(
        payload.get("exit_code") == (0 if status == "ok" else 1),
        "conformance artifact exit code mismatch",
    )
    require(payload.get("finding_count") == finding_count, "conformance artifact finding_count mismatch")
    require(findings == conformance.get("findings"), "conformance artifact findings mismatch")
    require(summary.get("finding_count") == finding_count, "conformance artifact summary mismatch")
    require(
        summary.get("scanned_count") == conformance.get("checked_count"),
        "conformance artifact scanned_count mismatch",
    )
    require(
        summary.get("scanned_unit") == "requirements",
        "conformance artifact scanned_unit mismatch",
    )
    require(summary.get("profile") == conformance.get("profile"), "conformance artifact profile mismatch")
    require(
        summary.get("conformance_finding_count") == finding_count,
        "conformance artifact finding summary mismatch",
    )


def _validate_surface_inventory_envelope(
    payload: Mapping[str, Any],
    inventory: Mapping[str, Any],
) -> None:
    inventory_summary = require_mapping(inventory.get("summary"), "$.artifact.surface_inventory.summary")
    surface_count = require_int(
        inventory_summary.get("surface_count"),
        "$.artifact.surface_inventory.summary.surface_count",
    )
    _validate_success_envelope(
        payload,
        artifact="surface inventory",
        scanned_count=surface_count,
        scanned_unit="surfaces",
    )
    summary = require_mapping(payload.get("summary"), "$.artifact.summary")
    require(summary.get("surface_count") == surface_count, "surface inventory artifact summary mismatch")


def _validate_evidence_pack_envelope(
    payload: Mapping[str, Any],
    manifest: Mapping[str, Any],
    report: Mapping[str, Any],
) -> None:
    gates = require_sequence(manifest.get("gates"), "$.artifact.evidence_pack_manifest.gates")
    _validate_success_envelope(
        payload,
        artifact="evidence-pack",
        scanned_count=len(gates),
        scanned_unit="gates",
    )
    manifest_summary = require_mapping(
        manifest.get("summary"),
        "$.artifact.evidence_pack_manifest.summary",
    )
    report_summary = require_mapping(report.get("summary"), "$.summary")
    require(manifest.get("tool") == report.get("tool"), "evidence-pack artifact tool mismatch")
    require(
        manifest_summary.get("surface_count") == report_summary.get("surface_count", 0),
        "evidence-pack artifact surface summary mismatch",
    )


def _validate_sarif(payload: object) -> None:
    sarif = require_mapping(payload, "$.sarif")
    require(sarif.get("version") == "2.1.0", "SARIF version mismatch")
    require(
        sarif.get("$schema") == "https://json.schemastore.org/sarif-2.1.0.json",
        "SARIF schema mismatch",
    )
    controlled = deepcopy(dict(sarif))
    controlled["$schema"] = "<redacted-url>"
    runs = require_sequence(controlled.get("runs"), "$.sarif.runs")
    require(len(runs) == 1, "SARIF must contain one run")
    for run_index, raw_run in enumerate(runs):
        run = require_mapping(raw_run, f"$.sarif.runs[{run_index}]")
        tool = require_mapping(run.get("tool"), f"$.sarif.runs[{run_index}].tool")
        driver = require_mapping(tool.get("driver"), f"$.sarif.runs[{run_index}].tool.driver")
        require(driver.get("name") == "agent-guard", "SARIF driver mismatch")
        require(
            driver.get("informationUri") == "https://github.com/yui-stingray/agent-guard",
            "SARIF information URI mismatch",
        )
        if isinstance(driver, dict):
            driver["informationUri"] = "<redacted-url>"
        require_sequence(driver.get("rules"), f"$.sarif.runs[{run_index}].tool.driver.rules")
        results = require_sequence(run.get("results"), f"$.sarif.runs[{run_index}].results")
        for result_index, raw_result in enumerate(results):
            result = require_mapping(
                raw_result,
                f"$.sarif.runs[{run_index}].results[{result_index}]",
            )
            fingerprints = result.get("partialFingerprints")
            if fingerprints is None:
                continue
            fingerprint_map = require_mapping(
                fingerprints,
                f"$.sarif.runs[{run_index}].results[{result_index}].partialFingerprints",
            )
            for key, value in list(fingerprint_map.items()):
                require(
                    isinstance(value, str)
                    and len(value) == 64
                    and all(char in "0123456789abcdef" for char in value),
                    "SARIF fingerprint mismatch",
                )
                if isinstance(fingerprint_map, dict):
                    fingerprint_map[key] = "<redacted>"
    validate_public_evidence_shape(controlled, path="$.sarif")


def _validate_evidence_bundle(
    evidence_dir: Path,
    report_path: Path,
) -> tuple[dict[str, Any], bytes | None]:
    """Validate a bundle and retain the exact annotation bytes read during validation."""

    require(evidence_dir.is_dir() and not evidence_dir.is_symlink(), "evidence directory is invalid")
    for artifact in _read_bundle_entries(evidence_dir):
        require(not artifact.is_symlink(), "public artifact must not be a symlink")
        require(artifact.is_file(), "public artifact entry is invalid")
        require(artifact.name in ALLOWED_EVIDENCE_ARTIFACT_NAMES, "public artifact name is not allowlisted")

    require(report_path.is_file() and not report_path.is_symlink(), "report artifact is invalid")
    report = _load_limited_payload(report_path, limit=MAX_REPORT_JSON_BYTES)
    summary = validate_report(report, load_report_schema())

    bundle_report_path = evidence_dir / "agent-guard-report.json"
    if bundle_report_path.is_file():
        bundle_report = _load_limited_payload(bundle_report_path, limit=MAX_REPORT_JSON_BYTES)
        validate_report(bundle_report, load_report_schema())
        require(bundle_report == report, "bundle report does not match selected report")

    markdown_path = evidence_dir / "agent-guard-report.md"
    if markdown_path.is_file():
        markdown = _read_limited_text(markdown_path, limit=MAX_MARKDOWN_BYTES)
        validate_public_text_shape(markdown, path="$.markdown")
        require(
            markdown == render_report_output(report, "markdown"),
            "rendered artifact does not match selected report",
        )

    annotation_bytes: bytes | None = None
    annotations_path = evidence_dir / "agent-guard-annotations.txt"
    if annotations_path.is_file():
        annotation_bytes = _read_limited_bytes(annotations_path, limit=MAX_ANNOTATIONS_BYTES)
        annotations = _decode_utf8(annotation_bytes)
        validate_public_text_shape(annotations, path="$.annotations")
        require(
            annotations == render_report_output(report, "github-annotations"),
            "rendered artifact does not match selected report",
        )

    sarif_path = evidence_dir / "agent-guard-results.sarif"
    if sarif_path.is_file():
        sarif = _read_limited_text(sarif_path, limit=MAX_SARIF_JSON_BYTES)
        _validate_sarif(_load_json_text(sarif))
        require(
            sarif == render_report_output(report, "sarif"),
            "rendered artifact does not match selected report",
        )

    inventory_path = evidence_dir / "agent-surface-inventory.json"
    if inventory_path.is_file():
        inventory_payload = _load_limited_payload(inventory_path, limit=MAX_ENVELOPE_JSON_BYTES)
        _validate_result_envelope(
            inventory_payload,
            scanner="surface",
            command="inventory",
            report=report,
        )
        require(
            inventory_payload.get("policy") == report.get("policy"),
            "surface inventory artifact policy mismatch",
        )
        inventory = require_mapping(
            inventory_payload.get("surface_inventory"),
            "$.artifact.surface_inventory",
        )
        require(
            inventory.get("schema_version") == "agent-guard.agent_surface_inventory.v2",
            "surface inventory schema mismatch",
        )
        validate_surface_inventory(inventory)
        require(inventory == report.get("surface_inventory"), "surface inventory does not match report")
        _validate_surface_inventory_envelope(inventory_payload, inventory)

    conformance_path = evidence_dir / "agent-guard-conformance.json"
    if conformance_path.is_file():
        conformance_payload = _load_limited_payload(conformance_path, limit=MAX_ENVELOPE_JSON_BYTES)
        _validate_result_envelope(
            conformance_payload,
            scanner="conformance",
            command="check",
            report=report,
        )
        require(
            _matches_report_artifact_policy(conformance_payload.get("policy"), report),
            "conformance artifact policy mismatch",
        )
        conformance = require_mapping(conformance_payload.get("conformance"), "$.artifact.conformance")
        validate_against_schema(
            _load_packaged_schema(CONFORMANCE_SCHEMA),
            conformance,
            path="$.artifact.conformance",
        )
        validate_conformance(conformance, report)
        require(conformance == report.get("conformance"), "conformance artifact does not match report")
        _validate_conformance_envelope(conformance_payload, conformance)

    manifest_path = evidence_dir / "agent-guard-evidence-pack.json"
    if manifest_path.is_file():
        manifest_payload = _load_limited_payload(manifest_path, limit=MAX_ENVELOPE_JSON_BYTES)
        _validate_result_envelope(
            manifest_payload,
            scanner="evidence-pack",
            command="manifest",
            report=report,
        )
        require(
            _matches_report_artifact_policy(manifest_payload.get("policy"), report),
            "evidence-pack artifact policy mismatch",
        )
        manifest = require_mapping(
            manifest_payload.get("evidence_pack_manifest"),
            "$.artifact.evidence_pack_manifest",
        )
        validate_against_schema(
            _load_packaged_schema(EVIDENCE_PACK_SCHEMA),
            manifest,
            path="$.artifact.evidence_pack_manifest",
        )
        validate_evidence_pack_manifest(manifest, report)
        require(
            manifest == report.get("evidence_pack_manifest"),
            "evidence-pack manifest does not match report",
        )
        _validate_evidence_pack_envelope(manifest_payload, manifest, report)

    return summary, annotation_bytes


def validate_evidence_bundle(evidence_dir: Path, report_path: Path) -> dict[str, Any]:
    """Validate an allowlisted public evidence directory against a report file."""

    summary, _ = _validate_evidence_bundle(evidence_dir, report_path)
    return summary
