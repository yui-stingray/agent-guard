# Where: tests/cli/test_evidence_pack.py
# What: focused subprocess tests for evidence-pack manifest emission.
# Why: keep extracted evidence-pack subcommand coverage close to its module.

from __future__ import annotations

import json
from pathlib import Path

from tests.cli.helpers import run_cli


def test_evidence_pack_manifest_cli_is_sanitized(tmp_path: Path) -> None:
    report = tmp_path / "report.json"
    report.write_text(
        json.dumps(
            {
                "tool": {"name": "agent-guard", "version": "0.1.7"},
                "status": "ok",
                "finding_count": 0,
                "summary": {"surface_count": 2},
                "report": {
                    "schema_version": "agent-guard.report_evidence.v1",
                    "format": "json",
                    "scope": "context",
                },
                "evidence_coverage": {
                    "gate_count": 1,
                    "enabled_count": 1,
                    "missing_count": 0,
                    "failing_count": 0,
                    "gates": [{"gate": "context", "status": "ok", "finding_count": 0}],
                },
            }
        ),
        encoding="utf-8",
    )

    result = run_cli(
        "evidence-pack",
        "manifest",
        "--root",
        str(tmp_path),
        "--report",
        str(report),
        "--artifact",
        str(tmp_path / ".agent-guard" / "evidence" / "report.json"),
        "--artifact",
        str(tmp_path.parent / "outside-report.json"),
        "--artifact",
        r"C:\Users\alice\secret\agent-guard-report.json",
        "--artifact",
        r"\\server\share\agent-guard-report.json",
        "--agent-policy-audit-event",
        str(tmp_path / ".agent-guard" / "evidence" / "policy-admission-event.json"),
        "--json",
    )

    assert result.returncode == 0
    payload = json.loads(result.stdout)
    manifest = payload["evidence_pack_manifest"]
    assert manifest["schema_version"] == "agent-guard.evidence_pack_manifest.v1"
    assert manifest["sanitized"] is True
    assert manifest["artifacts"] == [
        {"path": ".agent-guard/evidence/report.json", "role": "report"},
        {"path": "outside-report.json", "role": "report"},
        {"path": "agent-guard-report.json", "role": "report"},
        {"path": "agent-guard-report.json", "role": "report"},
        {"path": ".agent-guard/evidence/policy-admission-event.json", "role": "agent-policy-audit-event"},
    ]
    assert str(tmp_path) not in result.stdout
    assert r"C:\Users\alice" not in result.stdout
    assert r"\\server\share" not in result.stdout


def test_evidence_pack_manifest_cli_sanitizes_copied_report_metadata(tmp_path: Path) -> None:
    secret_shaped = "AKIA" + ("A" * 16)
    raw_url = "HtTpS://example.invalid/private"
    local_path = "/home/synthetic/private/repository"
    windows_path = r"D:\synthetic\private\repository"
    unc_path = r"\\synthetic-host\private\repository"
    hash_shaped = "a" * 64
    report = tmp_path / "report.json"
    report.write_text(
        json.dumps(
            {
                "tool": {
                    "name": unc_path,
                    "version": secret_shaped,
                    "build_path": windows_path,
                },
                "status": "ok",
                "finding_count": 0,
                "summary": {"surface_count": 2},
                "report": {
                    "schema_version": "agent-guard.report_evidence.v1",
                    "format": "json",
                    "scope": local_path,
                },
                "evidence_coverage": {
                    "gate_count": 2,
                    "enabled_count": 2,
                    "missing_count": 0,
                    "failing_count": 0,
                    "gates": [
                        {"gate": raw_url, "status": "ok", "checked_count": 1, "finding_count": 0},
                        {"gate": hash_shaped, "status": "ok", "checked_count": 1, "finding_count": 0},
                    ],
                },
                "conformance": {
                    "schema_version": "agent-guard.conformance.v1",
                    "profile": "recommended",
                    "status": "ok",
                    "finding_count": 0,
                },
            }
        ),
        encoding="utf-8",
    )

    result = run_cli(
        "evidence-pack",
        "manifest",
        "--root",
        str(tmp_path),
        "--report",
        str(report),
        "--artifact",
        raw_url,
        "--agent-policy-audit-event",
        raw_url,
        "--json",
    )

    assert result.returncode == 0
    payload = json.loads(result.stdout)
    manifest = payload["evidence_pack_manifest"]
    assert manifest["sanitized"] is True
    assert manifest["tool"]["name"] == "<absolute-path>"
    assert manifest["tool"]["version"] == "<redacted>"
    assert manifest["tool"]["build_path"] == "<absolute-path>"
    assert manifest["report"]["scope"] == "<absolute-path>"
    assert manifest["gates"][0]["gate"] == "<redacted-url>"
    assert manifest["gates"][1]["gate"] == "<redacted>"
    assert manifest["conformance"]["profile"] == "recommended"
    assert manifest["artifacts"] == [
        {"path": "<redacted-url>", "role": "report"},
        {"path": "<redacted-url>", "role": "agent-policy-audit-event"},
    ]
    for value in (secret_shaped, raw_url, local_path, windows_path, unc_path, hash_shaped):
        assert value not in result.stdout
