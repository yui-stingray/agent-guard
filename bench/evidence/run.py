"""Where: bench/evidence/run.py
What: evidence integrity checks for determinism, redaction, schemas, and compat.
Why: publish deterministic contract-quality measurements for agent-guard.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

try:
    from .fixture_repo import SEEDED_VALUES, write_fixture_repo
except ImportError:
    from fixture_repo import SEEDED_VALUES, write_fixture_repo


RESULT_SCHEMA_VERSION = "agent-guard.evidence_results.v1"
VOLATILE_KEYS = frozenset({"generated_at"})


@dataclass(frozen=True)
class CheckResult:
    name: str
    passed: bool
    message: str
    details: dict[str, object] = field(default_factory=dict)

    def to_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "status": "ok" if self.passed else "fail",
            "message": self.message,
            **({"details": self.details} if self.details else {}),
        }


def normalize_for_determinism(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: normalize_for_determinism(item)
            for key, item in sorted(value.items())
            if key not in VOLATILE_KEYS
        }
    if isinstance(value, list):
        return [normalize_for_determinism(item) for item in value]
    return value


def find_seed_hits(paths: list[Path], seeded_values: list[str] | tuple[str, ...]) -> dict[str, list[str]]:
    hits: dict[str, list[str]] = {}
    for path in paths:
        text = path.read_text(encoding="utf-8", errors="replace")
        for value in seeded_values:
            if value in text:
                hits.setdefault(value, []).append(path.name)
    return hits


def validate_schema(schema: dict[str, Any], payload: Any, *, label: str) -> None:
    try:
        import jsonschema  # type: ignore[import-not-found]
    except Exception:
        from examples.evidence_consumer import validate_against_schema

        validate_against_schema(schema, payload, path=f"$.{label}")
        return
    jsonschema.Draft202012Validator(schema).validate(payload)


def load_schema(repo_root: Path, name: str) -> dict[str, Any]:
    path = repo_root / "src" / "agent_guard" / "schemas" / name
    loaded = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(loaded, dict):
        raise ValueError(f"schema must be a JSON object: {name}")
    return loaded


def command_env(repo_root: Path) -> dict[str, str]:
    env = os.environ.copy()
    src_path = str((repo_root / "src").resolve())
    env["PYTHONPATH"] = src_path if not env.get("PYTHONPATH") else f"{src_path}{os.pathsep}{env['PYTHONPATH']}"
    return env


def run_cli(repo_root: Path, args: list[str], *, allowed_exit_codes: tuple[int, ...]) -> str:
    result = subprocess.run(
        [sys.executable, "-m", "agent_guard.cli", *args],
        cwd=repo_root,
        env=command_env(repo_root),
        text=True,
        capture_output=True,
        check=False,
        timeout=60,
    )
    if result.returncode not in allowed_exit_codes:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip() or f"exit {result.returncode}")
    return result.stdout


def run_report_json(repo_root: Path, fixture_root: Path) -> dict[str, Any]:
    output = run_cli(
        repo_root,
        [
            "report",
            "--root",
            str(fixture_root),
            "--context-policy",
            ".agent-guard/context-policy.yaml",
            "--evidence-preset",
            "recommended",
            "--format",
            "json",
        ],
        allowed_exit_codes=(0, 1),
    )
    loaded = json.loads(output)
    if not isinstance(loaded, dict):
        raise ValueError("report output must be a JSON object")
    return loaded


def run_evidence_manifest_json(repo_root: Path, fixture_root: Path, report_path: Path) -> dict[str, Any]:
    output = run_cli(
        repo_root,
        [
            "evidence-pack",
            "manifest",
            "--root",
            str(fixture_root),
            "--report",
            str(report_path),
            "--artifact",
            str(report_path),
            "--json",
        ],
        allowed_exit_codes=(0,),
    )
    loaded = json.loads(output)
    if not isinstance(loaded, dict):
        raise ValueError("manifest output must be a JSON object")
    return loaded


def run_determinism_check(repo_root: Path, work_root: Path) -> CheckResult:
    fixture_root = work_root / "determinism-repo"
    write_fixture_repo(fixture_root)
    first = normalize_for_determinism(run_report_json(repo_root, fixture_root))
    second = normalize_for_determinism(run_report_json(repo_root, fixture_root))
    return CheckResult("determinism", first == second, "report output is stable outside volatile fields")


def run_redaction_check(repo_root: Path, work_root: Path) -> CheckResult:
    fixture_root = work_root / "redaction-repo"
    write_fixture_repo(fixture_root)
    report = run_report_json(repo_root, fixture_root)
    report_path = work_root / "redaction-report.json"
    report_path.write_text(json.dumps(report, ensure_ascii=False, sort_keys=True), encoding="utf-8")
    manifest = run_evidence_manifest_json(repo_root, fixture_root, report_path)
    manifest_path = work_root / "redaction-manifest.json"
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, sort_keys=True), encoding="utf-8")
    hits = find_seed_hits([report_path, manifest_path], SEEDED_VALUES)
    return CheckResult("redaction", not hits, "seeded sensitive values are absent from evidence artifacts", {"hits": hits})


def run_schema_check(repo_root: Path, work_root: Path) -> CheckResult:
    fixture_root = work_root / "schema-repo"
    write_fixture_repo(fixture_root)
    report = run_report_json(repo_root, fixture_root)
    report_path = work_root / "schema-report.json"
    report_path.write_text(json.dumps(report, ensure_ascii=False, sort_keys=True), encoding="utf-8")
    manifest_envelope = run_evidence_manifest_json(repo_root, fixture_root, report_path)
    manifest = manifest_envelope.get("evidence_pack_manifest", {})
    validate_schema(load_schema(repo_root, "agent-guard.report_evidence.v1.schema.json"), report, label="report")
    validate_schema(load_schema(repo_root, "agent-guard.result.v1.schema.json"), manifest_envelope, label="manifest_envelope")
    validate_schema(
        load_schema(repo_root, "agent-guard.evidence_pack_manifest.v1.schema.json"),
        manifest,
        label="manifest",
    )
    return CheckResult("schema_validation", True, "report and evidence-pack JSON outputs match packaged schemas")


def run_backward_compat_check(repo_root: Path, work_root: Path) -> CheckResult:
    golden_dir = repo_root / "bench" / "evidence" / "golden"
    golden_reports = sorted(golden_dir.glob("*.json"))
    if not golden_reports:
        return CheckResult("backward_compat", False, "no golden evidence reports found")
    for path in golden_reports:
        result = subprocess.run(
            [sys.executable, str(repo_root / "examples" / "evidence_consumer.py"), str(path)],
            cwd=repo_root,
            env=command_env(repo_root),
            text=True,
            capture_output=True,
            check=False,
            timeout=60,
        )
        if result.returncode != 0:
            return CheckResult("backward_compat", False, result.stderr.strip() or result.stdout.strip(), {"golden": path.name})
    return CheckResult("backward_compat", True, "golden evidence reports remain accepted", {"golden_count": len(golden_reports)})


def build_results(repo_root: Path, work_root: Path, *, out_path: Path | None = None) -> dict[str, object]:
    checks: list[Callable[[Path, Path], CheckResult]] = [
        run_determinism_check,
        run_redaction_check,
        run_schema_check,
        run_backward_compat_check,
    ]
    work_root.mkdir(parents=True, exist_ok=True)
    results: list[CheckResult] = []
    for check in checks:
        try:
            results.append(check(repo_root, work_root))
        except Exception as exc:
            results.append(CheckResult(check.__name__.removeprefix("run_").removesuffix("_check"), False, str(exc)))
    passed = sum(1 for item in results if item.passed)
    payload: dict[str, object] = {
        "schema_version": RESULT_SCHEMA_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "status": "ok" if passed == len(results) else "fail",
        "summary": {"passed": passed, "failed": len(results) - passed},
        "checks": [item.to_dict() for item in results],
    }
    if out_path is not None:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return payload


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="run agent-guard evidence integrity checks")
    parser.add_argument("--repo-root", default=".", help="agent-guard repository root")
    parser.add_argument("--work-dir", default="", help="optional working directory for generated fixture repos")
    parser.add_argument("--out", default="", help="optional JSON result path")
    args = parser.parse_args(argv)
    repo_root = Path(args.repo_root).resolve()
    default_out = repo_root / "bench" / "results" / f"evidence-{datetime.now(timezone.utc):%Y%m%d}.json"
    out_path = Path(args.out).resolve() if args.out else default_out
    if args.work_dir:
        payload = build_results(repo_root, Path(args.work_dir).resolve(), out_path=out_path)
    else:
        with tempfile.TemporaryDirectory(prefix="agent-guard-evidence-") as tmp:
            payload = build_results(repo_root, Path(tmp), out_path=out_path)
    print(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if payload["status"] == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())
