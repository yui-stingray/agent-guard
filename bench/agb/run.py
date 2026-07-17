"""Where: bench/agb/run.py
What: offline Agent-Guard Bench runner and scorer.
Why: publish deterministic detection-quality numbers for agent-guard.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path, PureWindowsPath
from typing import Any, Callable

DEFAULT_GUARDS = ("context", "content", "path", "mcp", "digest", "drift")
RESULT_SCHEMA_VERSION = "agent-guard.agb_results.v1"
VALID_GUARD_EXIT_CODES = {0, 1}
RUNNER_ERROR_LABELS = {
    "runner_configuration_error",
    "runner_execution_error",
    "runner_invalid_json",
    "runner_invalid_json_type",
    "runner_timeout",
}
BENCHMARK_ERROR_LABELS = {
    "benchmark_fixture_error",
    "benchmark_output_error",
}
POSIX_ABSOLUTE_TEXT_RE = re.compile(
    r"(?<![A-Za-z0-9_.<>/\\-])/(?:[^/\s:'\"`]+/)*[^/\s:'\"`]+"
)
WINDOWS_ABSOLUTE_TEXT_RE = re.compile(
    r"(?<![A-Za-z0-9_])[A-Za-z]:[\\/](?:[^\\/\s:'\"`]+[\\/])*[^\\/\s:'\"`]+"
)


@dataclass(frozen=True)
class FindingSpec:
    guard: str
    rule: str
    path: str
    reason: str = ""

    def matches(self, actual: "FindingSpec") -> bool:
        return (
            self.guard == actual.guard
            and self.rule == actual.rule
            and self.path == actual.path
            and (not self.reason or self.reason == actual.reason)
        )

    def to_dict(self) -> dict[str, str]:
        payload = {
            "guard": redact_benchmark_text(self.guard),
            "rule": redact_benchmark_text(self.rule),
            "path": public_output_path(self.path),
        }
        if self.reason:
            payload["reason"] = redact_benchmark_text(self.reason)
        return payload


@dataclass
class GuardResult:
    counts: dict[str, int]

    def to_dict(self) -> dict[str, object]:
        return metrics_from_counts(self.counts)


@dataclass
class CaseResult:
    case_id: str
    guards: list[str]
    counts: dict[str, int]
    by_guard: dict[str, GuardResult]
    false_positives: list[FindingSpec] = field(default_factory=list)
    false_negatives: list[FindingSpec] = field(default_factory=list)
    forbidden_hits: list[FindingSpec] = field(default_factory=list)
    errors: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, object]:
        return {
            "case_id": redact_benchmark_text(self.case_id),
            "guards": [redact_benchmark_text(guard) for guard in self.guards],
            "counts": self.counts,
            "metrics": metrics_from_counts(self.counts),
            "by_guard": {
                redact_benchmark_text(guard): item.to_dict()
                for guard, item in self.by_guard.items()
            },
            "false_positives": [item.to_dict() for item in self.false_positives],
            "false_negatives": [item.to_dict() for item in self.false_negatives],
            "forbidden_hits": [item.to_dict() for item in self.forbidden_hits],
            "errors": {
                redact_benchmark_text(guard): public_runner_error(error)
                for guard, error in self.errors.items()
            },
        }


def metrics_from_counts(counts: dict[str, int]) -> dict[str, object]:
    tp = int(counts.get("tp", 0))
    fp = int(counts.get("fp", 0))
    fn = int(counts.get("fn", 0))
    precision = 1.0 if tp + fp == 0 else tp / (tp + fp)
    recall = 1.0 if tp + fn == 0 else tp / (tp + fn)
    f1 = 1.0 if precision + recall == 0 else 2 * precision * recall / (precision + recall)
    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "precision": round(precision, 6),
        "recall": round(recall, 6),
        "f1": round(f1, 6),
    }


def load_expected(case_dir: Path) -> dict[str, Any]:
    loaded = json.loads((case_dir / "expected.json").read_text(encoding="utf-8"))
    if not isinstance(loaded, dict):
        raise ValueError(f"expected.json must be an object: {case_dir}")
    return loaded


def spec_from_expected(item: object, case_root: Path | None = None) -> FindingSpec:
    if not isinstance(item, dict):
        raise ValueError("expected finding entries must be objects")
    guard = required_fixture_text(item, ("guard",), "guard")
    if guard not in DEFAULT_GUARDS:
        raise ValueError("unsupported AGB guard")
    rule = required_fixture_text(item, ("rule", "rule_id"), "rule")
    path = required_fixture_text(item, ("path", "file"), "path")
    reason = optional_fixture_text(item, "reason")
    return FindingSpec(
        guard=guard,
        rule=rule,
        path=normalize_scoring_path(path, case_root) if case_root is not None else path,
        reason=reason,
    )


def required_fixture_text(item: dict[str, object], keys: tuple[str, ...], label: str) -> str:
    for key in keys:
        if key in item:
            value = item[key]
            if isinstance(value, str) and value.strip():
                return value.strip()
            raise ValueError(f"expected finding {label} must be a non-empty string")
    raise ValueError(f"expected finding {label} must be a non-empty string")


def optional_fixture_text(item: dict[str, object], key: str) -> str:
    if key not in item:
        return ""
    value = item[key]
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"expected finding {key} must be a non-empty string when present")
    return value.strip()


@lru_cache(maxsize=1)
def _public_redactor() -> Callable[[str], str]:
    module_path = Path(__file__).resolve().parents[2] / "src" / "agent_guard" / "public_redaction.py"
    spec = importlib.util.spec_from_file_location("_agb_public_redaction", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("public redaction helper unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    redactor = getattr(module, "redact_public_text", None)
    if not callable(redactor):
        raise RuntimeError("public redaction helper unavailable")
    return redactor


def redact_public_text(text: str) -> str:
    return _public_redactor()(text)


def redact_benchmark_text(text: str) -> str:
    redacted = redact_public_text(text)
    redacted = WINDOWS_ABSOLUTE_TEXT_RE.sub("<absolute-path>", redacted)
    return POSIX_ABSOLUTE_TEXT_RE.sub("<absolute-path>", redacted)


def normalize_scoring_path(path: str, case_root: Path) -> str:
    candidate = Path(path)
    if not candidate.is_absolute():
        return path
    try:
        return candidate.resolve().relative_to(case_root.resolve()).as_posix()
    except ValueError:
        return path


def public_output_path(path: str) -> str:
    if Path(path).is_absolute() or PureWindowsPath(path).is_absolute():
        return "<absolute-path>"
    return redact_benchmark_text(path)


def public_finding_path(path: str, case_root: Path) -> str:
    return public_output_path(normalize_scoring_path(path, case_root))


def public_runner_error(error: object) -> str:
    label = str(error)
    return label if label in RUNNER_ERROR_LABELS else "runner_execution_error"


def public_benchmark_error(error: object) -> str:
    label = str(error)
    return label if label in BENCHMARK_ERROR_LABELS else "benchmark_fixture_error"


def finding_text(finding: dict[str, object], keys: tuple[str, ...]) -> str | None:
    for key in keys:
        if key in finding:
            value = finding[key]
            if not isinstance(value, str):
                return None
            return value.strip() or None
    return None


def normalize_finding(guard: str, finding: object, case_root: Path) -> FindingSpec | None:
    if not isinstance(finding, dict):
        return None
    rule = finding_text(finding, ("rule_id", "check_id", "rule"))
    path = finding_text(finding, ("path", "file", "target"))
    if not rule or not path:
        return None
    reason = finding.get("reason", "")
    if not isinstance(reason, str):
        return None
    return FindingSpec(
        guard=guard,
        rule=rule,
        path=normalize_scoring_path(path, case_root),
        reason=reason.strip(),
    )


def expected_specs(payload: dict[str, Any], key: str, case_root: Path | None = None) -> list[FindingSpec]:
    raw_items = payload.get(key, [])
    if not isinstance(raw_items, list):
        raise ValueError(f"{key} must be a list")
    return [spec_from_expected(item, case_root) for item in raw_items]


def declared_guards(payload: dict[str, Any]) -> list[str]:
    raw = payload.get("guards", [])
    if not isinstance(raw, list):
        raise ValueError("AGB guards must be a list")
    if raw:
        if any(not isinstance(item, str) or not item.strip() for item in raw):
            raise ValueError("AGB guards must contain non-empty strings")
        guards = [item.strip() for item in raw]
    else:
        inferred = {item.guard for item in expected_specs(payload, "expected_findings")}
        inferred.update(item.guard for item in expected_specs(payload, "forbidden_findings"))
        guards = sorted(inferred) or list(DEFAULT_GUARDS)
    if len(set(guards)) != len(guards):
        raise ValueError("AGB guards must be unique")
    if any(guard not in DEFAULT_GUARDS for guard in guards):
        raise ValueError("unsupported AGB guard")
    finding_guards = {item.guard for item in expected_specs(payload, "expected_findings")}
    finding_guards.update(item.guard for item in expected_specs(payload, "forbidden_findings"))
    if any(guard not in guards for guard in finding_guards):
        raise ValueError("expected finding guard must be declared")
    return guards


def score_guard(expected: list[FindingSpec], actual: list[FindingSpec]) -> tuple[dict[str, int], list[FindingSpec], list[FindingSpec]]:
    matched_actual: set[int] = set()
    false_negatives: list[FindingSpec] = []
    for expected_item in expected:
        for index, actual_item in enumerate(actual):
            if index not in matched_actual and expected_item.matches(actual_item):
                matched_actual.add(index)
                break
        else:
            false_negatives.append(expected_item)
    false_positives = [item for index, item in enumerate(actual) if index not in matched_actual]
    return (
        {"tp": len(matched_actual), "fp": len(false_positives), "fn": len(false_negatives)},
        false_positives,
        false_negatives,
    )


def evaluate_case(case_dir: Path, guard_outputs: dict[str, dict[str, Any]]) -> CaseResult:
    payload = load_expected(case_dir)
    case_id = str(payload.get("case_id", case_dir.name)).strip() or case_dir.name
    guards = declared_guards(payload)
    expected = expected_specs(payload, "expected_findings", case_dir)
    forbidden = expected_specs(payload, "forbidden_findings", case_dir)
    by_guard: dict[str, GuardResult] = {}
    false_positives: list[FindingSpec] = []
    false_negatives: list[FindingSpec] = []
    forbidden_hits: list[FindingSpec] = []
    errors: dict[str, str] = {}

    for guard in guards:
        raw_findings = guard_outputs.get(guard, {}).get("findings", [])
        actual = [item for item in (normalize_finding(guard, finding, case_dir) for finding in raw_findings) if item]
        expected_for_guard = [item for item in expected if item.guard == guard]
        counts, guard_fp, guard_fn = score_guard(expected_for_guard, actual)
        by_guard[guard] = GuardResult(counts=counts)
        false_positives.extend(guard_fp)
        false_negatives.extend(guard_fn)
        forbidden_hits.extend(actual_item for actual_item in actual if any(item.matches(actual_item) for item in forbidden))
        error = guard_outputs.get(guard, {}).get("runner_error")
        if error:
            errors[guard] = public_runner_error(error)

    totals = {"tp": 0, "fp": 0, "fn": 0}
    for item in by_guard.values():
        for key in totals:
            totals[key] += item.counts[key]
    return CaseResult(
        case_id=case_id,
        guards=guards,
        counts=totals,
        by_guard=by_guard,
        false_positives=false_positives,
        false_negatives=false_negatives,
        forbidden_hits=forbidden_hits,
        errors=errors,
    )


def guard_command(case_root: Path, guard: str) -> list[str]:
    policies = case_root / "policies"
    if guard == "context":
        return ["context", "check", "--root", str(case_root), "--policy", str(policies / "context-policy.yaml"), "--json"]
    if guard == "content":
        return ["content", "check", "--repo-root", str(case_root), "--policy", str(policies / "content-policy.yaml"), "--mode", "registered", "--scan-dir", ".", "--json"]
    if guard == "path":
        return ["path", "check", "--root", str(case_root), "--policy", str(policies / "path-policy.yaml"), "--json"]
    if guard == "mcp":
        return ["mcp", "check", "--root", str(case_root), "--policy", str(policies / "mcp-policy.yaml"), "--json"]
    if guard == "digest":
        return ["digest", "check", "--root", str(case_root), "--policy", str(policies / "digest-policy.yaml"), "--json"]
    if guard == "drift":
        return ["drift", "check", "--root", str(case_root), "--profile", "recommended", "--schema-version", "v2", "--json"]
    raise ValueError(f"unsupported AGB guard: {guard}")


def run_guard(repo_root: Path, case_root: Path, guard: str) -> dict[str, Any]:
    env = os.environ.copy()
    src_path = str((repo_root / "src").resolve())
    env["PYTHONPATH"] = src_path if not env.get("PYTHONPATH") else f"{src_path}{os.pathsep}{env['PYTHONPATH']}"
    try:
        command = [os.sys.executable, "-m", "agent_guard.cli", *guard_command(case_root, guard)]
    except ValueError:
        return {"exit_code": 2, "findings": [], "runner_error": "runner_configuration_error"}
    try:
        result = subprocess.run(
            command,
            cwd=repo_root,
            env=env,
            text=True,
            capture_output=True,
            check=False,
            timeout=30,
        )
    except subprocess.TimeoutExpired:
        return {"exit_code": 2, "findings": [], "runner_error": "runner_timeout"}
    except OSError:
        return {"exit_code": 2, "findings": [], "runner_error": "runner_execution_error"}
    try:
        loaded = json.loads(result.stdout)
    except json.JSONDecodeError:
        return {"exit_code": result.returncode, "findings": [], "runner_error": "runner_invalid_json"}
    if not isinstance(loaded, dict):
        return {"exit_code": result.returncode, "findings": [], "runner_error": "runner_invalid_json_type"}
    if result.returncode not in VALID_GUARD_EXIT_CODES:
        return {"exit_code": result.returncode, "findings": [], "runner_error": "runner_execution_error"}
    findings = loaded.get("findings")
    if not isinstance(findings, list) or any(
        normalize_finding(guard, finding, case_root) is None for finding in findings
    ):
        return {"exit_code": result.returncode, "findings": [], "runner_error": "runner_invalid_json_type"}
    return {"exit_code": result.returncode, "findings": findings}


def run_case(repo_root: Path, case_dir: Path) -> CaseResult:
    payload = load_expected(case_dir)
    outputs = {guard: run_guard(repo_root, case_dir, guard) for guard in declared_guards(payload)}
    return evaluate_case(case_dir, outputs)


def discover_cases(fixtures_root: Path) -> list[Path]:
    return sorted(path for path in fixtures_root.iterdir() if (path / "expected.json").is_file())


def aggregate(results: list[CaseResult]) -> tuple[dict[str, object], dict[str, object]]:
    totals = {"tp": 0, "fp": 0, "fn": 0}
    by_guard_counts: dict[str, dict[str, int]] = {}
    for result in results:
        for key in totals:
            totals[key] += result.counts[key]
        for guard, guard_result in result.by_guard.items():
            counts = by_guard_counts.setdefault(guard, {"tp": 0, "fp": 0, "fn": 0})
            for key in counts:
                counts[key] += guard_result.counts[key]
    return metrics_from_counts(totals), {guard: metrics_from_counts(counts) for guard, counts in sorted(by_guard_counts.items())}


def build_results(repo_root: Path, fixtures_root: Path) -> dict[str, object]:
    case_results = [run_case(repo_root, case_dir) for case_dir in discover_cases(fixtures_root)]
    overall, by_guard = aggregate(case_results)
    return {
        "schema_version": RESULT_SCHEMA_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "case_count": len(case_results),
        "overall": overall,
        "by_guard": by_guard,
        "cases": [item.to_dict() for item in case_results],
    }


def has_runner_errors(payload: dict[str, object]) -> bool:
    if "benchmark_error" in payload:
        return True
    if "cases" not in payload:
        return False
    cases = payload["cases"]
    if not isinstance(cases, list):
        return True
    for case in cases:
        if not isinstance(case, dict):
            return True
        if "errors" in case and case["errors"] != {}:
            return True
    return False


def benchmark_error_payload(error: object = "benchmark_fixture_error") -> dict[str, object]:
    return {
        "schema_version": RESULT_SCHEMA_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "case_count": 0,
        "overall": metrics_from_counts({"tp": 0, "fp": 0, "fn": 0}),
        "by_guard": {},
        "cases": [],
        "benchmark_error": {"type": public_benchmark_error(error)},
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="run Agent-Guard Bench fixtures")
    parser.add_argument("--repo-root", default=".", help="agent-guard repository root")
    parser.add_argument("--fixtures", default="bench/agb/fixtures", help="AGB fixture directory")
    parser.add_argument("--out", default="", help="optional JSON result path")
    args = parser.parse_args(argv)
    repo_root = Path(args.repo_root).resolve()
    fixtures_root = (repo_root / args.fixtures).resolve() if not Path(args.fixtures).is_absolute() else Path(args.fixtures)
    try:
        payload = build_results(repo_root, fixtures_root)
    except Exception:
        payload = benchmark_error_payload()
    text = json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True)
    if args.out:
        try:
            out_path = Path(args.out)
            out_path = (repo_root / out_path).resolve() if not out_path.is_absolute() else out_path
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(text + "\n", encoding="utf-8")
        except Exception:
            payload = benchmark_error_payload("benchmark_output_error")
            text = json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True)
    print(text)
    return 2 if has_runner_errors(payload) else 0


if __name__ == "__main__":
    raise SystemExit(main())
