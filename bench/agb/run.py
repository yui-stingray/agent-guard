"""Where: bench/agb/run.py
What: offline Agent-Guard Bench runner and scorer.
Why: publish deterministic detection-quality numbers for agent-guard.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

DEFAULT_GUARDS = ("context", "content", "path", "mcp")
RESULT_SCHEMA_VERSION = "agent-guard.agb_results.v1"


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
        payload = {"guard": self.guard, "rule": self.rule, "path": self.path}
        if self.reason:
            payload["reason"] = self.reason
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
            "case_id": self.case_id,
            "guards": self.guards,
            "counts": self.counts,
            "metrics": metrics_from_counts(self.counts),
            "by_guard": {guard: item.to_dict() for guard, item in self.by_guard.items()},
            "false_positives": [item.to_dict() for item in self.false_positives],
            "false_negatives": [item.to_dict() for item in self.false_negatives],
            "forbidden_hits": [item.to_dict() for item in self.forbidden_hits],
            "errors": self.errors,
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


def spec_from_expected(item: object) -> FindingSpec:
    if not isinstance(item, dict):
        raise ValueError("expected finding entries must be objects")
    return FindingSpec(
        guard=str(item.get("guard", "")).strip(),
        rule=str(item.get("rule", item.get("rule_id", ""))).strip(),
        path=str(item.get("path", item.get("file", ""))).strip(),
        reason=str(item.get("reason", "")).strip(),
    )


def normalize_finding(guard: str, finding: object) -> FindingSpec | None:
    if not isinstance(finding, dict):
        return None
    rule = str(finding.get("rule_id", finding.get("check_id", finding.get("rule", "")))).strip()
    path = str(finding.get("path", finding.get("file", finding.get("target", "")))).strip()
    if not rule or not path:
        return None
    return FindingSpec(
        guard=guard,
        rule=rule,
        path=path,
        reason=str(finding.get("reason", "")).strip(),
    )


def expected_specs(payload: dict[str, Any], key: str) -> list[FindingSpec]:
    raw_items = payload.get(key, [])
    if not isinstance(raw_items, list):
        raise ValueError(f"{key} must be a list")
    return [spec_from_expected(item) for item in raw_items]


def declared_guards(payload: dict[str, Any]) -> list[str]:
    raw = payload.get("guards", [])
    if isinstance(raw, list) and raw:
        return [str(item).strip() for item in raw if str(item).strip()]
    guards = {item.guard for item in expected_specs(payload, "expected_findings")}
    guards.update(item.guard for item in expected_specs(payload, "forbidden_findings"))
    return sorted(guards) or list(DEFAULT_GUARDS)


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
    expected = expected_specs(payload, "expected_findings")
    forbidden = expected_specs(payload, "forbidden_findings")
    by_guard: dict[str, GuardResult] = {}
    false_positives: list[FindingSpec] = []
    false_negatives: list[FindingSpec] = []
    forbidden_hits: list[FindingSpec] = []
    errors: dict[str, str] = {}

    for guard in guards:
        raw_findings = guard_outputs.get(guard, {}).get("findings", [])
        actual = [item for item in (normalize_finding(guard, finding) for finding in raw_findings) if item]
        expected_for_guard = [item for item in expected if item.guard == guard]
        counts, guard_fp, guard_fn = score_guard(expected_for_guard, actual)
        by_guard[guard] = GuardResult(counts=counts)
        false_positives.extend(guard_fp)
        false_negatives.extend(guard_fn)
        forbidden_hits.extend(actual_item for actual_item in actual if any(item.matches(actual_item) for item in forbidden))
        error = guard_outputs.get(guard, {}).get("runner_error")
        if error:
            errors[guard] = str(error)

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
    raise ValueError(f"unsupported AGB guard: {guard}")


def run_guard(repo_root: Path, case_root: Path, guard: str) -> dict[str, Any]:
    env = os.environ.copy()
    src_path = str((repo_root / "src").resolve())
    env["PYTHONPATH"] = src_path if not env.get("PYTHONPATH") else f"{src_path}{os.pathsep}{env['PYTHONPATH']}"
    result = subprocess.run(
        [os.sys.executable, "-m", "agent_guard.cli", *guard_command(case_root, guard)],
        cwd=repo_root,
        env=env,
        text=True,
        capture_output=True,
        check=False,
        timeout=30,
    )
    try:
        loaded = json.loads(result.stdout)
    except json.JSONDecodeError:
        return {"exit_code": result.returncode, "findings": [], "runner_error": result.stderr.strip() or result.stdout.strip()}
    return loaded if isinstance(loaded, dict) else {"exit_code": result.returncode, "findings": []}


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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="run Agent-Guard Bench fixtures")
    parser.add_argument("--repo-root", default=".", help="agent-guard repository root")
    parser.add_argument("--fixtures", default="bench/agb/fixtures", help="AGB fixture directory")
    parser.add_argument("--out", default="", help="optional JSON result path")
    args = parser.parse_args(argv)
    repo_root = Path(args.repo_root).resolve()
    fixtures_root = (repo_root / args.fixtures).resolve() if not Path(args.fixtures).is_absolute() else Path(args.fixtures)
    payload = build_results(repo_root, fixtures_root)
    text = json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True)
    if args.out:
        out_path = Path(args.out)
        out_path = (repo_root / out_path).resolve() if not out_path.is_absolute() else out_path
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(text + "\n", encoding="utf-8")
    print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
