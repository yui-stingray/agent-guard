#!/usr/bin/env sh
# Where: examples/evidence_contracts_ci.sh
# What: runnable CI examples for consuming sanitized agent-guard evidence.
# Why: show fail-closed downstream contracts without adding scanner logic.

set -eu

mode="${1:-consume}"
root="${AGENT_GUARD_ROOT:-.}"
evidence_dir="${AGENT_GUARD_EVIDENCE_DIR:-.agent-guard/evidence}"
report_json="${AGENT_GUARD_REPORT_JSON:-$evidence_dir/agent-guard-report.json}"
work_dir="${AGENT_GUARD_WORK_DIR:-${RUNNER_TEMP:-/tmp}/agent-guard-evidence-contracts}"
agent_guard="${AGENT_GUARD_BIN:-agent-guard}"
python_bin="${PYTHON_BIN:-python}"

mkdir -p "$work_dir"

run_agent_guard() {
  $agent_guard "$@"
}

validate_report() {
  "$python_bin" -m agent_guard.consumer "$1" >/dev/null
}

generate_recommended_report() {
  run_agent_guard report \
    --root "$root" \
    --context-policy .agent-guard/context-policy.yaml \
    --evidence-preset recommended \
    --mcp-policy .agent-guard/mcp-policy.yaml \
    --format json \
    --output "$report_json"
}

generate_strict_report() {
  run_agent_guard report \
    --root "$root" \
    --context-policy .agent-guard/context-policy.yaml \
    --evidence-preset recommended \
    --mcp-policy .agent-guard/mcp-policy.yaml \
    --digest-policy .agent-guard/context-digest-policy.yaml \
    --conformance-profile strict \
    --evidence-pack-manifest \
    --format json \
    --output "$report_json"
}

render_public_artifacts() {
  run_agent_guard render-report \
    --root "$root" \
    --input "$report_json" \
    --format markdown \
    --output "$evidence_dir/agent-guard-report.md"
  run_agent_guard render-report \
    --root "$root" \
    --input "$report_json" \
    --format sarif \
    --output "$evidence_dir/agent-guard-results.sarif"
  run_agent_guard render-report \
    --root "$root" \
    --input "$report_json" \
    --format github-annotations \
    > "$evidence_dir/agent-guard-annotations.txt"
}

lint_public_artifact_names() {
  if [ ! -d "$evidence_dir" ]; then
    echo "agent-guard evidence directory missing: $evidence_dir" >&2
    return 1
  fi
  find "$evidence_dir" -type f | while IFS= read -r path; do
    rel="${path#"$evidence_dir"/}"
    case "$rel" in
      agent-guard-report.json|\
      agent-guard-report.md|\
      agent-guard-results.sarif|\
      agent-guard-annotations.txt|\
      agent-guard-conformance.json|\
      agent-guard-evidence-pack.json|\
      agent-surface-inventory.json)
        ;;
      *)
        echo "not a public agent-guard evidence artifact: $rel" >&2
        return 1
        ;;
    esac
  done
}

restore_evidence_dir() {
  if [ "${restore_evidence:-0}" = "1" ]; then
    if [ -d "$evidence_dir" ]; then
      generated_parent="$(mktemp -d "$work_dir/generated-evidence.XXXXXX")"
      mv "$evidence_dir" "$generated_parent/evidence"
    fi
    mkdir -p "$(dirname "$evidence_dir")"
    mv "$backup_evidence_dir" "$evidence_dir"
  fi
}

consume_report() {
  validate_report "$report_json"
  original_report="$work_dir/original-agent-guard-report.json"
  backup_parent="$(mktemp -d "$work_dir/original-evidence.XXXXXX")"
  backup_evidence_dir="$backup_parent/evidence"
  cp "$report_json" "$original_report"
  mv "$evidence_dir" "$backup_evidence_dir"
  restore_evidence=1
  trap restore_evidence_dir EXIT HUP INT TERM

  generate_recommended_report
  validate_report "$report_json"
  if ! cmp -s "$original_report" "$report_json"; then
    echo "agent-guard evidence stale: regenerate $report_json from current repository state" >&2
    exit 1
  fi

  restore_evidence_dir
  restore_evidence=0
  trap - EXIT HUP INT TERM
}

lint_public_artifacts() {
  validate_report "$report_json"
  render_public_artifacts
  lint_public_artifact_names
}

strict_release_gate() {
  generate_strict_report
  validate_report "$report_json"
  run_agent_guard conformance check \
    --root "$root" \
    --evidence "$report_json" \
    --profile strict \
    --json \
    > "$evidence_dir/agent-guard-conformance.json"
  run_agent_guard evidence-pack manifest \
    --root "$root" \
    --report "$report_json" \
    --artifact "$report_json" \
    --json \
    > "$evidence_dir/agent-guard-evidence-pack.json"
  lint_public_artifacts
}

case "$mode" in
  consume)
    consume_report
    ;;
  lint-public)
    lint_public_artifacts
    ;;
  strict-release)
    strict_release_gate
    ;;
  *)
    echo "usage: $0 {consume|lint-public|strict-release}" >&2
    exit 2
    ;;
esac
