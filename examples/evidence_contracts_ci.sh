#!/usr/bin/env sh
# Where: examples/evidence_contracts_ci.sh
# What: runnable CI examples for consuming sanitized agent-guard evidence.
# Why: show fail-closed downstream contracts without adding scanner logic.

set -eu

mode="${1:-consume}"
root="${AGENT_GUARD_ROOT:-.}"
evidence_dir_input="${AGENT_GUARD_EVIDENCE_DIR:-.agent-guard/evidence}"
agent_guard="${AGENT_GUARD_BIN:-agent-guard}"
python_bin="${PYTHON_BIN:-python}"
context_policy="${AGENT_GUARD_CONTEXT_POLICY:-.agent-guard/context-policy.yaml}"
path_policy="${AGENT_GUARD_PATH_POLICY:-.agent-guard/path-policy.yaml}"
content_policy="${AGENT_GUARD_CONTENT_POLICY:-.agent-guard/content-policy.yaml}"
mcp_policy="${AGENT_GUARD_MCP_POLICY:-.agent-guard/mcp-policy.yaml}"
workflow_policy="${AGENT_GUARD_WORKFLOW_POLICY:-.agent-guard/workflow-policy.yaml}"
digest_policy="${AGENT_GUARD_DIGEST_POLICY:-.agent-guard/context-digest-policy.yaml}"
content_scan_dir="${AGENT_GUARD_CONTENT_SCAN_DIR:-.}"
base_ref="${AGENT_GUARD_BASE_REF:-}"
surface_delta_base_ref="${AGENT_GUARD_SURFACE_DELTA_BASE_REF:-}"
conformance_profile="${AGENT_GUARD_CONFORMANCE_PROFILE:-recommended}"
include_digest_policy=false

if ! "$python_bin" -I - >/dev/null 2>&1 <<'PY'
import os

raise SystemExit(0 if os.name == "posix" else 1)
PY
then
  echo "agent-guard shell evidence example requires a POSIX host" >&2
  exit 2
fi

run_agent_guard() {
  $agent_guard "$@"
}

validate_report() {
  if "$python_bin" -I -m agent_guard.consumer "$1" >/dev/null 2>&1; then
    return 0
  fi
  echo "agent-guard evidence validation failed" >&2
  return 1
}

policy_path() {
  case "$1" in
    /*) printf '%s\n' "$1" ;;
    *) printf '%s/%s\n' "${root%/}" "$1" ;;
  esac
}

evidence_path() {
  case "$1" in
    /*) printf '%s\n' "$1" ;;
    *)
      if [ "$root" = "." ]; then
        printf '%s\n' "$1"
      else
        printf '%s/%s\n' "${root%/}" "$1"
      fi
      ;;
  esac
}

validate_relative_evidence_location() {
  AGENT_GUARD_ROOT_TO_INSPECT="$root" \
    AGENT_GUARD_EVIDENCE_INPUT_TO_INSPECT="$evidence_dir_input" \
    "$python_bin" -I - >/dev/null 2>&1 <<'PY'
import os
import stat
from pathlib import Path

try:
    raw_evidence = os.environ["AGENT_GUARD_EVIDENCE_INPUT_TO_INSPECT"]
    relative = Path(raw_evidence)
    if relative.is_absolute():
        raise SystemExit(0)
    if relative == Path(".") or ".." in relative.parts:
        raise SystemExit(1)
    root = Path(os.environ["AGENT_GUARD_ROOT_TO_INSPECT"]).resolve(strict=True)
    if not root.is_dir():
        raise SystemExit(1)
    lexical = Path(os.path.abspath(root / relative))
    bounded = lexical.relative_to(root)
    if not bounded.parts:
        raise SystemExit(1)
    current = root
    for part in bounded.parts:
        current /= part
        try:
            current_stat = os.lstat(current)
        except FileNotFoundError:
            break
        if stat.S_ISLNK(current_stat.st_mode):
            raise SystemExit(1)
    resolved = lexical.resolve(strict=False)
    resolved.relative_to(root)
    if resolved == root:
        raise SystemExit(1)
except (KeyError, OSError, RuntimeError, ValueError):
    raise SystemExit(1)
PY
}

rename_path() {
  AGENT_GUARD_RENAME_SOURCE="$1" \
    AGENT_GUARD_RENAME_DESTINATION="$2" \
    "$python_bin" -I - >/dev/null 2>&1 <<'PY'
import os

try:
    os.rename(
        os.environ["AGENT_GUARD_RENAME_SOURCE"],
        os.environ["AGENT_GUARD_RENAME_DESTINATION"],
    )
except (KeyError, OSError):
    raise SystemExit(1)
PY
}

if ! validate_relative_evidence_location; then
  echo "agent-guard relative evidence-dir must stay under root without symlinked ancestors" >&2
  exit 2
fi

evidence_dir="$(evidence_path "$evidence_dir_input")"
report_json="${AGENT_GUARD_REPORT_JSON:-$evidence_dir/agent-guard-report.json}"

run_agent_guard_report() {
  if run_agent_guard "$@" >/dev/null 2>&1; then
    return 0
  else
    code="$?"
  fi
  if [ "$code" -eq 1 ]; then
    return 1
  fi
  echo "agent-guard evidence generation failed" >&2
  return 2
}

public_validation_failed() {
  echo "agent-guard public artifact validation failed" >&2
  return 1
}

generate_recommended_report() {
  set -- report \
    --root "$root" \
    --context-policy "$context_policy" \
    --evidence-preset recommended
  if [ -f "$(policy_path "$path_policy")" ]; then
    set -- "$@" --path-policy "$path_policy"
  fi
  if [ -f "$(policy_path "$content_policy")" ]; then
    set -- "$@" --content-policy "$content_policy" --content-scan-dir "$content_scan_dir"
  fi
  if [ -n "$mcp_policy" ] && {
    [ "$mcp_policy" != ".agent-guard/mcp-policy.yaml" ] || [ -f "$(policy_path "$mcp_policy")" ]
  }; then
    set -- "$@" --mcp-policy "$mcp_policy"
  fi
  if [ -f "$(policy_path "$workflow_policy")" ]; then
    set -- "$@" --workflow-policy "$workflow_policy"
  fi
  if [ "$include_digest_policy" = "true" ] && [ -f "$(policy_path "$digest_policy")" ]; then
    set -- "$@" --digest-policy "$digest_policy"
  fi
  if [ -n "$base_ref" ]; then
    set -- "$@" --drift-base-ref "$base_ref"
  fi
  if [ -n "$surface_delta_base_ref" ]; then
    set -- "$@" --surface-delta-base-ref "$surface_delta_base_ref"
  fi
  set -- "$@" \
    --conformance-profile "$conformance_profile" \
    --format json \
    --output "$report_json"
  run_agent_guard_report "$@"
}

generate_strict_report() {
  run_agent_guard report \
    --root "$root" \
    --context-policy "$context_policy" \
    --evidence-preset recommended \
    --mcp-policy "$mcp_policy" \
    --digest-policy "$digest_policy" \
    --conformance-profile strict \
    --evidence-pack-manifest \
    --format json \
    --output "$report_json"
}

render_public_artifacts() {
  markdown="$evidence_dir/agent-guard-report.md"
  sarif="$evidence_dir/agent-guard-results.sarif"
  annotations="$evidence_dir/agent-guard-annotations.txt"
  if [ ! -e "$markdown" ] && [ ! -L "$markdown" ]; then
    render_status=0
    run_agent_guard render-report \
      --root "$root" \
      --input "$report_json" \
      --format markdown \
      --output "$markdown" >/dev/null 2>&1 || render_status="$?"
    if [ "$render_status" -ge 2 ] || [ ! -f "$markdown" ] || [ -L "$markdown" ]; then
      public_validation_failed
    fi
  fi
  if [ ! -e "$sarif" ] && [ ! -L "$sarif" ]; then
    render_status=0
    run_agent_guard render-report \
      --root "$root" \
      --input "$report_json" \
      --format sarif \
      --output "$sarif" >/dev/null 2>&1 || render_status="$?"
    if [ "$render_status" -ge 2 ] || [ ! -f "$sarif" ] || [ -L "$sarif" ]; then
      public_validation_failed
    fi
  fi
  if [ ! -e "$annotations" ] && [ ! -L "$annotations" ]; then
    render_status=0
    run_agent_guard render-report \
      --root "$root" \
      --input "$report_json" \
      --format github-annotations 2>/dev/null > "$annotations" || render_status="$?"
    if [ "$render_status" -ge 2 ] || [ ! -f "$annotations" ] || [ -L "$annotations" ]; then
      public_validation_failed
    fi
  fi
}

validate_bounded_evidence_bundle() {
  "$python_bin" -I -m agent_guard.consumer \
    --evidence-dir "$evidence_dir" \
    "$report_json" >/dev/null 2>&1
}

validate_consume_artifact_contents() {
  if validate_bounded_evidence_bundle; then
    return 0
  fi
  echo "agent-guard evidence validation failed" >&2
  return 1
}

validate_public_artifact_contents() {
  if validate_bounded_evidence_bundle; then
    return 0
  fi
  public_validation_failed
}

validate_existing_evidence_dir() {
  validation_status=0
  if AGENT_GUARD_EVIDENCE_TO_INSPECT="$evidence_dir" \
    "$python_bin" -I - >/dev/null 2>&1 <<'PY'
import os
import stat

allowed_names = frozenset(
    {
        "agent-guard-report.json",
        "agent-guard-report.md",
        "agent-guard-results.sarif",
        "agent-guard-conformance.json",
        "agent-guard-evidence-pack.json",
        "agent-surface-inventory.json",
        "agent-guard-annotations.txt",
    }
)
path = os.environ.get("AGENT_GUARD_EVIDENCE_TO_INSPECT")
if path is None:
    raise SystemExit(1)
try:
    path_stat = os.lstat(path)
except OSError:
    raise SystemExit(1)
if stat.S_ISLNK(path_stat.st_mode) or not stat.S_ISDIR(path_stat.st_mode):
    raise SystemExit(1)
try:
    with os.scandir(path) as entries:
        for index, entry in enumerate(entries):
            if index >= len(allowed_names) or entry.name not in allowed_names:
                raise SystemExit(1)
            if entry.is_symlink() or not entry.is_file(follow_symlinks=False):
                raise SystemExit(1)
except OSError:
    raise SystemExit(1)
PY
  then
    return 0
  else
    validation_status="$?"
  fi
  return "$validation_status"
}

resolve_transaction_parent() {
  AGENT_GUARD_ROOT_TO_INSPECT="$root" \
    AGENT_GUARD_EVIDENCE_INPUT_TO_INSPECT="$evidence_dir_input" \
    AGENT_GUARD_EVIDENCE_TO_INSPECT="$evidence_dir" \
    "$python_bin" -I - 2>/dev/null <<'PY'
import os
from pathlib import Path

try:
    root = Path(os.environ["AGENT_GUARD_ROOT_TO_INSPECT"]).resolve(strict=True)
    evidence = Path(os.environ["AGENT_GUARD_EVIDENCE_TO_INSPECT"]).resolve(strict=True)
    evidence_input = Path(os.environ["AGENT_GUARD_EVIDENCE_INPUT_TO_INSPECT"])
    if not evidence_input.is_absolute():
        evidence.relative_to(root)
        candidate = root.parent
    else:
        try:
            evidence.relative_to(root)
        except ValueError:
            candidate = evidence.parent
        else:
            candidate = root.parent
    candidate = candidate.resolve(strict=True)
    if (
        candidate == root
        or not candidate.is_dir()
        or candidate.stat().st_dev != evidence.stat().st_dev
    ):
        raise SystemExit(1)
    try:
        candidate.relative_to(root)
    except ValueError:
        pass
    else:
        raise SystemExit(1)
except (KeyError, OSError, RuntimeError, ValueError):
    raise SystemExit(1)
print(os.fspath(candidate))
PY
}

report_restore_failure() {
  if [ "$1" -eq 2 ]; then
    echo "agent-guard evidence cleanup failed" >&2
  else
    echo "agent-guard evidence restoration failed" >&2
  fi
}

restore_evidence_dir() {
  restore_state="${restore_evidence:-0}"
  if [ "$restore_state" = "0" ]; then
    return 0
  fi
  if [ -z "${backup_parent:-}" ] || [ -z "${backup_evidence_dir:-}" ]; then
    return 1
  fi
  if [ "$restore_state" = "2" ]; then
    if [ -e "$backup_evidence_dir" ] || [ -L "$backup_evidence_dir" ]; then
      : # The whole-directory staging rename completed before state publication.
    elif [ -e "$evidence_dir" ] || [ -L "$evidence_dir" ]; then
      if ! rm -rf "$backup_parent" 2>/dev/null; then
        return 2
      fi
      restore_evidence=0
      backup_parent=""
      backup_evidence_dir=""
      return 0
    else
      return 1
    fi
  elif [ "$restore_state" != "1" ]; then
    return 1
  fi

  generated_parent=""
  generated_evidence_dir=""
  if [ -e "$evidence_dir" ] || [ -L "$evidence_dir" ]; then
    if ! generated_parent="$(mktemp -d "$transaction_parent/.agent-guard-evidence-generated.XXXXXX" 2>/dev/null)"; then
      return 1
    fi
    generated_evidence_dir="$generated_parent/evidence"
    if ! rename_path "$evidence_dir" "$generated_evidence_dir"; then
      if ! { { [ -e "$generated_evidence_dir" ] || [ -L "$generated_evidence_dir" ]; } &&
        [ ! -e "$evidence_dir" ] && [ ! -L "$evidence_dir" ]; }; then
        return 1
      fi
    fi
  fi
  if ! rename_path "$backup_evidence_dir" "$evidence_dir"; then
    if ! { { [ -e "$evidence_dir" ] || [ -L "$evidence_dir" ]; } &&
      [ ! -e "$backup_evidence_dir" ] && [ ! -L "$backup_evidence_dir" ]; }; then
      return 1
    fi
  fi
  restore_evidence=0

  cleanup_failed=0
  if ! rm -rf "$backup_parent" 2>/dev/null; then
    cleanup_failed=1
  fi
  if [ -n "$generated_parent" ] && ! rm -rf "$generated_parent" 2>/dev/null; then
    cleanup_failed=1
  fi
  if [ "$cleanup_failed" -ne 0 ]; then
    return 2
  fi
  backup_parent=""
  backup_evidence_dir=""
  generated_parent=""
  generated_evidence_dir=""
  return 0
}

restore_evidence_on_exit() {
  exit_status="$1"
  trap - EXIT
  restore_in_progress=1
  if restore_evidence_dir; then
    restore_status=0
  else
    restore_status="$?"
  fi
  if [ "$restore_status" -ne 0 ]; then
    report_restore_failure "$restore_status"
    restore_in_progress=0
    trap - HUP INT TERM
    exit 2
  fi
  restore_in_progress=0
  trap - HUP INT TERM
  if [ "${termination_requested:-0}" = "1" ]; then
    exit 2
  fi
  exit "$exit_status"
}

terminate_consume() {
  if [ "${restore_in_progress:-0}" = "1" ]; then
    termination_requested=1
    return 0
  fi
  exit 2
}

report_is_within_evidence_dir() {
  AGENT_GUARD_REPORT_TO_INSPECT="$report_json" \
    AGENT_GUARD_EVIDENCE_TO_INSPECT="$evidence_dir" \
    "$python_bin" -I - >/dev/null 2>&1 <<'PY'
import os
from pathlib import Path

try:
    report = Path(os.environ["AGENT_GUARD_REPORT_TO_INSPECT"])
    evidence = Path(os.environ["AGENT_GUARD_EVIDENCE_TO_INSPECT"])
    lexical_report = Path(os.path.abspath(report))
    lexical_evidence = Path(os.path.abspath(evidence))
    lexical_report.relative_to(lexical_evidence)
    if report.exists() or report.is_symlink():
        report.resolve(strict=True).relative_to(evidence.resolve(strict=True))
except (KeyError, OSError, RuntimeError, ValueError):
    raise SystemExit(1)
PY
}

consume_report() {
  if ! report_is_within_evidence_dir; then
    echo "agent-guard evidence comparison setup failed" >&2
    return 2
  fi
  if ! validate_existing_evidence_dir; then
    echo "agent-guard evidence validation failed" >&2
    return 1
  fi
  validate_consume_artifact_contents
  validate_report "$report_json"
  if AGENT_GUARD_REPORT_TO_INSPECT="$report_json" "$python_bin" -I - >/dev/null 2>&1 <<'PY'
import json
import os
from pathlib import Path

payload = json.loads(Path(os.environ["AGENT_GUARD_REPORT_TO_INSPECT"]).read_text(encoding="utf-8"))
raise SystemExit(0 if isinstance(payload, dict) and "digest" in payload else 1)
PY
  then
    include_digest_policy=true
  fi
  if ! transaction_parent="$(resolve_transaction_parent)" || [ -z "$transaction_parent" ]; then
    echo "agent-guard evidence comparison setup failed" >&2
    return 1
  fi
  if ! backup_parent="$(mktemp -d "$transaction_parent/.agent-guard-evidence-backup.XXXXXX" 2>/dev/null)"; then
    echo "agent-guard evidence comparison setup failed" >&2
    return 1
  fi
  backup_evidence_dir="$backup_parent/evidence"
  original_report="$backup_evidence_dir/${report_json##*/}"
  restore_evidence=2
  restore_in_progress=0
  termination_requested=0
  trap 'restore_evidence_on_exit "$?"' EXIT
  trap terminate_consume HUP INT TERM
  if ! rename_path "$evidence_dir" "$backup_evidence_dir"; then
    echo "agent-guard evidence comparison setup failed" >&2
    exit 1
  fi
  restore_evidence=1

  regenerated_status=0
  generate_recommended_report || regenerated_status="$?"
  if [ "$regenerated_status" -ge 2 ]; then
    exit "$regenerated_status"
  fi
  validate_consume_artifact_contents
  validate_report "$report_json"

  if ! cmp -s "$original_report" "$report_json"; then
    echo "agent-guard evidence stale: sanitized report differs from current repository state" >&2
    exit 1
  fi

  restore_in_progress=1
  if restore_evidence_dir; then
    restore_status=0
  else
    restore_status="$?"
  fi
  if [ "$restore_status" -ne 0 ]; then
    report_restore_failure "$restore_status"
    restore_in_progress=0
    trap - EXIT HUP INT TERM
    return 2
  fi
  restore_in_progress=0
  trap - EXIT HUP INT TERM
  if [ "$termination_requested" = "1" ]; then
    return 2
  fi
  return "$regenerated_status"
}

lint_public_artifacts() {
  validate_public_artifact_contents
  validate_report "$report_json"
  render_public_artifacts
  validate_public_artifact_contents
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
