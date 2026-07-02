#!/usr/bin/env bash
# Where: bench/health/run.sh
# What: local code-health budget and tool availability checks.
# Why: make Day reports capture file-size, test, coverage, and lint status.

set -u

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

python_bin="${PYTHON:-}"
if [[ -z "$python_bin" ]]; then
  if [[ -x "/home/yui/.cache/agent-safety-toolkit-example-venv/bin/python" ]]; then
    python_bin="/home/yui/.cache/agent-safety-toolkit-example-venv/bin/python"
  elif command -v python >/dev/null 2>&1; then
    python_bin="$(command -v python)"
  else
    python_bin="$(command -v python3)"
  fi
fi

echo "health: python=$python_bin"
echo "health: file-size budget (>800 lines)"
find src/agent_guard -maxdepth 1 -name "*.py" -print0 \
  | xargs -0 wc -l \
  | awk '$1 > 800 && $2 != "total" {print "over_budget:", $0}'

echo "health: new python file headers"
while IFS= read -r file; do
  case "$file" in
    bench/agb/fixtures/*) continue ;;
  esac
  lines="$(wc -l < "$file")"
  if [[ "$lines" -gt 300 && "$file" == bench/* ]]; then
    echo "over_300_new_python: $lines $file"
  fi
  if ! sed -n '1,5p' "$file" | grep -Eq "Where: .*What: .*Why:|Where:"; then
    echo "missing_header: $file"
  fi
done < <(find bench tests -name "*.py" -type f | sort)

echo "health: pytest"
PYTHONPATH=src:. "$python_bin" -m pytest -q
pytest_status=$?

echo "health: coverage"
if "$python_bin" -c "import pytest_cov" >/dev/null 2>&1; then
  PYTHONPATH=src:. "$python_bin" -m pytest -q --cov=agent_guard --cov-report=json
  coverage_status=$?
else
  echo "coverage_unavailable: pytest-cov is not installed for $python_bin"
  trace_dir="${TMPDIR:-/tmp}/agent-guard-agb-trace-$$"
  rm -rf "$trace_dir"
  if PYTHONPATH=src:. "$python_bin" -m trace --count --missing --coverdir "$trace_dir" --module pytest tests/test_agb_runner.py -q >/tmp/agent-guard-agb-trace.out 2>&1; then
    awk 'BEGIN{total=0;hit=0} /^[ ]*[0-9]+:/ {hit++; total++; next} /^[ ]*>>>>>>/ {total++} END{printf "agb_runner_trace_line_coverage: %.2f%% (%d/%d)\n", total ? hit*100/total : 0, hit, total}' "$trace_dir/bench.agb.run.cover"
  else
    echo "agb_runner_trace_line_coverage_unavailable"
    tail -20 /tmp/agent-guard-agb-trace.out
  fi
  rm -rf "$trace_dir" /tmp/agent-guard-agb-trace.out
  coverage_status=0
fi

echo "health: yamllint"
if command -v yamllint >/dev/null 2>&1; then
  yamllint -s . || true
else
  echo "yamllint_unavailable"
fi

echo "health: actionlint"
if command -v actionlint >/dev/null 2>&1; then
  actionlint || true
else
  echo "actionlint_unavailable"
fi

if [[ "$pytest_status" -ne 0 || "$coverage_status" -ne 0 ]]; then
  exit 1
fi
