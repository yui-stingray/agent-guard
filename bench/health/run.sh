#!/usr/bin/env bash
# Where: bench/health/run.sh
# What: local code-health budget and tool availability checks.
# Why: make Day reports capture file-size, test, coverage, and lint status.

set -u

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

python_bin="${PYTHON:-}"
if [[ -z "$python_bin" ]]; then
  if [[ -x "$repo_root/.venv312/bin/python" ]]; then
    python_bin="$repo_root/.venv312/bin/python"
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
PYTEST_DISABLE_PLUGIN_AUTOLOAD="${PYTEST_DISABLE_PLUGIN_AUTOLOAD:-1}" PYTHONPATH=src:. "$python_bin" -m pytest -q
pytest_status=$?

echo "health: coverage"
coverage_status=0
coverage_file="${COVERAGE_FILE:-$repo_root/.coverage}"
rm -f "$coverage_file" "$coverage_file".* "$repo_root/coverage.json"
if "$python_bin" -c "import coverage" >/dev/null 2>&1; then
  PYTEST_DISABLE_PLUGIN_AUTOLOAD="${PYTEST_DISABLE_PLUGIN_AUTOLOAD:-1}" \
    COVERAGE_FILE="$coverage_file" \
    COVERAGE_PROCESS_START="$repo_root/.coveragerc" \
    PYTHONPATH=src:. \
    "$python_bin" -m pytest -q
  coverage_test_status=$?
  if [[ "$coverage_test_status" -eq 0 ]]; then
    COVERAGE_FILE="$coverage_file" "$python_bin" -m coverage combine
    coverage_combine_status=$?
  else
    coverage_combine_status="$coverage_test_status"
  fi
  if [[ "$coverage_test_status" -eq 0 && "$coverage_combine_status" -eq 0 ]]; then
    COVERAGE_FILE="$coverage_file" "$python_bin" -m coverage json -o coverage.json
    coverage_json_status=$?
    COVERAGE_FILE="$coverage_file" "$python_bin" -m coverage report
    coverage_report_status=$?
    if [[ "$coverage_json_status" -ne 0 || "$coverage_report_status" -ne 0 ]]; then
      coverage_status=1
    fi
  else
    coverage_status=1
  fi
else
  echo "coverage_unavailable: coverage.py is not installed for $python_bin"
  coverage_status=1
fi

echo "health: yamllint"
yamllint_status=0
if command -v yamllint >/dev/null 2>&1; then
  yamllint -s .
  yamllint_status=$?
else
  echo "yamllint_unavailable"
fi

echo "health: actionlint"
if command -v actionlint >/dev/null 2>&1; then
  actionlint || true
else
  echo "actionlint_unavailable"
fi

if [[ "$pytest_status" -ne 0 || "$coverage_status" -ne 0 || "$yamllint_status" -ne 0 ]]; then
  exit 1
fi
