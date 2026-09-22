#!/usr/bin/env bash
# Where: bench/ttfe/run.sh
# What: invoke the candidate-wheel TTFE helper without evaluating markdown.
# Why: isolate the shell surface while the Python helper records strict proof.

set -u

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
date_stamp="$(date +%Y%m%d)"
out_path="${AGENT_GUARD_TTFE_OUT:-$repo_root/bench/results/ttfe-$date_stamp.json}"
if [[ -n "${PYTHON+x}" ]]; then
  python_bin="$PYTHON"
  if [[ "$python_bin" != /* ]]; then
    if command -v "$python_bin" >/dev/null 2>&1; then
      python_bin="$(command -v "$python_bin")"
    else
      echo "TTFE replay failed: explicit PYTHON is not executable" >&2
      exit 127
    fi
  fi
  if [[ ! -x "$python_bin" ]]; then
    echo "TTFE replay failed: explicit PYTHON is not executable" >&2
    exit 127
  fi
else
  python_bin="$repo_root/.venv312/bin/python"
fi
if [[ ! -x "$python_bin" ]]; then
  if command -v python3 >/dev/null 2>&1; then
    python_bin="$(command -v python3)"
  elif command -v python >/dev/null 2>&1; then
    python_bin="$(command -v python)"
  else
    echo "TTFE replay failed: no Python interpreter is available" >&2
    exit 127
  fi
fi

exec "$python_bin" -I "$repo_root/bench/ttfe/run.py" replay \
  --repo-root "$repo_root" \
  --out "$out_path" \
  --python "$python_bin"
