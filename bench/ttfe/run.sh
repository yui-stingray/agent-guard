#!/usr/bin/env bash
# Where: bench/ttfe/run.sh
# What: replay the existing-repo quickstart in a temporary repository.
# Why: measure time-to-first-evidence as a repeatable onboarding benchmark.

set -u

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
date_stamp="$(date +%Y%m%d)"
out_path="${AGENT_GUARD_TTFE_OUT:-$repo_root/bench/results/ttfe-$date_stamp.json}"
python_bin="${PYTHON:-$repo_root/.venv312/bin/python}"
case "$python_bin" in
  /*) ;;
  *) python_bin="$repo_root/$python_bin" ;;
esac
if [[ ! -x "$python_bin" ]]; then
  if command -v python >/dev/null 2>&1; then
    python_bin="$(command -v python)"
  else
    python_bin="$(command -v python3)"
  fi
fi

work_root="$(mktemp -d "${TMPDIR:-/tmp}/agent-guard-ttfe.XXXXXX")"
fixture_repo="$work_root/repo"
shim_bin="$work_root/bin"
commands_file="$work_root/commands.txt"
records_file="$work_root/records.jsonl"
wheelhouse="$work_root/wheelhouse"
mkdir -p "$fixture_repo" "$shim_bin" "$wheelhouse"
trap 'rm -rf "$work_root"' EXIT
base_python="$("$python_bin" -c 'import sys; print(getattr(sys, "_base_executable", sys.executable))')"
build_python="$python_bin"
if ! "$build_python" -m pip --version >/dev/null 2>&1; then
  build_python="$base_python"
fi
cat > "$shim_bin/python3" <<EOF
#!/usr/bin/env bash
exec "$base_python" "\$@"
EOF
chmod +x "$shim_bin/python3"
export PATH="$shim_bin:$PATH"
export PYTHONPATH="$repo_root${PYTHONPATH:+:$PYTHONPATH}"

cat > "$fixture_repo/AGENTS.md" <<'EOF'
Require approval before shell writes.
Keep credentials redacted in public evidence.
Run tests before reporting completion.
EOF

cat > "$fixture_repo/README.md" <<'EOF'
# TTFE Fixture

agent-guard context check --root . --policy .agent-guard/context-policy.yaml --json
agent-guard mcp check --root . --policy .agent-guard/mcp-policy.yaml --json
agent-guard workflow check --root . --policy .agent-guard/workflow-policy.yaml --json
agent-guard drift check --root . --profile recommended --schema-version v2 --json
agent-guard report --root . --context-policy .agent-guard/context-policy.yaml --evidence-preset recommended --mcp-policy .agent-guard/mcp-policy.yaml --format json
EOF

"$python_bin" -m bench.ttfe.run list --source "$repo_root/docs/quickstart-existing-repo.md" > "$commands_file"

setup_status="skipped"
setup_detail=""
if "$build_python" -m pip wheel --no-deps "$repo_root" -w "$wheelhouse" >/dev/null 2>&1; then
  setup_status="local_wheelhouse"
  setup_detail="built yui-agent-guard wheel"
  "$build_python" -m pip wheel --no-deps 'PyYAML>=6,<7' -w "$wheelhouse" >/dev/null 2>&1 || true
  export PIP_FIND_LINKS="$wheelhouse"
  if find "$wheelhouse" -maxdepth 1 -iname 'pyyaml-*.whl' | grep -q .; then
    export PIP_NO_INDEX=1
  else
    setup_detail="built yui-agent-guard wheel; PyYAML wheel unavailable"
  fi
else
  setup_status="wheelhouse_failed"
  setup_detail="could not build local package wheel"
fi
export PIP_CACHE_DIR="$work_root/pip-cache"

append_record() {
  local index="$1"
  local command="$2"
  local exit_code="$3"
  local duration_ms="$4"
  local output_file="$5"
  "$python_bin" - "$records_file" "$index" "$command" "$exit_code" "$duration_ms" "$output_file" "$fixture_repo" "$work_root" "$repo_root" <<'PY'
import json
import sys
from pathlib import Path

records_path = Path(sys.argv[1])
index = int(sys.argv[2])
command = sys.argv[3]
exit_code = int(sys.argv[4])
duration_ms = int(sys.argv[5])
output_path = Path(sys.argv[6])
fixture_repo = sys.argv[7]
work_root = sys.argv[8]
repo_root = sys.argv[9]
output = output_path.read_text(encoding="utf-8", errors="replace") if output_path.exists() else ""
output = output.replace(fixture_repo, "<ttfe-repo>").replace(work_root, "<ttfe-work>").replace(repo_root, "<repo-root>")
tail = "\n".join(output.splitlines()[-12:])
if len(tail) > 800:
    tail = tail[-800:]
record = {
    "index": index,
    "command": command,
    "exit_code": exit_code,
    "duration_ms": duration_ms,
    "output_tail": tail,
}
with records_path.open("a", encoding="utf-8") as fh:
    fh.write(json.dumps(record, sort_keys=True) + "\n")
PY
}

cd "$fixture_repo" || exit 2
start_ms="$("$python_bin" -c 'import time; print(time.monotonic_ns() // 1_000_000)')"
index=0
while IFS= read -r command; do
  index=$((index + 1))
  output_file="$work_root/command-$index.out"
  command_start_ms="$("$python_bin" -c 'import time; print(time.monotonic_ns() // 1_000_000)')"
  set +e
  eval "$command" > "$output_file" 2>&1
  exit_code=$?
  command_end_ms="$("$python_bin" -c 'import time; print(time.monotonic_ns() // 1_000_000)')"
  append_record "$index" "$command" "$exit_code" "$((command_end_ms - command_start_ms))" "$output_file"
  if [[ "$exit_code" -ge 2 ]]; then
    break
  fi
done < "$commands_file"
end_ms="$("$python_bin" -c 'import time; print(time.monotonic_ns() // 1_000_000)')"

setup_json="$(S="$setup_status" D="$setup_detail" "$python_bin" -c 'import json,os; print(json.dumps({"status": os.environ["S"], "detail": os.environ["D"]}))')"
AGENT_GUARD_TTFE_SOURCE_LABEL="docs/quickstart-existing-repo.md" "$python_bin" -m bench.ttfe.run result \
  --source "$repo_root/docs/quickstart-existing-repo.md" \
  --records "$records_file" \
  --out "$out_path" \
  --elapsed-ms "$((end_ms - start_ms))" \
  --setup "$setup_json"
