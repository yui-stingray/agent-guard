#!/usr/bin/env sh
# Where: examples/render_evidence_surfaces.sh
# What: render public-safe evidence surfaces from a sanitized report JSON.
# Why: show downstream consumers how to avoid rerunning scanners for each format.

set -eu

report_json="${1:-docs/evidence-samples/agent-guard-report.json}"
output_dir="${2:-.agent-guard/evidence}"

mkdir -p "$output_dir"

agent-guard render-report \
  --root . \
  --input "$report_json" \
  --format markdown \
  --output "$output_dir/agent-guard-report.md"

agent-guard render-report \
  --root . \
  --input "$report_json" \
  --format sarif \
  --output "$output_dir/agent-guard-results.sarif"

agent-guard render-report \
  --root . \
  --input "$report_json" \
  --format github-annotations
