# Benchmark Results

Agent-Guard Bench (AGB) is the local deterministic regression benchmark for
the repository evidence scanners. It measures static guard behavior on inert
fixtures checked into this repository.

## Current AGB Result

The current AGB result is based on 60 self-authored cases with
groups A16/B10/C13/D6/E10/F5. The groups cover agent instruction files, skill
content, MCP config metadata, digest and workflow drift, benign false-positive
probes, and path-policy positives.

Current metrics: overall F1 `0.982143`, precision `0.964912`, recall `1.000000`,
with `TP=55`, `FP=2`, `FN=0`.

Status: no independent verification yet. Treat this as repository-local
regression evidence for deterministic static checks, not as an externally
validated product-quality benchmark.

Scope limits:

- AGB covers static repository evidence only: context files, skill text, MCP
  config metadata, path names, digest pins, and workflow drift.
- AGB does not execute MCP servers, validate OAuth flows, run LLM judging,
  route models, perform generic secret scanning, or evaluate runtime policy
  decisions.
- The corpus and expectations are self-authored, so benchmark movement is most
  useful for regression tracking until independent fixtures or review exist.

Known false negatives queued for a future rule-tuning session:

- No known false negatives remain in the current self-authored 60-case AGB corpus.

Known false positives:

- `e03`: benign negated secret-guidance content probe.
- `e06`: benign quoted pipe-pattern documentation probe.

## Next Evaluation Work

Near-term AGB work should improve the usefulness of the existing static
evidence regression suite without turning the benchmark into a product-quality
claim:

- Add or tune rules only when a fixture documents a concrete static repository
  evidence pattern and the public artifact hygiene contract stays unchanged.
- When a known false negative starts matching, update the expected fixture,
  this page, and the per-guard table in the same change.
- Keep third-party or independently reviewed fixture sets separate from the
  self-authored AGB score until their source, license, selection criteria, and
  expected findings are reviewed.
- Defer broad external benchmark work, case studies, rename work, or marketing
  claims until demand signals such as user feedback, downstream issues, or
  integration requests justify that investment.

Do not use AGB movement as a reason to add runtime MCP execution, live OAuth
validation, generic credential scanning, model judging, or autonomous policy
enforcement.

## Per-Guard Results

This table was rendered from the current AGB result JSON with
`python -m bench.agb.reporting <result-json>`.

| Guard | TP | FP | FN | Precision | Recall | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Content | 10 | 2 | 0 | 0.833333 | 1.000000 | 0.909091 |
| Context | 17 | 0 | 0 | 1.000000 | 1.000000 | 1.000000 |
| Digest | 2 | 0 | 0 | 1.000000 | 1.000000 | 1.000000 |
| Drift | 5 | 0 | 0 | 1.000000 | 1.000000 | 1.000000 |
| MCP | 14 | 0 | 0 | 1.000000 | 1.000000 | 1.000000 |
| Path | 7 | 0 | 0 | 1.000000 | 1.000000 | 1.000000 |

## Reproducing The Table

Run the benchmark to a local result JSON:

```bash
PYTHONPATH=src:. python -m bench.agb.run --repo-root . --out /tmp/agent-guard-agb.json
```

Render the per-guard Markdown table:

```bash
PYTHONPATH=src:. python -m bench.agb.reporting /tmp/agent-guard-agb.json
```

When refreshing committed benchmark artifacts, render from the newest
`bench/results/agb-*.json` file after the result refresh has been reviewed.
The committed `bench/results/agb-20260702.json` file is a historical 40-case
artifact and should not be cited as the current 60-case AGB measurement.
