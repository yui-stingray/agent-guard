# Comparison: agent-guard and agent-audit

This is a scoped comparison, not an independent evaluation. The `agent-audit`
descriptions below are based on its upstream project materials checked on
2026-08-06; its scope and implementation may change.

| Dimension | agent-audit | agent-guard |
| --- | --- | --- |
| Primary target | The upstream project describes agent code and deployment artifacts. | Agent instruction files, skills directories, MCP configs, context digests, workflows, and evidence artifacts. |
| Main technique | Its public materials describe static analysis and configuration checks. | Deterministic static repository evidence, policy conformance, digest pinning, drift checks, and consumer validation. |
| Rule surface | Project-defined detection rules; consult upstream material for the current inventory. | Config-surface rules and taxonomy mappings for repository-local agent evidence. |
| Output | The upstream repository and paper describe terminal, JSON, and SARIF output. | Stable JSON envelopes, sanitized reports, SARIF/annotation rendering, conformance results, and evidence-pack manifests. |
| Published measurement | The authors report benchmark results; read their method and version context in the primary sources. | Current AGB metrics are reported with population, FP/FN counts, known gaps, and scope limits in [Benchmark Results](benchmark-results.md). |
| Benchmark caveat | This document does not independently validate external results. | The AGB corpus is self-authored, has no independent verification yet, and covers static repository configuration evidence only. |
| Best fit | A possible fit for scanning agent applications; evaluate it for the repository and version in use. | A possible fit for checking repository agent configuration, evidence contracts, and CI gates. |
| Relationship | Potentially complementary with repository evidence workflows. | May consume or package detection outputs from scanners such as `agent-audit` after repository-specific evaluation. |

External statements were checked on 2026-08-06 against the primary
[agent-audit repository](https://github.com/HeadyZhang/agent-audit) and
[Agent Audit paper](https://arxiv.org/abs/2603.22853). `agent-guard`
measurement details are maintained in [Benchmark Results](benchmark-results.md).
