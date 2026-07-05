# Comparison: agent-guard and agent-audit

Both projects are useful, but they sit at different layers. `agent-audit` is a detection scanner for agent code; `agent-guard` is a deterministic evidence and conformance layer for agent configuration surfaces.

| Dimension | agent-audit | agent-guard |
| --- | --- | --- |
| Primary target | Agent code. | Agent instruction files, skills directories, MCP configs, context digests, workflows, and evidence artifacts. |
| Main technique | Static AST and taint analysis. | Deterministic static repository evidence, policy conformance, digest pinning, drift checks, and consumer validation. |
| Rule surface | 53 code-focused rules mapped to OWASP ASI. | Config-surface rules and taxonomy mappings for repository-local agent evidence. |
| Output | Scanner findings, including SARIF. | Stable JSON envelopes, sanitized reports, SARIF/annotation rendering, conformance results, and evidence-pack manifests. |
| Published measurement | The authors publish a 22-sample AVB benchmark; see upstream material for the reported score and method details. | Current AGB metrics are reported with population, FP/FN counts, known gaps, and scope limits in [Benchmark Results](benchmark-results.md). |
| Benchmark caveat | The AVB benchmark is self-authored and not independently validated. | The AGB corpus is self-authored, has no independent verification yet, and covers static repository configuration evidence only. |
| Best fit | Finding vulnerabilities in agent code paths. | Proving that repository agent configuration, evidence contracts, and CI gates stayed within policy. |
| Relationship | Its findings could be attached as evidence artifacts. | It could consume or package detection outputs from scanners like `agent-audit` as part of a broader evidence workflow. |

References: `agent-audit` is described as an AST and taint static scanner for agent code at `github.com/HeadyZhang/agent-audit` with paper `arXiv:2603.22853`. `agent-guard` measurement details are maintained in [Benchmark Results](benchmark-results.md).
