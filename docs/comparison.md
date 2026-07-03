# Comparison: agent-guard and agent-audit

Both projects are useful, but they sit at different layers. `agent-audit` is a detection scanner for agent code; `agent-guard` is a deterministic evidence and conformance layer for agent configuration surfaces.

| Dimension | agent-audit | agent-guard |
| --- | --- | --- |
| Primary target | Agent code. | Agent instruction files, skills directories, MCP configs, context digests, workflows, and evidence artifacts. |
| Main technique | Static AST and taint analysis. | Deterministic static repository evidence, policy conformance, digest pinning, drift checks, and consumer validation. |
| Rule surface | 53 code-focused rules mapped to OWASP ASI. | Config-surface rules and taxonomy mappings for repository-local agent evidence. |
| Output | Scanner findings, including SARIF. | Stable JSON envelopes, sanitized reports, SARIF/annotation rendering, conformance results, and evidence-pack manifests. |
| Published measurement | F1 0.91 on the authors' 22-sample AVB benchmark. | AGB F1 0.959, precision 0.921, recall 1.0 on our self-authored 40-case corpus. |
| Benchmark caveat | The AVB benchmark is self-authored and not independently validated. | The AGB benchmark is self-authored and not independently validated. |
| Best fit | Finding vulnerabilities in agent code paths. | Proving that repository agent configuration, evidence contracts, and CI gates stayed within policy. |
| Relationship | Its findings could be attached as evidence artifacts. | It could consume or package detection outputs from scanners like `agent-audit` as part of a broader evidence workflow. |

References: `agent-audit` is described as an AST and taint static scanner for agent code at `github.com/HeadyZhang/agent-audit` with paper `arXiv:2603.22853`. `agent-guard` measurement comes from `bench/results/agb-20260702.json`.
