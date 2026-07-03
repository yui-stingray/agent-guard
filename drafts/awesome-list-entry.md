# Proposed Awesome List Entry

Suggested category: static evidence, conformance, and repository policy gates for agent skills and configuration.

`agent-guard` is a vendor-neutral static evidence and conformance layer for repositories touched by coding agents. It checks agent instruction files, skills directories, MCP configuration, pinned context digests, workflow drift, and sanitized evidence reports without executing tools or MCP servers. The angle is complementary to detection scanners: rather than trying to find every vulnerability in agent code, it produces deterministic repository-local evidence that CI, release gates, and downstream consumers can validate across agent frameworks.

needs_human_review: true
