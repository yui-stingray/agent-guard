# CLI reference

Command synopsis for the `agent-guard` CLI. See the
[scanner reference](scanners.md) for what each command checks.

```bash
agent-guard init --root <repo> [--print] [--write] [--skip-existing] [--force] [--json]
agent-guard api check --root <repo> --policy <yaml> [--json]
agent-guard content check --repo-root <repo> --policy <yaml> --mode <registered|preregister|new> [--scan-dir <dir>] [--targets <paths...>] [--since-ref <ref>] [--no-untracked] [--json]
agent-guard context check --root <repo> --policy <yaml> [--json]
agent-guard context inventory --root <repo> --policy <yaml> [--json]
agent-guard context lock --root <repo> --policy <yaml> [--check --digest-policy <yaml>] [--json]
agent-guard mcp check --root <repo> [--policy <yaml>] [--json]
agent-guard surface inventory --root <repo> --context-policy <yaml> [--schema-version <v1|v2>] [--json]
agent-guard report --root <repo> --context-policy <yaml> [--evidence-preset recommended] [--path-policy <yaml>] [--content-policy <yaml>] [--content-scan-dir <dir>] [--api-policy <yaml>] [--mcp-config-check] [--mcp-policy <yaml>] [--digest-policy <yaml>] [--workflow-policy <yaml>] [--drift-check] [--drift-base-ref <ref>] [--agent-policy-audit-event <path> --agent-policy-audit-event-profile <profile>] [--format <markdown|json|github-annotations|sarif>] [--output <path>] [--stderr-summary]
agent-guard render-report --root <repo> --input <agent-guard-report.json> [--format <markdown|json|github-annotations|sarif>] [--output <path>]
agent-guard path check --root <repo> --policy <yaml> [--json]
agent-guard digest check --root <repo> --policy <yaml> [--json]
agent-guard workflow check --root <repo> --policy <yaml> [--json]
agent-guard drift check --root <repo> [--profile <minimal|recommended|strict>] [--schema-version <v1|v2>] [--base-ref <ref>] [--json]
agent-guard surface delta --root <repo> --context-policy <yaml> --base-ref <ref> [--schema-version <v1>] [--json]
agent-guard report --root <repo> --context-policy <yaml> --surface-delta-base-ref <ref> [--format <markdown|json|github-annotations>] [--output <path>]
```

Policy path arguments are resolved relative to the relevant repository root
(`--root` or `--repo-root`) unless an absolute path is provided. Public report
payloads keep in-repository policy paths repo-relative and display external
policy files as `<external-policy>`. In the repo-scoped `content check` modes
(`registered` and `new`), `--scan-dir` must resolve under `--repo-root`;
registered file targets and discovered directory symlinks must also resolve
under that root. Use `preregister` with explicit `--targets` for local review
of candidates outside the repository.
