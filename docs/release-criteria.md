# Release Criteria

`agent-guard` is still `0.1.x` alpha. Releases should stay small and evidence
driven.

## Patch Release Candidates

Consider the next patch release when at least one of these changes lands:

- a CLI behavior change that downstream CI users need from PyPI;
- a packaged JSON Schema change or new packaged schema;
- a report payload compatibility fix;
- a workflow, packaging, or wheel-contract fix that affects installed users;
- documentation that must appear on PyPI because the README changed materially.

Docs-only changes under `docs/` do not need an immediate release unless they
change the README or are needed by users who only read the packaged project
page.

## Release Readiness

Before tagging, verify:

- full test suite passes on the supported Python versions;
- self-dogfood `path`, `context`, `context lock`, `digest`, `content`,
  `workflow`, and `report` gates pass;
- packaged schemas are present in the wheel;
- wheel contract check passes from a clean install;
- GitHub Actions CI is green on the release commit;
- no generated private evidence, local paths, credentials, or private fixtures
  are tracked.

The release workflow remains tag-driven. Do not publish from an unreviewed
branch.

## Non-Goals For Releases

Do not use a release as a reason to expand into LLM review, issue triage,
model routing, MoA orchestration, broad credential scanning, or a general
governance framework. Those tools can consume `agent-guard` evidence, but they
should remain separate layers.
