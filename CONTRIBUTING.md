# Contributing to agent-guard

`agent-guard` provides static checks for agent-touched repositories. It should
stay small, deterministic, and easy to run in hooks or CI.

## Good first contributions

- Improve scanner examples and policy documentation.
- Add tests for path, content, digest, or API guard edge cases.
- Improve JSON output consistency while preserving existing fields.
- Add narrowly scoped scanners only when they can run without network access
  and without reading private state outside the requested repository root.

## Local setup

Use Python 3.11 or newer.

```bash
python -m venv .venv
. .venv/bin/activate
pip install -e ".[dev]"
python -m pytest -q
```

If local pytest capture is unstable in your environment, run:

```bash
python -m pytest -s -q
```

## Pull request expectations

- Keep each PR focused on one scanner, CLI behavior, or documentation topic.
- Add tests for behavior changes and regression cases.
- Preserve the CLI exit-code contract: `0` clean, `1` violation, `2`
  configuration or runtime error.
- Avoid network access and avoid scanning outside explicit roots.

## Release notes

User-visible changes should update `CHANGELOG.md`. Version bumps should remain
separate from feature or fix patches unless the change is specifically a
release preparation patch.
