# Contributing to agent-guard

`agent-guard` provides static checks for agent-touched repositories. It should
stay small, deterministic, and easy to run in hooks or CI.

## Good first contributions

- Improve scanner examples and policy documentation.
- Add tests for path, content, digest, or API guard edge cases.
- Improve JSON output consistency while preserving existing fields.
- Add narrowly scoped scanners only when they can run without network access
  and without reading private state outside the requested repository root.
- Do not add runtime MCP execution, live OAuth validation, generic credential
  scanning, model judging, LLM review, or issue-triage automation to this
  package.

## Local setup

Use Python 3.11.4 or newer.

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

## Optional YAML style check

YAML style checking is an optional developer check, separate from the required
CI checks and from `actionlint` workflow validation. The repository's
`.yamllint` configuration was verified with yamllint 1.38.0. Install that version
in a separate virtual environment outside the checkout if needed; it is not
part of the package's `dev` dependencies.

From the repository root, using the Python environment that contains yamllint,
check only Git-tracked YAML files with NUL-safe filename handling:

```bash
python - <<'PY'
import os
import subprocess
import sys

paths = subprocess.check_output(["git", "ls-files", "-z"]).split(b"\0")
yaml_paths = [os.fsdecode(p) for p in paths if p.endswith((b".yaml", b".yml"))]
if yaml_paths:
    raise SystemExit(subprocess.call([
        sys.executable, "-m", "yamllint", "-c", ".yamllint", "--", *yaml_paths,
    ]))
PY
```

`yamllint .` also traverses untracked files subject to `.yamllint` exclusions;
local build outputs or virtual environments can therefore change its results.
Keep such diagnostics separate from tracked-source diagnostics.

## Pull request expectations

- Keep each PR focused on one scanner, CLI behavior, or documentation topic.
- Add tests for behavior changes and regression cases.
- Preserve the CLI exit-code contract: `0` clean, `1` violation, `2`
  configuration or runtime error.
- Avoid network access and avoid scanning outside explicit roots.
- Keep public artifacts sanitized: no raw local paths, credentials, raw snippets,
  raw URLs, raw scope strings, or private command transcripts.

## Release notes

User-visible changes should update `CHANGELOG.md`. Version bumps should remain
separate from feature or fix patches unless the change is specifically a
release preparation patch.
