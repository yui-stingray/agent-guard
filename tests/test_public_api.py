"""Where: tests/test_public_api.py
What: import-surface checks for scanner functions and finding types.
Why: release builds should not hide newly documented scanners from library callers.
"""

from __future__ import annotations

import json
import subprocess
import sys
import textwrap
from pathlib import Path

import agent_guard


def test_public_api_exports_all_scanners() -> None:
    assert callable(agent_guard.scan_urls)
    assert callable(agent_guard.scan_context_files)
    assert callable(agent_guard.scan_paths)
    assert callable(agent_guard.scan_content_paths)
    assert callable(agent_guard.scan_repo_paths)
    assert callable(agent_guard.scan_digests)
    assert callable(agent_guard.build_mcp_config_report)
    assert callable(agent_guard.scan_workflow_policy)


def test_scan_paths_alias_preserves_content_guard_backcompat() -> None:
    assert agent_guard.scan_paths is agent_guard.scan_content_paths


def _standalone_consumer_source(*, guarded: bool) -> str:
    exercise = textwrap.dedent(
        """
        def exercise():
            root = Path.cwd()
            target = root / "blocked-item.md"
            api_policy = {
                "scan": {"include": ["blocked-item.md"], "exclude": []},
                "policy": {
                    "allowed_api_patterns": [],
                    "forbidden_api_patterns": [r"^https://blocked\\.invalid/"],
                },
            }
            path_policy = {
                "scan": {"include": ["blocked-item.md"], "exclude": []},
                "policy": {
                    "allowed_path_patterns": [],
                    "forbidden_path_patterns": [
                        {
                            "id": "blocked_path",
                            "pattern": "blocked-item",
                            "severity": "high",
                            "message": "synthetic blocked path",
                        }
                    ],
                },
            }
            content_rules = build_rules(
                {
                    "forbidden_patterns": [
                        {
                            "id": "blocked_content",
                            "pattern": "BLOCKED_CONTENT",
                            "severity": "high",
                            "message": "synthetic blocked content",
                        }
                    ]
                }
            )
            api_findings = agent_guard.scan_urls(root=root, policy=api_policy)
            path_findings, _ = agent_guard.scan_repo_paths(
                root=root,
                policy=path_policy,
            )
            content_findings = agent_guard.scan_paths([target], content_rules, root)
            content_alias_findings = agent_guard.scan_content_paths(
                [target],
                content_rules,
                root,
            )
            file_findings = scan_file(target, content_rules, root)
            results = {
                "scan_urls": [
                    [item.path, item.line, type(item).__name__] for item in api_findings
                ],
                "scan_repo_paths": [
                    [item.path, item.rule_id, type(item).__name__]
                    for item in path_findings
                ],
                "scan_paths": [
                    [item.file, item.line, item.rule_id, type(item).__name__]
                    for item in content_findings
                ],
                "scan_content_paths": [
                    [item.file, item.line, item.rule_id, type(item).__name__]
                    for item in content_alias_findings
                ],
                "scan_file": [
                    [item.file, item.line, item.rule_id, type(item).__name__]
                    for item in file_findings
                ],
            }
            print(json.dumps(results, sort_keys=True))
        """
    )
    invocation = "exercise()"
    if guarded:
        invocation = "if __name__ == '__main__':\n    exercise()"
    return (
        "import json\n"
        "from pathlib import Path\n"
        "import agent_guard\n"
        "from agent_guard.content_guard import build_rules, scan_file\n\n"
        f"{exercise}\n"
        f"{invocation}\n"
    )


def test_public_scanners_support_unguarded_consumer_with_guarded_parity(
    tmp_path: Path,
) -> None:
    (tmp_path / "blocked-item.md").write_text(
        'endpoint = "https://blocked.invalid/v1"\nBLOCKED_CONTENT\n',
        encoding="utf-8",
    )
    outputs: dict[str, str] = {}

    for label, guarded in (("unguarded", False), ("guarded", True)):
        script = tmp_path / f"{label}_consumer.py"
        script.write_text(
            _standalone_consumer_source(guarded=guarded),
            encoding="utf-8",
        )
        result = subprocess.run(
            [sys.executable, "-I", str(script)],
            cwd=tmp_path,
            capture_output=True,
            check=False,
            text=True,
        )

        assert result.returncode == 0
        assert result.stderr == ""
        outputs[label] = result.stdout

    expected = {
        "scan_content_paths": [
            ["blocked-item.md", 2, "blocked_content", "ContentGuardFinding"]
        ],
        "scan_file": [
            ["blocked-item.md", 2, "blocked_content", "ContentGuardFinding"]
        ],
        "scan_paths": [
            ["blocked-item.md", 2, "blocked_content", "ContentGuardFinding"]
        ],
        "scan_repo_paths": [
            ["blocked-item.md", "blocked_path", "PathGuardFinding"]
        ],
        "scan_urls": [["blocked-item.md", 1, "ApiGuardFinding"]],
    }
    assert outputs == {
        "unguarded": json.dumps(expected, sort_keys=True) + "\n",
        "guarded": json.dumps(expected, sort_keys=True) + "\n",
    }
