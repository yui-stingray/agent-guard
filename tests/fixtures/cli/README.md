# CLI entrypoint characterization

`entrypoint-output.json` records the unchanged CLI at commit
`91ef96a9e069222f3b1cfd56fee5a20ddd09334d` under CPython
3.11.4, 3.12.12, 3.13.14 and 3.14.6 on Linux. Cases are an independent
list of all 29 help nodes, version, and missing/unknown commands at the root
and each of the 11 groups. Each case has separate installed console and
module observations. Identical stream pairs are stored once; integer references
only deduplicate exact equality, never normalize output.

The test runs from an empty external cwd with no inherited Python import
overrides. The fixture records the language, color and terminal-width settings.
The wide terminal keeps usage on one line so interpreter basename length does
not alter wrapping. CPython's argparse wording differs across minors, notably
invalid-choice quoting and Python 3.14 module program names, so each minor has
its own observed mapping. New interpreter behavior requires review, not an
automatic fixture refresh.

Actual stdout/stderr are compared as bytes. Expected program names are expanded
only in usage/error prefixes from the selected runtime and installed executable;
the version text and help prose are unchanged. Expected Windows newline bytes
are explicit. Windows has not been used to capture these Linux baselines;
Windows execution, including Python 3.14 distlib launcher naming, remains a CI
validation requirement. No actual output fields are removed or masked.

These tests fix a migration comparison surface. They do not declare incidental
shim exports a permanent public API, replace scanner/security tests, or update
policy/evidence digests. Root API aliases and spawn-main non-execution are
already covered by `tests/test_public_api.py` and `tests/test_cli.py`.
