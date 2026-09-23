# TTFE candidate replay

This local benchmark replays the four-command initial diagnostic path from
`docs/quickstart-existing-repo.md` against a wheel built from the current
checkout. It does not change the published quickstart's release pin.

Use a development environment with the project's existing build/test tools:

```bash
PYTHON="$(command -v python)" AGENT_GUARD_TTFE_OUT=/tmp/agent-guard-ttfe.json \
  bash bench/ttfe/run.sh
python -m bench.ttfe.run check --input /tmp/agent-guard-ttfe.json --max-elapsed-ms 900000
```

CI runs this path with Python 3.14. The runner's interpreter supplies benchmark
and build tools; a separate fresh venv supplies the installed candidate and all
onboarding commands. Python 3.12 regression tests do not substitute for the
Python 3.14 replay.

The replay recognizes the documented bootstrap/install, init preview, init
write and recommended report steps. It records the original commands and the
executed candidate commands. The published install is replaced only at the
known install step with an explicit local wheel installation. Explicit venv
Python/entry-point paths replace reliance on shell activation. An unrecognized
quickstart edit fails instead of being interpreted as arbitrary shell code.

Bootstrap, environment creation, installation and init must exit zero. Report
exit zero or one is accepted only with a newly generated, structurally valid
recommended report whose status agrees with the process result. A diagnostic
violation is valid evidence of findings, not a clean policy gate. Missing,
stale, malformed or inconsistent evidence fails the replay.

## Result contract

`agent-guard.ttfe_results.v2` binds the source revision, candidate wheel digest,
actual installation record, installed package bytes, interpreter/venv/package
locations and entry point. The result also retains the validated report and
ordered command records. The checker verifies their consistency after the
temporary replay directory is removed; it does not require deleted paths to
remain accessible.

These records are evidence of a controlled local validation, not provenance
attestation against a compromised host. Benchmark results contain local
installation metadata and must be reviewed before sharing. Their metadata is
separate from the sanitized product report; no product report schema changes.

After Python 3.14 replay succeeds or fails, CI retains any generated v2 result
as `agent-guard-ttfe-py314-<run_id>-<run_attempt>` for 14 days. It contains
the extracted install metadata and validated report, not the raw pip receipt,
wheel archive, venv or environment dump. Download it for independent checking;
the self-dogfood evidence bundle is a separate artifact. An upload or missing
result failure fails CI, and uploading a failed replay does not make it pass.

Historical `agent-guard.ttfe_results.v1` files remain historical measurements.
A wheelhouse flag and report command marker did not prove installation or
evidence generation. The current checker rejects them with a rerun requirement;
it does not upgrade or rewrite old success records.

Wheel/dependency preparation occurs before the measured onboarding interval and
is recorded separately. The 900000 ms replay ceiling remains unchanged. A
measured elapsed-time ceiling is not an operating-system process timeout:
subprocesses have finite limits, and external regression invocations also use
finite timeouts. A JSON result written after a failure is diagnostic output,
not successful measurement. Runner and checker both return failure for invalid
or incomplete proof.

Offline failure-injection tests exercise preparation, installation and evidence
failures. They supplement the real-wheel end-to-end run; stub success is not
proof that the candidate was installed.
