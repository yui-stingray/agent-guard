"""Offline subprocess regressions for the complete TTFE replay/check pipeline."""
from __future__ import annotations

import importlib.metadata
import json
import os
from pathlib import Path
import subprocess
import sys
import zipfile

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def offline_dependency_wheel(tmp_path_factory):
    """Repack the already installed dependency, without resolving or fetching it."""
    wheelhouse = tmp_path_factory.mktemp("ttfe-wheelhouse")
    dist = importlib.metadata.distribution("PyYAML")
    tag = next(line.split(": ", 1)[1] for line in dist.read_text("WHEEL").splitlines()
               if line.startswith("Tag: "))
    wheel = wheelhouse / f"pyyaml-{dist.version}-{tag}.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        for item in dist.files:
            if ".." in item.parts:
                continue
            path = Path(dist.locate_file(item))
            if path.is_file() and path.suffix != ".pyc" and "__pycache__" not in path.parts:
                archive.write(path, str(item))
    return wheelhouse


class OfflineProcess:
    def __init__(self, wheelhouse, failure=None):
        self.wheelhouse = wheelhouse
        self.failure = failure
        self.calls = []
        self.report_file = None

    def __call__(self, argv, **kwargs):
        argv = [str(x) for x in argv]
        self.calls.append(argv)
        text = " ".join(argv)
        pip = "pip" in argv and "-m" in argv
        if pip:
            env = dict(kwargs.get("env", os.environ))
            env.update(PIP_NO_INDEX="1", PIP_FIND_LINKS=str(self.wheelhouse),
                       PIP_CONFIG_FILE=os.devnull)
            kwargs["env"] = env
        failed = (
            (self.failure == "wheel" and pip and "wheel" in argv and str(ROOT) in argv)
            or (self.failure == "dependency" and pip and any(x in argv for x in ["download", "wheel"])
                and any("pyyaml" in x.lower() for x in argv))
            or (self.failure == "bootstrap" and "-c" in argv and "sys.version_info" in text)
            or (self.failure == "venv" and "-m" in argv and "venv" in argv)
            or (self.failure == "install" and pip and "install" in argv)
            or (self.failure == "init" and "init" in argv)
        )
        if failed:
            return subprocess.CompletedProcess(argv, 1, stdout="", stderr="injected stage failure")
        return subprocess.run(argv, **kwargs)


def check_result(path):
    return subprocess.run(
        [sys.executable, "-m", "bench.ttfe.run", "check", "--input", str(path)],
        cwd=ROOT, text=True, capture_output=True, timeout=30,
    )

@pytest.mark.parametrize("failure", ["wheel", "dependency", "bootstrap", "venv", "install", "init"])
def test_stage_failure_propagates_without_later_onboarding(
    tmp_path, offline_dependency_wheel, failure,
):
    from bench.ttfe.run import execute_replay

    process = OfflineProcess(offline_dependency_wheel, failure)
    result_path = tmp_path / "result.json"
    payload, code = execute_replay(
        repo_root=ROOT, out_path=result_path, python_bin=sys.executable,
        process_runner=process,
    )
    assert code != 0
    assert payload["status"] == "failed"
    assert failure in json.dumps(payload["failure_point"]).lower()
    assert not any("report" in call for call in process.calls)
    assert check_result(result_path).returncode != 0


@pytest.fixture(scope="module")
def real_offline_result(tmp_path_factory, offline_dependency_wheel):
    from bench.ttfe.run import execute_replay

    directory = tmp_path_factory.mktemp("ttfe-real")
    artifact = directory / "result.json"
    process = OfflineProcess(offline_dependency_wheel)
    payload, code = execute_replay(
        repo_root=ROOT, out_path=artifact, python_bin=sys.executable,
        process_runner=process,
    )
    assert code == 0, payload
    assert payload["status"] == "ok"
    assert check_result(artifact).returncode == 0
    return payload


def test_real_wheel_replay_and_checker_agree_after_cleanup(real_offline_result):
    from bench.ttfe.run import validate_result_payload

    assert validate_result_payload(real_offline_result, max_elapsed_ms=900000) == []
    assert real_offline_result["schema_version"] == "agent-guard.ttfe_results.v2"
    assert real_offline_result["candidate"]
    assert real_offline_result["evidence"]


def test_shell_install_failure_never_uses_outer_agent_guard(
    tmp_path, offline_dependency_wheel,
):
    # Test-only interpreter driver injects one pip failure in the replay helper.
    # No production test-mode environment variable or network failure is needed.
    driver = tmp_path / "driver.py"
    calls_path = tmp_path / "calls.json"
    driver.write_text(
        "import json, sys\n"
        f"sys.path[:0] = {[str(ROOT), str(ROOT / 'tests')]!r}\n"
        "from test_ttfe_replay import OfflineProcess\n"
        "from bench.ttfe import run\n"
        f"process = OfflineProcess({str(offline_dependency_wheel)!r}, 'install')\n"
        "original = run.execute_replay\n"
        "def injected(**kwargs):\n"
        "    kwargs['process_runner'] = process\n"
        f"    kwargs['python_bin'] = {sys.executable!r}\n"
        "    try:\n"
        "        return original(**kwargs)\n"
        "    finally:\n"
        f"        open({str(calls_path)!r}, 'w').write(json.dumps(process.calls))\n"
        "run.execute_replay = injected\n"
        "raise SystemExit(run.main(sys.argv[sys.argv.index('replay'):]))\n"
    )
    interpreter = tmp_path / "interpreter"
    import shlex
    interpreter.write_text(
        f"#!/bin/sh\nexec {shlex.quote(sys.executable)} {shlex.quote(str(driver))} \"$@\"\n"
    )
    interpreter.chmod(0o755)
    outer = tmp_path / "outer"
    outer.mkdir()
    marker = tmp_path / "outer-was-used"
    executable = outer / "agent-guard"
    executable.write_text(f"#!/bin/sh\ntouch {shlex.quote(str(marker))}\nexit 0\n")
    executable.chmod(0o755)
    result_path = tmp_path / "result.json"
    env = os.environ.copy()
    env.update(PYTHON=str(interpreter), PYTHONPATH=str(tmp_path / "foreign-package"),
               PATH=str(outer) + os.pathsep + env["PATH"],
               AGENT_GUARD_TTFE_OUT=str(result_path), TMPDIR=str(tmp_path),
               PIP_CONFIG_FILE=os.devnull, PIP_NO_INDEX="1")
    result = subprocess.run(["bash", str(ROOT / "bench/ttfe/run.sh")], cwd=ROOT,
                            env=env, text=True, capture_output=True, timeout=120)
    assert result.returncode != 0
    payload = json.loads(result_path.read_text())
    assert payload["status"] == "failed"
    assert "install" in json.dumps(payload["failure_point"]).lower()
    assert not marker.exists()
    calls = json.loads(calls_path.read_text())
    assert any("pip" in call and "install" in call for call in calls)
    assert not any("init" in call or "report" in call for call in calls)
    assert check_result(result_path).returncode != 0


# Start with a real installation and a consumer-validated report. Each mutation
# changes one contract dimension; no expected result is generated by the gate.
@pytest.mark.parametrize(('path', 'value'), [
    (('commands',), []), (('commands', 0), {}),
    (('commands', 1, 'stage'), 'build-candidate'),
    (('commands', 0, 'index'), True),
    (('commands', 5, 'exit_code'), 1),
    (('commands', 5, 'exit_code'), None),
    (('commands', 0, 'duration_ms'), -1),
    (('commands', 0, 'duration_ms'), 1.5),
    (('commands', 0, 'timeout_ms'), 0),
    (('commands', 3, 'documented_command'), 'unrecognized quickstart'),
    (('commands', 5, 'executed_command'), []),
    (('command_count',), 4), (('command_count',), True),
    (('documented_command_count',), 3),
    (('first_nonzero',), None), (('failure_point',), {'exit_code': 1}),
    (('elapsed_ms',), -1), (('elapsed_ms',), True),
    (('elapsed_ms',), 900001), (('elapsed_ms',), '1'),
    (('status',), []), (('generated_at',), 'invalidZ'),
    (('candidate',), {}),
    (('candidate', 'wheel', 'sha256'), '0' * 64),
    (('candidate', 'install', 'report_version'), ''),
    (('candidate', 'install', 'report_version'), 'future'),
    (('candidate', 'install', 'candidate', 'version'), '0.3.9'),
    (('candidate', 'install', 'candidate', 'requested'), False),
    (('candidate', 'runtime', 'sys_prefix'), '/outer'),
    (('candidate', 'runtime', 'sys_executable'), '<candidate-venv>/../outer/python'),
    (('candidate', 'runtime', 'module_origin'), '/outer/agent_guard/__init__.py'),
    (('candidate', 'runtime', 'entrypoint'), '/outer/agent-guard'),
    (('candidate', 'package_manifests', 'installed', 'sha256'), '0' * 64),
    (('evidence',), {}), (('evidence', 'report', 'fresh'), False),
    (('evidence', 'report', 'payload', 'status'), []),
    (('evidence', 'report', 'payload', 'status'), 'ok'),
    (('evidence', 'report', 'payload', 'conformance'), None),
    (('evidence', 'report', 'payload', 'evidence_pack_manifest'), None),
    (('evidence', 'report', 'consumer_summary'), {}),
])
def test_checker_rejects_inconsistent_durable_proof(real_offline_result, tmp_path, path, value):
    import copy
    from bench.ttfe.run import validate_result_payload
    payload = copy.deepcopy(real_offline_result)
    target = payload
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    assert validate_result_payload(payload, max_elapsed_ms=900000)
    artifact = tmp_path / 'mutated.json'
    artifact.write_text(json.dumps(payload))
    result = check_result(artifact)
    assert result.returncode != 0
    assert 'Traceback' not in result.stderr


def test_checker_rejects_missing_duplicate_and_reordered_stages(real_offline_result):
    import copy
    from bench.ttfe.run import validate_result_payload
    for change in ('missing', 'duplicate', 'reordered'):
        payload = copy.deepcopy(real_offline_result)
        records = payload['commands']
        if change == 'missing':
            records.pop(5)
        elif change == 'duplicate':
            records.append(records[5])
        else:
            records[4], records[5] = records[5], records[4]
        payload['command_count'] = len(records)
        assert validate_result_payload(payload, max_elapsed_ms=900000)


class EvidenceProcess(OfflineProcess):
    def __init__(self, wheelhouse, fault, report_exit=1):
        super().__init__(wheelhouse)
        self.fault, self.report_exit = fault, report_exit

    def __call__(self, argv, **kwargs):
        argv = [str(part) for part in argv]
        fixture = Path(kwargs['cwd'])
        report = fixture / '.agent-guard/evidence/agent-guard-report.json'
        if 'report' in argv and self.fault in ('missing', 'malformed'):
            self.calls.append(argv)
            if self.fault == 'malformed':
                report.parent.mkdir(parents=True, exist_ok=True)
                report.write_text('{"status":"ok"}')
            return subprocess.CompletedProcess(argv, self.report_exit, stdout='', stderr='')
        if 'report' in argv and self.fault == 'clean':
            with (fixture / 'README.md').open('a') as handle:
                handle.write('\nagent-guard surface inventory --root . --context-policy .agent-guard/context-policy.yaml\n')
            with (fixture / 'AGENTS.md').open('a') as handle:
                handle.write('\nRun local verification before reporting success.\n')
        if self.fault == 'interrupted' and 'pip' in argv and 'install' in argv:
            self.calls.append(argv)
            return subprocess.CompletedProcess(argv, -15, stdout='', stderr='')
        if self.fault == 'timeout' and 'pip' in argv and 'install' in argv:
            self.calls.append(argv)
            raise subprocess.TimeoutExpired(argv, 120)
        result = super().__call__(argv, **kwargs)
        if 'init' in argv and '--write' in argv and self.fault == 'stale':
            report.parent.mkdir(parents=True, exist_ok=True)
            report.write_text('{"status":"ok"}')
            os.utime(report, (1, 1))
        if '-c' in argv and 'import agent_guard, agent_guard.cli' in argv[-1] and self.fault in ('outer-python', 'outer-install'):
            identity = json.loads(result.stdout)
            identity['sys_executable' if self.fault == 'outer-python' else 'module_origin'] = '/outer/python'
            return subprocess.CompletedProcess(argv, 0, stdout=json.dumps(identity), stderr='')
        return result


@pytest.mark.parametrize(('fault', 'exit_code'), [
    ('missing', 0), ('missing', 1), ('malformed', 0), ('malformed', 1),
    ('stale', 1), ('interrupted', 1), ('timeout', 1),
    ('outer-python', 1), ('outer-install', 1),
])
def test_replay_rejects_invalid_evidence_and_wrong_runtime(tmp_path, offline_dependency_wheel, fault, exit_code):
    from bench.ttfe.run import execute_replay
    process = EvidenceProcess(offline_dependency_wheel, fault, exit_code)
    artifact = tmp_path / 'result.json'
    payload, code = execute_replay(repo_root=ROOT, out_path=artifact,
                                   python_bin=sys.executable, process_runner=process)
    assert code != 0
    assert payload['status'] == 'failed'
    assert check_result(artifact).returncode != 0
    if fault == 'stale':
        assert not any('report' in call for call in process.calls)


def test_real_clean_report_zero_is_accepted(tmp_path, offline_dependency_wheel):
    from bench.ttfe.run import execute_replay
    process = EvidenceProcess(offline_dependency_wheel, 'clean')
    artifact = tmp_path / 'result.json'
    payload, code = execute_replay(repo_root=ROOT, out_path=artifact,
                                   python_bin=sys.executable, process_runner=process)
    assert code == 0, payload
    assert payload['evidence']['report']['payload']['status'] == 'ok'
    assert next(r for r in payload['commands'] if r['stage'] == 'report')['exit_code'] == 0
    assert check_result(artifact).returncode == 0

@pytest.fixture(scope='module')
def built_candidate_wheel(tmp_path_factory):
    wheelhouse = tmp_path_factory.mktemp('ttfe-candidate-wheel')
    environment = os.environ.copy()
    environment.update(PIP_NO_INDEX='1', PIP_CONFIG_FILE=os.devnull)
    result = subprocess.run(
        [sys.executable, '-I', '-m', 'pip', 'wheel', '--no-build-isolation',
         '--no-deps', '--wheel-dir', str(wheelhouse), str(ROOT)],
        text=True, capture_output=True, env=environment, timeout=120,
    )
    assert result.returncode == 0, result.stderr
    return next(wheelhouse.glob('yui_agent_guard-*.whl'))


def test_different_same_version_wheel_is_rejected_before_install(
    tmp_path, offline_dependency_wheel, built_candidate_wheel,
):
    from bench.ttfe.run import execute_replay
    altered = tmp_path / built_candidate_wheel.name
    with zipfile.ZipFile(built_candidate_wheel) as source, zipfile.ZipFile(altered, 'w') as target:
        for info in source.infolist():
            data = source.read(info)
            if info.filename == 'agent_guard/__init__.py':
                data += b'\n# another wheel with the same version\n'
            target.writestr(info, data)
    process = OfflineProcess(offline_dependency_wheel)
    payload, code = execute_replay(repo_root=ROOT, out_path=tmp_path/'result.json',
                                   python_bin=sys.executable, process_runner=process,
                                   candidate_wheel=altered)
    assert code != 0
    assert payload['status'] == 'failed'
    assert not any('install' in call for call in process.calls)


@pytest.mark.parametrize('field', ['candidate', 'evidence', 'execution', 'elapsed_ms', 'commands', 'status'])
def test_required_proof_fields_cannot_be_omitted(real_offline_result, field):
    import copy
    from bench.ttfe.run import validate_result_payload
    payload = copy.deepcopy(real_offline_result)
    del payload[field]
    assert validate_result_payload(payload, max_elapsed_ms=900000)


def test_unknown_quickstart_is_rejected_before_any_execution(tmp_path):
    from bench.ttfe.run import execute_replay
    source = tmp_path / 'checkout'
    (source / 'docs').mkdir(parents=True)
    (source / 'docs/quickstart-existing-repo.md').write_text('```bash\necho changed\n```\n')
    calls = []
    def forbidden(*args, **kwargs):
        calls.append(args)
        raise AssertionError('unknown markdown must never be evaluated')
    payload, code = execute_replay(repo_root=source, out_path=tmp_path/'result.json',
                                   process_runner=forbidden)
    assert code != 0
    assert payload['failure_point']['stage'] == 'prepare-replay'
    assert not calls
