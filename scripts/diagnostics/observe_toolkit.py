"""Task-scoped observation only; the fixed Toolkit checkout is never edited."""
from __future__ import annotations

import argparse
import datetime
import hashlib
import importlib.util
import json
import os
import platform
import zipfile
from pathlib import Path
import signal
import stat
import subprocess
import sys
import time

SAFE_ENV = ('PATH', 'HOME', 'TEMP', 'TMP', 'TMPDIR', 'VIRTUAL_ENV', 'PYTHON',
            'GIT_CONFIG_NOSYSTEM', 'GIT_TERMINAL_PROMPT', 'LANG', 'LC_ALL', 'TZ',
            'CI', 'GITHUB_ACTIONS', 'GITHUB_EVENT_NAME', 'RUNNER_OS', 'RUNNER_ARCH',
            'AGENT_SAFETY_CANDIDATE_WHEEL_COMPATIBILITY')

def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def save(path, value):
    temporary = path.with_suffix(path.suffix + '.new')
    with private_file(temporary) as f:
        f.write((json.dumps(value, indent=2) + '\n').encode())
        f.flush()
        os.fsync(f.fileno())
    temporary.replace(path)

def private_file(path):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
        os.close(fd)
        raise RuntimeError('invalid capture file')
    return os.fdopen(fd, 'wb', buffering=0)

def load_harness(path):
    spec = importlib.util.spec_from_file_location('fixed_toolkit_harness', path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module

PROBE = r'''
import sys, json, platform, importlib.metadata as m, hashlib
from pathlib import Path
import agent_guard, agent_guard.cli
p=Path(agent_guard.__file__).resolve().parent
files={x.relative_to(p).as_posix():hashlib.sha256(x.read_bytes()).hexdigest() for x in p.rglob('*') if x.is_file() and '__pycache__' not in x.parts and x.suffix!='.pyc'}
dist=m.distribution('yui-agent-guard')
selected={name:m.version(name) for name in ['pip','pytest','pluggy','iniconfig','packaging','Pygments','PyYAML','yui-agent-guard','yui-agent-policy']}
eps=[{'name':e.name,'value':e.value,'distribution':e.dist.metadata['Name']} for e in m.entry_points(group='pytest11')]
print(json.dumps({'python':sys.version,'executable':sys.executable,'prefix':sys.prefix,'platform':platform.platform(),'machine':platform.machine(),'versions':selected,'pytest_entrypoints_installed':eps,'loaded_pytest_plugins':'not observed; no pytest process instrumentation','package_origin':str(p),'cli_origin':agent_guard.cli.__file__,'main_owner':agent_guard.cli.main.__module__,'package_files':files,'direct_url':json.loads(dist.read_text('direct_url.json'))},sort_keys=True))
'''


def manifest_digest(files):
    return hashlib.sha256(json.dumps(files, sort_keys=True, separators=(',', ':')).encode()).hexdigest()

def provenance(wheel, harness):
    # The release job supplies its one built wheel. Compare package bytes, not timestamps.
    source = Path.cwd() / 'src/agent_guard'
    files = {p.relative_to(source).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
             for p in source.rglob('*') if p.is_file() and '__pycache__' not in p.parts and p.suffix != '.pyc'}
    with zipfile.ZipFile(wheel) as archive:
        packaged = {n[len('agent_guard/'):]: hashlib.sha256(archive.read(n)).hexdigest()
                    for n in archive.namelist() if n.startswith('agent_guard/') and not n.endswith('/')}
    if not files or files != packaged:
        raise RuntimeError('release wheel package does not match the checked source')
    return {'wheel_sha256': hashlib.sha256(wheel.read_bytes()).hexdigest(),
            'wheel_package_manifest_sha256': manifest_digest(packaged),
            'source_package_manifest_sha256': manifest_digest(files),
            'package_file_count': len(files), 'wheel_matches_source': True,
            'outer_python_version': platform.python_version(),
            'release_lock_sha256': hashlib.sha256(Path('requirements/release-tools.txt').read_bytes()).hexdigest(),
            'toolkit_lock_sha256': hashlib.sha256((harness.parent.parent/'requirements/agent-safety-tools.txt').read_bytes()).hexdigest(),
            'harness_sha256': hashlib.sha256(harness.read_bytes()).hexdigest()}

class Observer:
    def __init__(self, harness, out, enable_probe=False):
        self.harness = harness
        self.out = out
        self.enable_probe = enable_probe
        self.records = []
        self.probe_done = False

    def probe(self, cwd, env):
        """Read-only identity observation AFTER the formal stop point, not a gate stage."""
        if not self.enable_probe or self.probe_done or 'VIRTUAL_ENV' not in env:
            return
        self.probe_done = True
        python = Path(env['VIRTUAL_ENV']) / 'bin/python'
        args = [str(python), '-I', '-B', '-c', PROBE]
        # External cwd and outputs keep metadata out of the copied/staged worktree.
        with private_file(self.out / 'identity.stdout') as stdout, private_file(self.out / 'identity.stderr') as stderr:
            p = subprocess.run(args, cwd=self.out, env=env, stdin=subprocess.DEVNULL,
                               stdout=stdout, stderr=stderr, check=False, timeout=30)
        save(self.out / 'identity-command.json', {'phase': 'after formal failure or final success',
             'argv': args, 'cwd': str(self.out), 'exit_code': p.returncode,
             'formal_stage_order_unchanged': True})
        if p.returncode:
            raise RuntimeError('post-stage identity observation failed')

    def __call__(self, stage, argv, *, cwd, env):
        index = len(self.records) + 1
        stem = f'{index:02d}-' + ''.join(c if c.isalnum() else '-' for c in stage)
        out, err = self.out / (stem + '.stdout'), self.out / (stem + '.stderr')
        record = {'index': index, 'stage': stage, 'argv': list(argv), 'cwd': str(cwd),
                  'env_allowlist': {k: env[k] for k in SAFE_ENV if k in env},
                  'env_passed_unchanged': True, 'stdin': 'DEVNULL', 'check': False,
                  'start': now(), 'end': None, 'returncode': None, 'exception': None,
                  'stdout': str(out), 'stderr': str(err), 'state': 'RUNNING',
                  'capture_truncated': False}
        self.records.append(record)
        save(self.out / 'stages.json', self.records)
        started = time.monotonic()
        failure = None
        try:
            with private_file(out) as stdout, private_file(err) as stderr:
                try:
                    completed = subprocess.run(list(argv), cwd=cwd, env=env,
                                               stdin=subprocess.DEVNULL, stdout=stdout,
                                               stderr=stderr, check=False)
                    record['returncode'] = completed.returncode
                    record['state'] = 'PASS' if completed.returncode == 0 else 'FAIL'
                except OSError as exc:
                    record['exception'] = {'type': type(exc).__name__, 'errno': exc.errno}
                    record['state'] = 'SPAWN_ERROR'
                    failure = exc
                finally:
                    stdout.flush()
                    stderr.flush()
                    os.fsync(stdout.fileno())
                    os.fsync(stderr.fileno())
        except BaseException as exc:
            record['state'] = 'INTERRUPTED' if isinstance(exc, (KeyboardInterrupt, SystemExit)) else 'OBSERVATION_ERROR'
            record['exception'] = {'type': type(exc).__name__, 'errno': getattr(exc, 'errno', None)}
            raise
        finally:
            record['end'] = now()
            record['seconds'] = round(time.monotonic() - started, 6)
            for name, path in [('stdout', out), ('stderr', err)]:
                if path.exists():
                    record[name + '_bytes'] = path.stat().st_size
                    record[name + '_sha256'] = hashlib.sha256(path.read_bytes()).hexdigest()
            save(self.out / 'stages.json', self.records)
        if failure is not None or record['returncode'] != 0:
            self.probe(cwd, env)
            raise self.harness.CompatibilityError(f'candidate compatibility failed during {stage}') from None
        if stage == 'packaged snapshot consumer':
            self.probe(cwd, env)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--harness', type=Path, required=True)
    ap.add_argument('--wheel', type=Path, required=True)
    ap.add_argument('--out', type=Path, required=True)
    args = ap.parse_args()
    args.out.mkdir(mode=0o700, parents=True, exist_ok=False)
    save(args.out / 'provenance.json', provenance(args.wheel, args.harness))
    harness = load_harness(args.harness)
    original_run = subprocess.run
    observer = Observer(harness, args.out, enable_probe=True)
    harness._run_silent = observer
    def interrupted(signum, frame):
        save(args.out / 'interrupted.json', {'time': now(), 'signal': signum})
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, interrupted)
    start = now()
    result = None
    try:
        result = harness.main(['--wheel', str(args.wheel)])
        return result
    finally:
        assert subprocess.run is original_run
        save(args.out / 'harness-result.json', {'start': start, 'end': now(), 'exit_code': result,
             'stage_count': len(observer.records), 'harness_root': str(harness.ROOT),
             'harness_sha256': hashlib.sha256(args.harness.read_bytes()).hexdigest(),
             'wheel_sha256': hashlib.sha256(args.wheel.read_bytes()).hexdigest(),
             'subprocess_run_unchanged': True, 'only_harness_binding_replaced': '_run_silent'})

if __name__ == '__main__':
    raise SystemExit(main())
