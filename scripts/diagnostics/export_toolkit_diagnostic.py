"""Export allowlisted metadata and safe pytest excerpts, never arbitrary raw text."""
import argparse
import ast
import datetime
import hashlib
import json
from pathlib import Path
import re

STAGES = (
    'isolated toolkit initialization', 'isolated toolkit staging',
    'isolated toolkit baseline commit', 'isolated CPython environment creation',
    'committed hash lock installation', 'candidate wheel overlay', 'pip dependency check',
    'candidate evidence warmup', 'candidate evidence baseline staging',
    'candidate evidence baseline commit', 'full toolkit pytest', 'toolkit demo',
    'example snapshot consumer', 'packaged snapshot consumer',
)
STATES = {'RUNNING', 'PASS', 'FAIL', 'SPAWN_ERROR', 'INTERRUPTED', 'OBSERVATION_ERROR'}
EXCEPTIONS = {'OSError', 'FileNotFoundError', 'PermissionError', 'AssertionError', 'RuntimeError',
              'ValueError', 'TypeError', 'ImportError', 'ModuleNotFoundError', 'TimeoutError',
              'TimeoutExpired', 'KeyboardInterrupt', 'SystemExit', 'MemoryError', 'Exception'}
VERSIONS = {'pip', 'pytest', 'pluggy', 'iniconfig', 'packaging', 'Pygments', 'PyYAML', 'yui-agent-guard', 'yui-agent-policy'}

def integer(value):
    return value if type(value) is int else None

def digest(value):
    return value if type(value) is str and re.fullmatch('[a-f0-9]{64}', value) else None


def timestamp(value):
    if value is None:
        return None
    datetime.datetime.fromisoformat(value)
    return value

def public_command(record):
    literals = {'git', 'init', '--quiet', 'add', '--all', '-c', 'user.name=Candidate Wheel Check',
                'user.email=candidate-wheel-check@example.invalid', 'core.hooksPath=/dev/null',
                'commit', '--no-gpg-sign', '-m', 'candidate compatibility baseline',
                'venv', 'pip', '--isolated', '--disable-pip-version-check', '--no-input',
                'install', '--require-hashes', '-r', '--no-index', '--no-deps', '--force-reinstall',
                'check', 'bash', 'scripts/run_demo.sh', '--', '--allow-empty',
                'candidate evidence baseline', 'pytest', '-q', 'scripts/evidence_publication.py',
                'consume', '--repo', '.', '--consumer', 'example', 'packaged',
                '.agent-guard/evidence/agent-guard-report.json',
                '.agent-guard/evidence/agent-guard-evidence-pack.json',
                '.agent-policy/evidence/policy-admission-event.json'}
    argv = []
    for i, value in enumerate(record['argv']):
        path = Path(value)
        if value in literals:
            argv.append(value)
        elif i == 0 and path.is_absolute() and path.name == 'python':
            argv.append('<OUTER_PYTHON>' if record['stage'] == 'isolated CPython environment creation' else '<INNER_PYTHON>')
        elif path.is_absolute() and path.name == 'venv':
            argv.append('<INNER_VENV>')
        elif path.is_absolute() and path.parts[-2:] == ('requirements', 'agent-safety-tools.txt'):
            argv.append('<TOOLKIT_COPY>/requirements/agent-safety-tools.txt')
        elif path.is_absolute() and re.fullmatch(r'yui_agent_guard-[0-9A-Za-z_.+-]+-py3-none-any\.whl', path.name):
            argv.append('<STAGED_RELEASE_WHEEL>')
        else:
            raise ValueError('unexpected command token; public export blocked')
    return argv

def public_nodes(toolkit):
    nodes = set()
    for path in (toolkit/'tests').rglob('*.py'):
        relative = path.relative_to(toolkit).as_posix()
        for node in ast.walk(ast.parse(path.read_text())):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith('test_'):
                nodes.add((relative, node.name))
    return nodes

def safe_excerpt(data, toolkit):
    # Keep only unambiguous pytest syntax and identifiers present in the fixed public source.
    # Dynamic values, source/fixture bodies and arbitrary exception messages are omitted.
    text = data.decode('utf-8', errors='replace')
    if not data or re.fullmatch(r'[.sFxX\r\n ]+', text):
        return text[:131072], {'redacted': False, 'truncated': len(text) > 131072,
                              'omitted_lines': 0, 'detail_state': 'COMPLETE' if len(text) <= 131072 else 'TRUNCATED'}
    nodes = public_nodes(toolkit)
    lines = []
    omitted = 0
    for line in text.splitlines(keepends=True):
        clean = line.rstrip('\r\n')
        node = re.match(r'^(FAILED|ERROR) (tests/[A-Za-z0-9_/]+\.py)::((?:[A-Za-z0-9_]+::)*)(test_[A-Za-z0-9_]+)', clean)
        frame = re.fullmatch(r'(tests/[A-Za-z0-9_/]+\.py):(\d+): ([A-Za-z]+Error)', clean)
        typ = re.match(r'^(?:E\s+)?([A-Za-z]+Error|TimeoutExpired|KeyboardInterrupt|SystemExit)(?::|$)', clean)
        if node and (node[2], node[4]) in nodes:
            # Class/parameter/message values are intentionally excluded.
            lines.append(node[1]+' '+node[2]+'::'+node[4]+'\n')
            omitted += int(clean != lines[-1].rstrip('\n'))
        elif frame and frame[3] in EXCEPTIONS and (toolkit/frame[1]).is_file():
            count = len((toolkit/frame[1]).read_text().splitlines())
            if 0 < int(frame[2]) <= count:
                lines.append(line)
            else:
                omitted += 1
        elif typ and typ[1] in EXCEPTIONS:
            lines.append(typ[1]+'\n')
            omitted += int(clean != typ[1])
        elif re.fullmatch(r'[= ]*(?:FAILURES|ERRORS|short test summary info)[= ]*', clean):
            lines.append(line)
        elif re.fullmatch(r'[= ]*(?:\d+ (?:passed|failed|skipped|deselected|errors?|warnings?)(?:, )?)+ in \d+(?:\.\d+)?s(?: \([0-9:]+\))?[= ]*', clean):
            lines.append(line)
        else:
            omitted += 1
    result = ''.join(lines)
    return result[:131072], {'redacted': bool(omitted), 'truncated': len(result) > 131072,
                            'omitted_lines': omitted, 'detail_state': 'PARTIAL_UNVERIFIED' if omitted else 'COMPLETE'}

def make_summary(root, toolkit, candidate, public_dir=None):
    assert re.fullmatch('[a-f0-9]{40}', candidate)
    out = {'checkout_sha': candidate, 'raw_logs_uploaded': False, 'stages': [],
           'failed_test_functions': [], 'exception_types_reported': [], 'pytest_reported_counts': {}}
    records_path = root/'stages/stages.json'
    records = json.loads(records_path.read_text()) if records_path.exists() else []
    out['observation_state'] = 'RECORDED' if records else 'NOT_RUN'
    for record in records:
        if record['stage'] not in STAGES or record['state'] not in STATES:
            raise ValueError('unrecognized diagnostic record; export blocked')
        item = {k: record[k] for k in ('stage', 'state')}
        item.update(index=integer(record.get('index')), returncode=integer(record.get('returncode')),
                    start=timestamp(record.get('start')), end=timestamp(record.get('end')),
                    argv=public_command(record),
                    cwd='<TEMP_ROOT>' if record['stage'] == 'isolated CPython environment creation' else '<TOOLKIT_COPY>',
                    env_passed_unchanged=record.get('env_passed_unchanged') is True,
                    stdin='DEVNULL', check=False, capture_truncated=False,
                    stage_timeout_added=False)
        exception = record.get('exception') or {}
        item['exception_type'] = exception.get('type') if exception.get('type') in EXCEPTIONS else None
        item['errno'] = integer(exception.get('errno'))
        for stream in ('stdout', 'stderr'):
            item[stream+'_bytes'] = integer(record.get(stream+'_bytes'))
            item[stream+'_sha256'] = digest(record.get(stream+'_sha256'))
        out['stages'].append(item)
        if record['stage'] != 'full toolkit pytest':
            item['output_body_state'] = 'NOT_EXPORTED: raw installation/demo/consumer text withheld'
            continue
        for stream in ('stdout', 'stderr'):
            path = Path(record[stream]).resolve()
            assert path.is_relative_to(root.resolve())
            if not path.is_file() or path.stat().st_size > 33554432:
                item[stream+'_public_excerpt'] = {'detail_state': 'UNVERIFIED', 'reason': 'missing or capture limit exceeded'}
                continue
            data = path.read_bytes()
            observed_hash = hashlib.sha256(data).hexdigest()
            expected_size = item[stream+'_bytes']
            expected_hash = item[stream+'_sha256']
            final_metadata = expected_size is not None and expected_hash is not None
            if final_metadata and (len(data) != expected_size or observed_hash != expected_hash):
                raise ValueError('captured stream digest changed')
            item[stream+'_export_bytes'] = len(data)
            item[stream+'_export_sha256'] = observed_hash
            item[stream+'_capture_finalized'] = final_metadata
            excerpt, protection = safe_excerpt(data, toolkit)
            if not final_metadata:
                protection['detail_state'] = 'PARTIAL_UNVERIFIED'
                protection['interrupted_capture'] = True
            if public_dir is not None:
                public_dir.mkdir(parents=True, exist_ok=True)
                name = 'pytest.'+stream+'.txt'
                payload = excerpt.encode()
                (public_dir/name).write_bytes(payload)
                protection.update(file=name, bytes=len(payload), sha256=hashlib.sha256(payload).hexdigest())
            item[stream+'_public_excerpt'] = protection
            text = excerpt
            # Only tracked-looking source-relative test function identifiers; drop parameter values/messages.
            for match in re.finditer(r'(?m)^(?:FAILED|ERROR) (tests/[A-Za-z0-9_/]+\.py)::((?:[A-Za-z0-9_]+::)*test_[A-Za-z0-9_]+)', text):
                file, name = match.groups()
                if '..' not in Path(file).parts and (toolkit/file).is_file():
                    out['failed_test_functions'].append(file+'::'+name)
            for typ in EXCEPTIONS:
                if re.search(r'(?m)^(?:E\s+)?'+re.escape(typ)+r'(?:\s*:|\s*$)', text):
                    out['exception_types_reported'].append(typ)
            for count, result in re.findall(r'\b(\d+) (passed|failed|skipped|deselected|errors?|warnings?)\b', text):
                out['pytest_reported_counts'][result] = int(count)
            if stream == 'stdout' and re.fullmatch(r'[.sFxX\r\n ]+', text):
                out['quiet_progress_marks'] = {k: text.count(k) for k in '.sFxX'}
    out['not_run_stages'] = [name for name in STAGES if name not in {s['stage'] for s in records}]
    out['arbitrary_traceback_values'] = 'UNVERIFIED when redacted; never uploaded'
    provenance_path = root/'stages/provenance.json'
    if provenance_path.exists():
        provenance = json.loads(provenance_path.read_text())
        out['provenance'] = {k: digest(provenance.get(k)) for k in (
            'wheel_sha256', 'wheel_package_manifest_sha256', 'source_package_manifest_sha256',
            'release_lock_sha256', 'toolkit_lock_sha256', 'harness_sha256')}
        out['provenance']['package_file_count'] = integer(provenance.get('package_file_count'))
        version = provenance.get('outer_python_version', '')
        assert re.fullmatch(r'3\.[0-9]+\.[0-9]+', version)
        out['provenance']['outer_python_version'] = version
        out['provenance']['wheel_matches_source'] = provenance.get('wheel_matches_source') is True
    out['failed_test_functions'] = sorted(set(out['failed_test_functions']))
    out['exception_types_reported'] = sorted(set(out['exception_types_reported']))
    harness_path = root/'stages/harness-result.json'
    if harness_path.exists():
        harness = json.loads(harness_path.read_text())
        out['harness_exit_code'] = integer(harness.get('exit_code'))
        out['wheel_sha256'] = digest(harness.get('wheel_sha256'))
        out['harness_sha256'] = digest(harness.get('harness_sha256'))
    control_path = root/'supervisor.json'
    if control_path.exists():
        control = json.loads(control_path.read_text())
        allowed = {'COMPLETED','OUTER_INTERRUPTION','OUTER_TIMEOUT','CAPTURE_LIMIT','CLEANUP_INCOMPLETE'}
        assert control['wrapper_result'] in allowed
        out['wrapper_result'] = control['wrapper_result']
        out['observer_exit_code'] = integer(control.get('observer_exit_code'))
        out['remaining_descendant_count'] = len(control['remaining_descendants'])
        out['outer_timeout'] = control['wrapper_result'] == 'OUTER_TIMEOUT'
        out['capture_limit_exceeded'] = control['wrapper_result'] == 'CAPTURE_LIMIT'
        out['capture_completeness'] = 'INTERRUPTED' if control['wrapper_result'] != 'COMPLETED' else 'RECORDED'
    identity_path = root/'stages/identity.stdout'
    identity = None
    out['identity_state'] = 'NOT_RUN'
    if identity_path.exists():
        out['identity_state'] = 'UNVERIFIED'
        try:
            value = json.loads(identity_path.read_text())
            if isinstance(value, dict) and all(k in value for k in (
                'versions', 'python', 'package_files', 'package_origin', 'prefix', 'pytest_entrypoints_installed')):
                identity = value
        except (OSError, UnicodeError, ValueError):
            pass
    if identity is not None:
        out['identity_state'] = 'RECORDED'
        out['versions'] = {name: value for name, value in identity['versions'].items()
                           if name in VERSIONS and re.fullmatch(r'[0-9][A-Za-z0-9.+-]{0,63}', value)}
        version = identity['python'].split()[0]
        assert re.fullmatch(r'3\.[0-9]+\.[0-9]+', version)
        out['inner_python_version'] = version
        files = identity['package_files']
        out['package_manifest_sha256'] = hashlib.sha256(json.dumps(files,sort_keys=True,separators=(',',':')).encode()).hexdigest()
        out['package_file_count'] = len(files)
        out['import_under_inner_venv'] = Path(identity['package_origin']).is_relative_to(Path(identity['prefix']))
        out['installed_pytest_entrypoint_count'] = len(identity['pytest_entrypoints_installed'])
        out['installed_wheel_sha256'] = digest(identity.get('direct_url', {}).get('archive_info', {}).get('hashes', {}).get('sha256'))
        out['installed_matches_release_wheel'] = (
            out['package_manifest_sha256'] == out.get('provenance', {}).get('wheel_package_manifest_sha256')
            and out['installed_wheel_sha256'] == out.get('provenance', {}).get('wheel_sha256'))
        out['identity_observation'] = 'separate process after formal stop; not pytest sys.modules'
        out['loaded_pytest_plugins'] = 'UNVERIFIED'
    return out

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--toolkit', type=Path, required=True)
    parser.add_argument('--candidate', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    summary = make_summary(args.root, args.toolkit, args.candidate, args.output.parent)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(summary, indent=2)+'\n')
