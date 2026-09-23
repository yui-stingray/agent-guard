"""Focused tests for CI observation; no Toolkit tests or dependencies are run."""
import errno
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
import zipfile
from unittest.mock import patch

import export_toolkit_diagnostic as exporter
import observe_toolkit as capture
import supervise_toolkit as supervisor


class CompatibilityError(RuntimeError):
    pass


class ObservationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.stages = self.root / 'stages'
        self.stages.mkdir()
        self.observer = capture.Observer(SimpleNamespace(CompatibilityError=CompatibilityError), self.stages)

    def child(self, code):
        return [sys.executable, '-c', code]

    def test_success_preserves_stream_bytes(self):
        self.observer('success', self.child("import sys;sys.stdout.buffer.write(b'out\\n');sys.stderr.buffer.write(b'err\\n')"),
                      cwd=self.root, env=os.environ.copy())
        row = self.observer.records[0]
        self.assertEqual(row['returncode'], 0)
        self.assertEqual(Path(row['stdout']).read_bytes(), b'out\n')
        self.assertEqual(Path(row['stderr']).read_bytes(), b'err\n')
        self.assertEqual(Path(row['stdout']).stat().st_mode & 0o777, 0o600)

    def test_source_wheel_mismatch_stops_before_loading_harness(self):
        source = self.root / 'src/agent_guard/__init__.py'
        source.parent.mkdir(parents=True)
        source.write_bytes(b'# current source\n')
        wheel = self.root / 'candidate.whl'
        with zipfile.ZipFile(wheel, 'w') as archive:
            archive.writestr('agent_guard/__init__.py', b'# different wheel\n')
        argv = ['observe_toolkit.py', '--harness', str(self.root / 'unused.py'),
                '--wheel', str(wheel), '--out', str(self.root / 'mismatch')]
        with patch.object(sys, 'argv', argv), patch.object(capture.Path, 'cwd', return_value=self.root), \
             patch.object(capture, 'load_harness') as load:
            with self.assertRaisesRegex(RuntimeError, 'release wheel package does not match'):
                capture.main()
        load.assert_not_called()

    def test_nonzero_propagates_original_stage_failure(self):
        with self.assertRaises(CompatibilityError):
            self.observer('nonzero', self.child('raise SystemExit(7)'), cwd=self.root, env=os.environ.copy())
        self.assertEqual(self.observer.records[0]['returncode'], 7)
        self.assertEqual(self.observer.records[0]['state'], 'FAIL')

    def test_startup_exception_is_not_a_child_exit(self):
        with self.assertRaises(CompatibilityError):
            self.observer('startup', [str(self.root/'absent')], cwd=self.root, env=os.environ.copy())
        row = self.observer.records[0]
        self.assertIsNone(row['returncode'])
        self.assertEqual(row['exception'], {'type': 'FileNotFoundError', 'errno': errno.ENOENT})

    def test_initial_save_failure_stops_before_child(self):
        with patch.object(capture, 'save', side_effect=OSError(errno.ENOSPC, 'fixture')), patch.object(capture.subprocess, 'run') as run:
            with self.assertRaises(OSError):
                self.observer('save', self.child('pass'), cwd=self.root, env={})
        run.assert_not_called()

    def test_stream_save_failure_cannot_turn_child_success_green(self):
        fsync = os.fsync
        calls = 0
        def fail_stream(fd):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise OSError(errno.ENOSPC, 'fixture')
            return fsync(fd)
        with patch.object(capture.os, 'fsync', side_effect=fail_stream):
            with self.assertRaises(OSError):
                self.observer('save', self.child('pass'), cwd=self.root, env=os.environ.copy())
        row = json.loads((self.stages/'stages.json').read_text())[0]
        self.assertEqual(row['returncode'], 0)
        self.assertEqual(row['state'], 'OBSERVATION_ERROR')
        self.assertEqual(row['exception']['errno'], errno.ENOSPC)

    def test_capture_file_collision_fails_closed(self):
        (self.stages/'01-save.stdout').write_bytes(b'existing')
        with self.assertRaises(FileExistsError):
            self.observer('save', self.child('pass'), cwd=self.root, env={})
        self.assertEqual((self.stages/'01-save.stdout').read_bytes(), b'existing')

    def test_safe_output_and_sensitive_details_are_distinguished(self):
        tests = self.root/'tests'
        tests.mkdir()
        (tests/'test_public.py').write_text('def test_known():\n    assert False\n')
        data = (b'FAILED tests/test_public.py::test_known[PRIVATE_VALUE] - AssertionError: PRIVATE_VALUE\n'
                b'E AssertionError: PRIVATE_VALUE\n'
                b'tests/test_public.py:2: AssertionError\n'
                b'PRIVATE_PATH_AND_URL\n'
                b'FAILED tests/test_public.py::test_UNRECOGNIZED\n'
                b'1 failed, 2 passed in 1.20s\n')
        text, info = exporter.safe_excerpt(data, self.root)
        self.assertIn('FAILED tests/test_public.py::test_known\n', text)
        self.assertIn('tests/test_public.py:2: AssertionError', text)
        self.assertIn('1 failed, 2 passed', text)
        self.assertNotIn('PRIVATE', text)
        self.assertNotIn('UNRECOGNIZED', text)
        self.assertTrue(info['redacted'])
        self.assertEqual(info['detail_state'], 'PARTIAL_UNVERIFIED')

    def test_empty_and_progress_streams_are_exact(self):
        for data in (b'', b'....s.\n'):
            with self.subTest(data=data):
                text, info = exporter.safe_excerpt(data, self.root)
                self.assertEqual(text.encode(), data)
                self.assertFalse(info['redacted'])
                self.assertFalse(info['truncated'])

    def test_output_limit_is_explicit(self):
        text, info = exporter.safe_excerpt(b'.'*131073, self.root)
        self.assertEqual(len(text), 131072)
        self.assertTrue(info['truncated'])

    def test_missing_run_is_not_success(self):
        summary = exporter.make_summary(self.root, self.root, 'a'*40)
        self.assertEqual(summary['observation_state'], 'NOT_RUN')
        self.assertEqual(summary['not_run_stages'], list(exporter.STAGES))
        self.assertNotIn('harness_exit_code', summary)

    def test_stream_digest_mismatch_blocks_export(self):
        stdout = self.stages/'11.stdout'
        stderr = self.stages/'11.stderr'
        stdout.write_bytes(b'.\n')
        stderr.write_bytes(b'')
        row = {'stage': 'full toolkit pytest', 'state': 'PASS', 'index': 11,
               'argv': ['/fixture/venv/bin/python', '-m', 'pytest', '-q'],
               'stdout': str(stdout), 'stderr': str(stderr),
               'stdout_bytes': 2, 'stdout_sha256': '0'*64,
               'stderr_bytes': 0, 'stderr_sha256': hashlib.sha256(b'').hexdigest()}
        (self.stages/'stages.json').write_text(json.dumps([row]))
        with self.assertRaisesRegex(ValueError, 'digest changed'):
            exporter.make_summary(self.root, self.root, 'a'*40)

    def test_unrecognized_argv_cannot_leak(self):
        with self.assertRaises(ValueError):
            exporter.public_command({'stage': 'full toolkit pytest', 'argv': ['PRIVATE_VALUE']})


    def test_failed_identity_probe_keeps_stage_metadata(self):
        (self.stages/'identity.stdout').write_bytes(b'')
        summary = exporter.make_summary(self.root, self.root, 'a'*40)
        self.assertEqual(summary['identity_state'], 'UNVERIFIED')
        self.assertEqual(summary['observation_state'], 'NOT_RUN')
        (self.stages/'identity.stdout').write_bytes(b'{incomplete')
        self.assertEqual(exporter.make_summary(self.root, self.root, 'a'*40)['identity_state'], 'UNVERIFIED')

    def test_interrupted_pytest_retains_partial_output(self):
        stdout = self.stages/'11.stdout'
        stderr = self.stages/'11.stderr'
        stdout.write_bytes(b'..')
        stderr.write_bytes(b'')
        row = {'stage': 'full toolkit pytest', 'state': 'RUNNING', 'index': 11,
               'argv': ['/fixture/venv/bin/python', '-m', 'pytest', '-q'],
               'stdout': str(stdout), 'stderr': str(stderr)}
        (self.stages/'stages.json').write_text(json.dumps([row]))
        summary = exporter.make_summary(self.root, self.root, 'a'*40, self.root/'public')
        self.assertIsNone(summary['stages'][0]['returncode'])
        self.assertEqual(summary['stages'][0]['stdout_public_excerpt']['detail_state'], 'PARTIAL_UNVERIFIED')
        self.assertFalse(summary['stages'][0]['stdout_capture_finalized'])
        self.assertEqual((self.root/'public/pytest.stdout.txt').read_bytes(), b'..')

    def test_size_watch_tolerates_atomic_metadata_rename_only(self):
        gone = SimpleNamespace(stat=lambda: (_ for _ in ()).throw(FileNotFoundError()))
        file = SimpleNamespace(stat=lambda: SimpleNamespace(st_mode=0o100600, st_size=42))
        root = SimpleNamespace(rglob=lambda _: [gone, file])
        self.assertEqual(supervisor.capture_sizes(root), [42])
        bad = SimpleNamespace(stat=lambda: (_ for _ in ()).throw(PermissionError()))
        with self.assertRaises(PermissionError):
            supervisor.capture_sizes(SimpleNamespace(rglob=lambda _: [bad]))

    def test_export_save_failure_propagates(self):
        stdout = self.stages/'11.stdout'
        stderr = self.stages/'11.stderr'
        stdout.write_bytes(b'.')
        stderr.write_bytes(b'')
        row = {'stage': 'full toolkit pytest', 'state': 'PASS', 'index': 11,
               'argv': ['/fixture/venv/bin/python', '-m', 'pytest', '-q'],
               'stdout': str(stdout), 'stderr': str(stderr)}
        (self.stages/'stages.json').write_text(json.dumps([row]))
        public = self.root/'public'
        public.write_bytes(b'existing')
        with self.assertRaises(FileExistsError):
            exporter.make_summary(self.root, self.root, 'a'*40, public)



    def test_supervisor_preserves_formal_child_umask(self):
        root = self.root/'supervisor'
        root.mkdir()
        original = os.umask(0o022)
        os.umask(original)
        proc = subprocess.run(['/usr/bin/python3', '-B', supervisor.__file__, '--root', str(root),
                               '--seconds', '10', '--', sys.executable, '-c',
                               'import os;print(oct(os.umask(0)))'],
                              capture_output=True, text=True, check=False)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual((root/'supervisor.stdout').read_text().strip(), oct(original))
        self.assertEqual((root/'supervisor.stdout').stat().st_mode & 0o777, 0o600)
        self.assertEqual(json.loads((root/'supervisor.json').read_text())['remaining_descendants'], {})

    def test_supervisor_final_capture_overflow_is_failure(self):
        root = self.root/'overflow'
        root.mkdir()
        proc = subprocess.run(['/usr/bin/python3', '-B', supervisor.__file__, '--root', str(root),
                               '--seconds', '10', '--per-file', '10', '--',
                               sys.executable, '-c', 'print("x"*20)'],
                              capture_output=True, text=True, check=False)
        self.assertEqual(proc.returncode, 124, proc.stderr)
        self.assertEqual(json.loads((root/'supervisor.json').read_text())['wrapper_result'], 'CAPTURE_LIMIT')


if __name__ == '__main__':
    unittest.main()
