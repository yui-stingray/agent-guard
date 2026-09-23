"""Run the real bounded runner with deliberately failed containment in isolation."""
import errno
import gc
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import time
import weakref

from agent_guard import bounded_git


def main():
    mode, directory = sys.argv[1:]
    created = []
    jobs = []
    events = []
    threads_before = set(threading.enumerate())
    old_popen = bounded_git.subprocess.Popen
    old_terminate = bounded_git._terminate_process_tree
    old_hook = sys.unraisablehook
    old_thread_hook = threading.excepthook

    def capture(*args, **kwargs):
        process = old_popen(*args, **kwargs)
        created.append(process)
        return process

    def fail_containment(process, job):
        if job is not None:
            jobs.append(job)
        return False

    def unraisable(event):
        events.append([event.exc_type.__name__, getattr(event.exc_value, 'errno', None)])

    def thread_error(event):
        events.append([event.exc_type.__name__, getattr(event.exc_value, 'errno', None)])

    bounded_git.subprocess.Popen = capture
    bounded_git._terminate_process_tree = fail_containment
    sys.unraisablehook = unraisable
    threading.excepthook = thread_error
    sentinel = None
    result = {}
    try:
        started = time.monotonic()
        try:
            bounded_git._run_bounded_process(
                [sys.executable, '-c', 'import time; time.sleep(30)'],
                environment=os.environ, timeout_seconds=0.15,
                max_output_bytes=1024,
                input_data=b'x' * (1024 * 1024) if mode == 'write' else None,
            )
            result['expected_error'] = False
        except bounded_git.BoundedGitProcessError:
            result['expected_error'] = True
        result['elapsed'] = time.monotonic() - started
        process = created[0]
        stream = process.stdin if mode == 'write' else process.stdout
        # Closed streams no longer expose fileno: capture the fd before cleanup
        # through the real Popen hook below, without replacing its close method.
        target = descriptors[mode]
        result['wrapper_closed_on_return'] = stream.closed
        ref = weakref.ref(stream)
        try:
            os.fstat(target)
            result['fd_released_on_return'] = False
        except OSError as exc:
            assert exc.errno == errno.EBADF
            result['fd_released_on_return'] = True
        assert result['fd_released_on_return']
        sentinel = os.open(str(Path(directory) / ('sentinel-' + mode)),
                           os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
        result['natural_reuse'] = sentinel == target
        if sentinel != target:
            # The target is our now-released pipe descriptor in this disposable process.
            os.dup2(sentinel, target)
            os.close(sentinel)
            sentinel = target
        result['same_number_reused'] = sentinel == target
        os.write(sentinel, b'before')
        for job in jobs:
            bounded_git._terminate_windows_job(job)
        jobs.clear()
        process.kill()
        process.wait(timeout=2)
        workers = [t for t in threading.enumerate() if t not in threads_before
                   and t.name.startswith('agent-guard-git-')]
        for worker in workers:
            worker.join(timeout=1)
        result['workers_stopped'] = all(not t.is_alive() for t in workers)
        del stream, process
        created.clear()
        gc.collect()
        result['wrapper_finalized'] = ref() is None
        result['events'] = list(events)
        try:
            os.write(sentinel, b'after')
            os.lseek(sentinel, 0, os.SEEK_SET)
            result['sentinel_contents'] = os.read(sentinel, 100).decode('ascii')
            result['sentinel_alive'] = True
        except OSError as exc:
            result['sentinel_alive'] = False
            result['sentinel_errno'] = exc.errno
        print(json.dumps(result))
    finally:
        for job in jobs:
            bounded_git._terminate_windows_job(job)
        for process in created:
            process.kill()
            process.wait(timeout=2)
        if sentinel is not None:
            try:
                os.close(sentinel)
            except OSError as exc:
                if exc.errno != errno.EBADF:
                    raise
        bounded_git.subprocess.Popen = old_popen
        bounded_git._terminate_process_tree = old_terminate
        sys.unraisablehook = old_hook
        threading.excepthook = old_thread_hook


# Capture identities at creation, before any worker starts or fd is released.
descriptors = {}
_original_popen = bounded_git.subprocess.Popen

def record_descriptors(*args, **kwargs):
    process = _original_popen(*args, **kwargs)
    descriptors['read'] = process.stdout.fileno()
    if process.stdin is not None:
        descriptors['write'] = process.stdin.fileno()
    return process

bounded_git.subprocess.Popen = record_descriptors
try:
    main()
finally:
    bounded_git.subprocess.Popen = _original_popen
