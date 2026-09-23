"""Finite task-local supervisor; only this process's descendants are signalled."""
import argparse
import ctypes
import datetime
import hashlib
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import time

def descendants():
    rows = {}
    for path in Path('/proc').glob('[0-9]*/stat'):
        try:
            data = path.read_text().rsplit(')', 1)[1].split()
            rows[int(path.parent.name)] = (int(data[1]), int(data[19]), data[0])
        except (OSError, ValueError, IndexError):
            continue
    owners = {os.getpid()}
    while True:
        new = {pid for pid, (ppid, _, _) in rows.items() if ppid in owners}
        if new <= owners:
            break
        owners |= new
    return {pid: rows[pid] for pid in owners if pid != os.getpid() and pid in rows}

def signal_owned(signum):
    sent = []
    for pid, (_, start, state) in descendants().items():
        if state == 'Z':
            continue
        # pidfd ties the signal to the opened process identity, not a reusable PID.
        try:
            fd = os.pidfd_open(pid)
            current = descendants().get(pid)
            if current is not None and current[1] == start:
                signal.pidfd_send_signal(fd, signum)
                sent.append(pid)
            os.close(fd)
        except ProcessLookupError:
            continue
    return sent

def capture_sizes(root):
    sizes = []
    for path in root.rglob('*'):
        try:
            info = path.stat()
        except FileNotFoundError:
            # Observer atomically replaces metadata; a vanished .new file is normal.
            continue
        if stat.S_ISREG(info.st_mode):
            sizes.append(info.st_size)
    return sizes

def main():
    inherited_umask = os.umask(0o077)
    ap = argparse.ArgumentParser()
    ap.add_argument('--root', type=Path, required=True)
    ap.add_argument('--seconds', type=float, default=1200)
    ap.add_argument('--per-file', type=int, default=33554432)
    ap.add_argument('--total', type=int, default=134217728)
    ap.add_argument('command', nargs=argparse.REMAINDER)
    a = ap.parse_args()
    if a.command[0] == '--': a.command.pop(0)
    if not hasattr(os, 'pidfd_open') or not hasattr(signal, 'pidfd_send_signal'):
        raise RuntimeError('supervisor requires pidfd support; no child started')
    assert ctypes.CDLL(None, use_errno=True).prctl(36, 1, 0, 0, 0) == 0
    start = time.monotonic()
    reason = None
    result = None
    events = []
    interrupted = []
    def receive(sig, _frame): interrupted.append(sig)
    signal.signal(signal.SIGTERM, receive)
    signal.signal(signal.SIGINT, receive)
    out = a.root / 'supervisor.stdout'
    err = a.root / 'supervisor.stderr'
    with out.open('xb', buffering=0) as stdout, err.open('xb', buffering=0) as stderr:
        p = subprocess.Popen(a.command, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr, start_new_session=True, umask=inherited_umask)
        try:
            while p.poll() is None:
                sizes = capture_sizes(a.root)
                if interrupted: reason = 'OUTER_INTERRUPTION'
                elif time.monotonic() - start > a.seconds: reason = 'OUTER_TIMEOUT'
                elif max(sizes, default=0) > a.per_file or sum(sizes) > a.total: reason = 'CAPTURE_LIMIT'
                if reason:
                    events.append({'signal': 'TERM', 'pids': signal_owned(signal.SIGTERM)})
                    break
                time.sleep(0.1)
            if reason:
                deadline = time.monotonic() + 5
                while p.poll() is None and time.monotonic() < deadline: time.sleep(0.1)
            if p.poll() is None:
                events.append({'signal': 'KILL', 'pids': signal_owned(signal.SIGKILL)})
            result = p.wait(timeout=5)
        finally:
            remaining = descendants()
            if any(row[2] != 'Z' for row in remaining.values()):
                events.append({'signal': 'TERM_CLEANUP', 'pids': signal_owned(signal.SIGTERM)})
                deadline = time.monotonic() + 2
                while any(row[2] != 'Z' for row in descendants().values()) and time.monotonic() < deadline: time.sleep(0.1)
                events.append({'signal': 'KILL_CLEANUP', 'pids': signal_owned(signal.SIGKILL)})
            deadline = time.monotonic() + 3
            while descendants() and time.monotonic() < deadline:
                try:
                    while os.waitpid(-1, os.WNOHANG)[0]: pass
                except ChildProcessError: pass
                time.sleep(0.05)
    sizes = capture_sizes(a.root)
    if max(sizes, default=0) > a.per_file or sum(sizes) > a.total:
        reason = reason or 'CAPTURE_LIMIT'
    remaining = descendants()
    if remaining: reason = reason or 'CLEANUP_INCOMPLETE'
    record = {'command': a.command, 'cwd': str(Path.cwd()), 'time': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'observer_exit_code': result, 'wrapper_result': reason or 'COMPLETED',
              'seconds': round(time.monotonic()-start, 4), 'limits': {'outer_seconds': a.seconds, 'per_file_bytes': a.per_file, 'total_bytes': a.total, 'enforcement': '100ms watcher; bound crossings interrupt observation, never truncate into success'},
              'cleanup_events': events, 'remaining_descendants': remaining,
              'logs': {x.name: {'bytes': x.stat().st_size, 'sha256': hashlib.sha256(x.read_bytes()).hexdigest()} for x in [out, err]}}
    (a.root/'supervisor.json').write_text(json.dumps(record, indent=2)+'\n')
    print(json.dumps({k: record[k] for k in ['observer_exit_code', 'wrapper_result', 'seconds', 'remaining_descendants']}))
    return 124 if reason else result

if __name__ == '__main__': raise SystemExit(main())
