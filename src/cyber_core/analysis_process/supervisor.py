"""Supervise one fixed trusted Python child, bounded IPC, and lifecycle cleanup."""
import json
import math
import os
from pathlib import Path
import subprocess
import sys
import threading
import time

from cyber_core.errors import CoreError
from cyber_core.analysis_process.limits import MAX_TIMEOUT_SECONDS
from cyber_core.analysis_process.tree import attach as _attach_tree


def _command():
    return [sys.executable, '-I', '-X', 'utf8', '-u', str(Path(__file__).with_name('child.py'))]


def run_monitored(request, *, cwd, timeout, should_stop=None, on_started=None, max_output=2097152):
    if type(timeout) not in (int, float) or not 0 < timeout <= MAX_TIMEOUT_SECONDS or not math.isfinite(timeout):
        raise CoreError('Invalid analysis process timeout')
    if type(max_output) is not int or not 1024 <= max_output <= 16777216:
        raise CoreError('Invalid analysis process output limit')
    try:
        payload = (json.dumps(request, ensure_ascii=True, allow_nan=False) + '\n').encode('utf-8')
    except (TypeError, ValueError) as exc:
        raise CoreError('Invalid analysis process request') from exc
    if len(payload) > 65536:
        raise CoreError('Analysis process request limit exceeded')
    started = time.monotonic()
    process, tree, readers, writer = None, None, [], None
    buffers = {'stdout': bytearray(), 'stderr': bytearray()}
    total = [0]
    overflow = threading.Event()
    lock = threading.Lock()
    env = {key: value for key, value in os.environ.items()
           if key.upper() in ('SYSTEMROOT', 'WINDIR', 'TEMP', 'TMP', 'LANG', 'LC_ALL')}
    try:
        flags = {'creationflags': subprocess.CREATE_NO_WINDOW} if os.name == 'nt' else {'start_new_session': True}
        try:
            process = subprocess.Popen(_command(), cwd=cwd, env=env, shell=False, close_fds=True,
                                       stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, **flags)
            # Trusted child waits for stdin; release input only after attaching lifecycle containment.
            tree = _attach_tree(process)
        except OSError as exc:
            raise CoreError('Analysis process supervision could not start') from exc

        def read(stream, name):
            try:
                while block := stream.read(4096):
                    with lock:
                        room = max_output - total[0]
                        buffers[name].extend(block[:max(0, room)])
                        total[0] += min(len(block), max(0, room))
                        if len(block) > room:
                            overflow.set()
                            return
            except (OSError, ValueError):
                pass

        def feed():
            try:
                process.stdin.write(payload)
                process.stdin.close()
            except (BrokenPipeError, OSError, ValueError):
                pass

        readers = [threading.Thread(target=read, args=(process.stdout, 'stdout'), daemon=True),
                   threading.Thread(target=read, args=(process.stderr, 'stderr'), daemon=True)]
        for reader in readers:
            reader.start()
        if on_started:
            on_started(process.pid)
        writer = threading.Thread(target=feed, daemon=True)
        writer.start()
        while process.poll() is None:
            if overflow.is_set():
                raise CoreError('Analysis process output limit exceeded')
            if time.monotonic() - started >= timeout:
                raise CoreError('Analysis process timeout exceeded')
            if should_stop:
                reason = should_stop()
                if reason:
                    raise CoreError('Analysis process stopped: ' + str(reason)[:200])
            time.sleep(.02)
        # Even a successfully exited leader can leave descendants holding its pipes open.
        tree.close()
        tree = None
        for reader in readers:
            reader.join(timeout=2)
        if any(reader.is_alive() for reader in readers):
            raise CoreError('Analysis process streams did not close')
        if overflow.is_set():
            raise CoreError('Analysis process output limit exceeded')
        if time.monotonic() - started >= timeout:
            raise CoreError('Analysis process timeout exceeded')
        if should_stop:
            reason = should_stop()
            if reason:
                raise CoreError('Analysis process stopped: ' + str(reason)[:200])
        if process.returncode:
            raise CoreError('Analysis child execution failed (exit ' + str(process.returncode) + ')')
        try:
            message = json.loads(bytes(buffers['stdout']).decode('utf-8'))
        except (UnicodeDecodeError, ValueError) as exc:
            raise CoreError('Invalid analysis child response') from exc
        if not isinstance(message, dict) or type(message.get('ok')) is not bool:
            raise CoreError('Invalid analysis child response')
        if message['ok'] is False:
            error = message.get('error')
            raise CoreError(error[:1024] if isinstance(error, str) else 'Analysis child rejected the request')
        if not isinstance(message.get('result'), dict):
            raise CoreError('Invalid analysis child result')
        return message['result']
    finally:
        if tree:
            tree.close()
        if process:
            # tree.close() may already have reaped the group leader; tolerate it.
            try:
                if process.poll() is None:
                    process.kill()
                process.wait(timeout=5)
            except (ChildProcessError, OSError, subprocess.TimeoutExpired):
                pass
            if writer:
                writer.join(timeout=1)
            for reader in readers:
                reader.join(timeout=1)
            for stream in (process.stdin, process.stdout, process.stderr):
                if stream and not stream.closed:
                    stream.close()
