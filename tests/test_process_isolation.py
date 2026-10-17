"""Process lifecycle beta: real subprocesses and synthetic files only."""
import ctypes
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from cyber_core.errors import CoreError
from cyber_core.service import Core


def alive(pid):
    if os.name == 'nt':
        from ctypes import wintypes
        api = ctypes.WinDLL('kernel32', use_last_error=True)
        api.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        api.OpenProcess.restype = wintypes.HANDLE
        api.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
        api.CloseHandle.argtypes = [wintypes.HANDLE]
        handle = api.OpenProcess(0x1000, False, pid)
        if not handle:
            return False
        try:
            code = wintypes.DWORD()
            return bool(api.GetExitCodeProcess(handle, ctypes.byref(code))) and code.value == 259
        finally:
            api.CloseHandle(handle)
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False


class ProcessIsolationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.marker = self.root / 'pid.txt'
        self.inputs = self.root / 'inputs'
        self.inputs.mkdir()
        self.source = self.inputs / 'sample.bin'
        self.source.write_bytes(b'abc')
        self.home = self.root / 'state'
        self.core = Core(self.home)
        self.addCleanup(self.core.close)
        self.case = self.core.investigate('process-beta', 'Synthetic process tests',
                                          str(self.inputs), 'operator', 'Synthetic lab')

    def supervisor(self):
        self.assertIsNotNone(importlib.util.find_spec('cyber_core.analysis_process'),
                             'Monitored analysis processes are missing')
        from cyber_core.analysis_process import supervisor
        return supervisor

    def fixture(self, body):
        prefix = ("import json,os,sys,time,subprocess\n"
                  "request=json.loads(sys.stdin.readline())\n"
                  "from pathlib import Path\n"
                  "Path(request['marker']).write_text(str(os.getpid()))\n")
        return [sys.executable, '-I', '-u', '-c', prefix + body]

    def run_fixture(self, body, **options):
        supervisor = self.supervisor()
        with patch.object(supervisor, '_command', return_value=self.fixture(body)):
            return supervisor.run_monitored({'marker': str(self.marker)}, cwd=self.root, **options)

    def assert_dead(self, pid):
        deadline = time.monotonic() + 5
        while alive(pid) and time.monotonic() < deadline:
            time.sleep(.02)
        self.assertFalse(alive(pid), 'Monitored child remained alive')

    def test_core_runs_analysis_in_a_different_process(self):
        task = self.core.enqueue(self.case, self.source)
        result = self.core.run_one(self.case)
        started = [json.loads(e['data']) for e in self.core.audit(self.case)
                   if e['event'] == 'analysis_process_started']
        self.assertEqual(len(started), 1, 'Analysis did not start a monitored child')
        self.assertNotEqual(started[0]['pid'], os.getpid())
        self.assertEqual(started[0]['task'], task)
        self.assert_dead(started[0]['pid'])
        self.assertEqual(result['sha256'], hashlib.sha256(b'abc').hexdigest())
        self.assertEqual(Path(result['copy']).read_bytes(), b'abc')
        self.assertEqual(self.source.read_bytes(), b'abc')
        self.assertTrue(self.core.verify_audit(self.case))

    def test_timeout_terminates_hung_process(self):
        started = time.monotonic()
        with self.assertRaisesRegex(CoreError, 'timeout'):
            self.run_fixture('while True: time.sleep(1)\n', timeout=2)
        self.assertLess(time.monotonic() - started, 7)
        self.assertTrue(self.marker.exists())
        self.assert_dead(int(self.marker.read_text()))

    def test_cancellation_terminates_child_without_waiting_for_task_timeout(self):
        def stop():
            return 'cancelled' if self.marker.exists() else None
        with self.assertRaisesRegex(CoreError, 'cancelled'):
            self.run_fixture('while True: time.sleep(1)\n', timeout=15, should_stop=stop)
        self.assert_dead(int(self.marker.read_text()))

    def test_output_limit_stops_flooding_child(self):
        body = "sys.stdout.write('x'*1000000);sys.stdout.flush()\nwhile True: time.sleep(1)\n"
        with self.assertRaisesRegex(CoreError, 'output'):
            self.run_fixture(body, timeout=10, max_output=4096)
        self.assert_dead(int(self.marker.read_text()))

    def test_crash_does_not_echo_child_stderr_or_accept_result(self):
        with self.assertRaises(CoreError) as caught:
            self.run_fixture("sys.stderr.write('sensitive-test-marker');sys.stderr.flush();os._exit(7)\n", timeout=10)
        self.assertNotIn('sensitive-test-marker', str(caught.exception))
        self.assert_dead(int(self.marker.read_text()))

    def test_descendants_are_stopped_even_when_leader_exits_normally(self):
        descendant = self.root / 'descendant.txt'
        body = ("child=subprocess.Popen([sys.executable,'-c','import time;time.sleep(60)'])\n"
                "Path(request['marker']+'.descendant').write_text(str(child.pid))\n"
                "print(json.dumps({'ok':True,'result':{'value':1}}),flush=True)\n")
        result = self.run_fixture(body, timeout=10)
        self.assertEqual(result['value'], 1)
        self.assert_dead(int(Path(str(self.marker)+'.descendant').read_text()))
        self.assert_dead(int(self.marker.read_text()))

    def test_keyboard_interrupt_in_monitor_cleans_child(self):
        def interrupt():
            if self.marker.exists():
                raise KeyboardInterrupt
        with self.assertRaises(KeyboardInterrupt):
            self.run_fixture('while True: time.sleep(1)\n', timeout=15, should_stop=interrupt)
        self.assert_dead(int(self.marker.read_text()))

    def test_invalid_response_is_rejected(self):
        with self.assertRaises(CoreError):
            self.run_fixture("print('not-json',flush=True)\n", timeout=10)

    def test_environment_does_not_inherit_unrelated_secrets(self):
        with patch.dict(os.environ, {'CYBER_TEST_SECRET': 'never-transfer'}):
            result = self.run_fixture("print(json.dumps({'ok':True,'result':{'secret':os.environ.get('CYBER_TEST_SECRET')}}))\n",
                                      timeout=10)
        self.assertIsNone(result['secret'])

    def test_monitor_setup_failure_does_not_release_input(self):
        supervisor = self.supervisor()
        pids = []
        with patch.object(supervisor, '_command', return_value=self.fixture('while True: time.sleep(1)\n')), \
             patch.object(supervisor, '_attach_tree', side_effect=OSError('Synthetic setup failure')):
            with self.assertRaises(CoreError):
                supervisor.run_monitored({'marker': str(self.marker)}, cwd=self.root, timeout=10,
                                          on_started=pids.append)
        self.assertFalse(self.marker.exists(), 'Work started without process supervision')

    def start_hung_core(self):
        self.supervisor()
        task = self.core.enqueue(self.case, self.source)
        helper = self.root / 'worker.py'
        command = self.fixture("Path(request['destination']).write_bytes(b'partial')\nwhile True: time.sleep(1)\n")
        command[-1] = command[-1].replace("request['marker']", repr(str(self.marker)))
        helper.write_text(
            "import sys\nfrom unittest.mock import patch\n"
            "from cyber_core.service import Core\nfrom cyber_core.errors import CoreError\n"
            "from cyber_core.analysis_process import supervisor\n"
            "core=Core(sys.argv[1],timeout=30)\n"
            "try:\n"
            " with patch.object(supervisor,'_command',return_value=" + repr(command) + "):\n"
            "  try: core.run_one(sys.argv[2])\n"
            "  except CoreError: pass\n"
            "finally: core.close()\n", encoding='utf-8')
        process = subprocess.Popen([sys.executable, str(helper), str(self.home), self.case],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.addCleanup(lambda: process.kill() if process.poll() is None else None)
        deadline = time.monotonic() + 15
        while not self.marker.exists() and process.poll() is None and time.monotonic() < deadline:
            time.sleep(.02)
        self.assertTrue(self.marker.exists(), 'Synthetic child did not reach its running marker')
        return task, process, int(self.marker.read_text())

    def test_cancelled_core_stops_live_child_and_removes_provisional_copy(self):
        task, worker, pid = self.start_hung_core()
        self.core.cancel(self.case, reason='Stop monitored synthetic analysis')
        stdout, stderr = worker.communicate(timeout=15)
        self.assertEqual(worker.returncode, 0, stderr)
        self.assert_dead(pid)
        self.assertEqual(self.core.tasks(self.case)[0]['status'], 'cancelled')
        self.assertFalse(self.core.results(self.case))
        self.assertFalse(list((self.home / 'cases' / self.case / 'evidence').glob('*.evidence')))
        self.assertEqual(self.source.read_bytes(), b'abc')
        self.assertTrue(self.core.verify_audit(self.case))

    def test_revocation_stops_live_child_without_publishing_result(self):
        task, worker, pid = self.start_hung_core()
        self.core.revoke(self.case)
        stdout, stderr = worker.communicate(timeout=15)
        self.assertEqual(worker.returncode, 0, stderr)
        self.assert_dead(pid)
        self.assertEqual(self.core.tasks(self.case)[0]['status'], 'failed')
        self.assertFalse(self.core.results(self.case))

    @unittest.skipUnless(os.name == 'nt', 'Windows Job Object parent-death guarantee')
    def test_parent_death_closes_job_and_expired_claim_can_resume(self):
        task, worker, pid = self.start_hung_core()
        worker.kill()
        worker.communicate(timeout=10)
        self.assert_dead(pid)
        self.assertFalse(self.core.results(self.case))
        self.core.db.execute('UPDATE tasks SET lease_until=0 WHERE id=?', (task,))
        self.core.db.commit()
        result = self.core.run_one(self.case)
        self.assertEqual(result['size'], 3)
        self.assertEqual(len(self.core.results(self.case)), 1)
        self.assertEqual(self.core.tasks(self.case)[0]['attempts'], 2)

    def test_redirected_descendant_has_exited_before_evidence_cleanup(self):
        supervisor = self.supervisor()
        destination = self.root / 'held-copy.bin'
        ready = self.root / 'held-copy.ready'
        child_code = (
            "import sys,time;from pathlib import Path;"
            "handle=open(sys.argv[1],'wb');handle.write(b'partial');handle.flush();"
            "Path(sys.argv[2]).write_text('ready');time.sleep(60)"
        )
        body = (
            "child=subprocess.Popen([sys.executable,'-c'," + repr(child_code) + "," +
            repr(str(destination)) + "," + repr(str(ready)) +
            "],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)\n"
            "Path(request['marker']+'.descendant').write_text(str(child.pid))\n"
            "deadline=time.monotonic()+10\n"
            "while not Path(" + repr(str(ready)) + ").exists():\n"
            " if time.monotonic()>deadline: raise RuntimeError('child not ready')\n"
            " time.sleep(.01)\n"
            "print(json.dumps({'ok':True,'result':{'value':1}}),flush=True)\n"
        )
        result = self.run_fixture(body, timeout=15)
        descendant = int(Path(str(self.marker)+'.descendant').read_text())
        self.assertFalse(alive(descendant), 'Descendant still running when supervisor returned')
        destination.unlink()
        self.assertEqual(result['value'], 1)

    @unittest.skipUnless(os.name == 'nt', 'Windows shutdown membership race')
    def test_child_spawned_during_shutdown_releases_all_file_handles(self):
        supervisor = self.supervisor()
        trigger, ready = self.root / 'spawn-now', self.root / 'new-child.ready'
        target, pid_file = self.root / 'late-copy.bin', self.root / 'late-child.pid'
        late = ("import sys,time;from pathlib import Path;"
                "handles=[open('NUL','wb') for _ in range(4096)];"
                "held=open(sys.argv[1],'wb');held.write(b'partial');held.flush();"
                "Path(sys.argv[2]).write_text('ready');time.sleep(60)")
        spawning = (
            "import sys,time,subprocess;from pathlib import Path\n"
            "trigger=Path(sys.argv[1])\n"
            "while not trigger.exists(): time.sleep(.01)\n"
            "child=subprocess.Popen([sys.executable,'-c'," + repr(late) + "," +
            repr(str(target)) + "," + repr(str(ready)) +
            "],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)\n"
            "Path(" + repr(str(pid_file)) + ").write_text(str(child.pid))\n"
            "time.sleep(60)\n")
        body = (
            "subprocess.Popen([sys.executable,'-c'," + repr(spawning) + "," +
            repr(str(trigger)) + "],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)\n"
            "print(json.dumps({'ok':True,'result':{'value':1}}),flush=True)\n")
        original_attach = supervisor._attach_tree
        def attach_with_shutdown_interleaving(process):
            tree = original_attach(process)
            terminate = tree.api.TerminateJobObject
            def spawn_before_termination(*args):
                trigger.write_text('spawn')
                deadline = time.monotonic() + 15
                while not ready.exists() and time.monotonic() < deadline:
                    time.sleep(.01)
                self.assertTrue(ready.exists(), 'Late descendant did not open its handles')
                return terminate(*args)
            tree.api.TerminateJobObject = spawn_before_termination
            return tree
        with patch.object(supervisor, '_attach_tree', side_effect=attach_with_shutdown_interleaving):
            self.assertEqual(self.run_fixture(body, timeout=25)['value'], 1)
        self.assertFalse(alive(int(pid_file.read_text())), 'New member survived shutdown return')
        target.unlink()
