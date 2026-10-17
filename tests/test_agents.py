from pathlib import Path
import sys
import subprocess
import tempfile
import unittest
from cyber_core.agents.runner import run_bounded, CodexAdapter, ClaudeAdapter
from cyber_core.errors import CoreError


class AgentTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def program(self, text):
        script = self.root / 'process.py'
        script.write_text(text)
        return [sys.executable, str(script)]

    def test_real_process_success(self):
        cmd = self.program('import sys\nprint(sys.stdin.read().upper())\n')
        result = run_bounded(cmd, 'synthetic', cwd=self.root, timeout=5)
        self.assertEqual(result['stdout'].strip(), 'SYNTHETIC')

    def test_process_timeout(self):
        cmd = self.program('import time\ntime.sleep(10)\n')
        with self.assertRaisesRegex(CoreError, 'timeout'):
            run_bounded(cmd, '', cwd=self.root, timeout=.2)

    def test_output_limit(self):
        cmd = self.program('print("x" * 100000)\n')
        with self.assertRaisesRegex(CoreError, 'output'):
            run_bounded(cmd, '', cwd=self.root, timeout=5, max_output=100)

    def test_unavailable(self):
        with self.assertRaises(CoreError):
            CodexAdapter(executable=str(self.root / 'missing.exe')).review({}, self.root)

    def test_claude_adapter_unavailable_executable_refuses_execution(self):
        # ClaudeAdapter evolved from a hardcoded stub (PR #14) into a real adapter
        # that locates its own executable, mirroring CodexAdapter. A bare
        # ClaudeAdapter() must not be used here: shutil.which('claude') can find
        # an unrelated 'claude' binary already on PATH in a Claude Code session
        # (this very CLI), so the executable is pinned explicitly, exactly like
        # test_unavailable does for CodexAdapter.
        with self.assertRaises(CoreError):
            ClaudeAdapter(executable=str(self.root / 'missing-claude.exe')).review({}, self.root)

    def test_timeout_covers_blocked_stdin(self):
        sleeper = self.root / 'sleeper.py'
        sleeper.write_text('import time\ntime.sleep(8)\n')
        probe = self.root / 'probe.py'
        probe.write_text('from cyber_core.agents.runner import run_bounded\nfrom cyber_core.errors import CoreError\n'
                         + 'try:\n run_bounded(' + repr([sys.executable, str(sleeper)]) + ', "x" * 16000, cwd=' + repr(str(self.root)) + ', timeout=.2)\n'
                         + 'except CoreError as exc:\n print(str(exc))\n')
        run = subprocess.run([sys.executable, str(probe)], capture_output=True, text=True, timeout=5)
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertIn('timeout', run.stdout)
