import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


class CLITests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.home = self.root / 'state'
        self.inputs = self.root / 'inputs'
        self.inputs.mkdir()

    def cli(self, *args, success=True):
        run = subprocess.run([sys.executable, '-m', 'cyber_core', '--home', str(self.home), *args], capture_output=True, text=True, timeout=30)
        if success:
            self.assertEqual(run.returncode, 0, run.stderr)
            return json.loads(run.stdout)
        self.assertNotEqual(run.returncode, 0)
        self.assertNotIn('Traceback', run.stderr)

    def test_new_process_pause_resume_report(self):
        self.cli('init')
        case = self.cli('investigate', '--project', 'demo', '--objective', 'synthetic', '--scope', str(self.inputs), '--owner', 'owner', '--authorization', 'Synthetic lab')['id']
        source = self.inputs / 'sample.bin'
        source.write_bytes(b'\x7fELF' + bytes(range(256)) * 16)
        self.cli('pause', case)
        self.cli('analyze-file', case, str(source), success=False)
        self.cli('resume', case)
        result = self.cli('analyze-file', case, str(source))
        self.assertTrue(result['copy_verified'])
        self.assertEqual(result['format'], 'ELF signature')
        report = self.cli('report', case)
        self.assertTrue(Path(report['path']).is_file())
        self.assertEqual(self.cli('status', case)['tasks'][0]['status'], 'done')

    def test_help_and_unsupported_module(self):
        self.cli('analyze-can', success=False)
        run = subprocess.run([sys.executable, '-m', 'cyber_core', '--help'], capture_output=True, text=True, timeout=30)
        self.assertEqual(run.returncode, 0)
        self.assertIn('analyze-file', run.stdout)

    def test_doctor(self):
        info = self.cli('doctor')
        self.assertIn('python', info)
        self.assertIn('codex', info['agents'])

    def test_immediate_analysis_returns_requested_file(self):
        case = self.cli('investigate', '--project', 'x', '--objective', 'x', '--scope', str(self.inputs), '--owner', 'owner', '--authorization', 'lab')['id']
        first, second = self.inputs / 'a.bin', self.inputs / 'b.bin'
        first.write_bytes(b'A' * 32)
        second.write_bytes(b'PK\x03\x04' + b'B' * 32)
        self.cli('analyze-file', case, str(first), '--queue-only')
        result = self.cli('analyze-file', case, str(second))
        self.assertEqual(result['format'], 'ZIP signature')
        statuses = self.cli('status', case)['tasks']
        self.assertEqual([t['status'] for t in statuses], ['pending', 'done'])

    def test_corrupted_database_has_clear_error(self):
        self.home.mkdir()
        (self.home / 'core.sqlite3').write_bytes(b'not a sqlite database')
        self.cli('status', success=False)
