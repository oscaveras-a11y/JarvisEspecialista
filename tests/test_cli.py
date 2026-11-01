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

    def test_materialize_wordlist_writes_a_real_candidate_file_into_scope(self):
        self.cli('init')
        case = self.cli('investigate', '--project', 'demo', '--objective', 'synthetic', '--scope', str(self.inputs), '--owner', 'owner', '--authorization', 'Synthetic lab')['id']
        destination = self.inputs / 'rockyou.txt'
        result = self.cli('materialize-wordlist', case, str(destination), '--limit', '5')
        self.assertEqual(result['source'], 'rockyou')
        self.assertEqual(result['lines'], 5)
        # Compare by identity, not literal string: on Windows the authorized
        # path can come back through its 8.3 short-name alias (RUNNER~1 vs
        # runneradmin), which is still the same file.
        self.assertTrue(Path(result['path']).samefile(destination))
        self.assertEqual(destination.read_text().splitlines(), ['123456', '12345', '123456789', 'password', 'iloveyou'])
        self.cli('materialize-wordlist', case, str(destination), '--limit', '5', success=False)

    def test_generate_wordlist_expands_hint_words_into_a_candidate_file(self):
        self.cli('init')
        case = self.cli('investigate', '--project', 'demo', '--objective', 'synthetic', '--scope', str(self.inputs), '--owner', 'owner', '--authorization', 'Synthetic lab')['id']
        destination = self.inputs / 'hints.txt'
        result = self.cli('generate-wordlist', case, str(destination), '--word', 'Rex', '--word', 'Max', '--limit', '40')
        self.assertEqual(result['source'], 'generated')
        self.assertEqual(result['lines'], 40)
        lines = destination.read_text().splitlines()
        self.assertEqual(len(lines), 40)
        self.assertIn('Rex', lines)

    def test_bruteforce_wordlist_exhaustively_enumerates_a_small_charset(self):
        self.cli('init')
        case = self.cli('investigate', '--project', 'demo', '--objective', 'synthetic', '--scope', str(self.inputs), '--owner', 'owner', '--authorization', 'Synthetic lab')['id']
        destination = self.inputs / 'brute.txt'
        result = self.cli('bruteforce-wordlist', case, str(destination),
                          '--charset', 'ab', '--min-length', '1', '--max-length', '2', '--limit', '100')
        self.assertEqual(result['source'], 'bruteforce')
        self.assertEqual(result['lines'], 6)
        lines = destination.read_text().splitlines()
        self.assertEqual(set(lines), {'a', 'b', 'aa', 'ab', 'ba', 'bb'})

    def test_logs_exposes_raw_audit_trail(self):
        self.cli('init')
        case = self.cli('investigate', '--project', 'demo', '--objective', 'synthetic', '--scope', str(self.inputs), '--owner', 'owner', '--authorization', 'Synthetic lab')['id']
        source = self.inputs / 'sample.bin'
        source.write_bytes(b'\x7fELF' + bytes(range(256)) * 16)
        self.cli('analyze-file', case, str(source))
        logs = self.cli('logs', case)
        self.assertTrue(logs['chain_valid'])
        events = [entry['event'] for entry in logs['audit']]
        self.assertIn('authorization_registered', events)
        self.assertIn('analysis_verified', events)

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

    def test_recovery_assessment_needs_no_key_argument(self):
        case = self.cli('investigate', '--project', 'x', '--objective', 'no supplied key', '--scope', str(self.inputs), '--owner', 'owner', '--authorization', 'Authorized assessment', '--allow-recovery')['id']
        (self.inputs / 'sample').write_bytes(b'Salted__' + bytes(24))
        result = self.cli('assess-recovery', case, str(self.inputs))
        self.assertEqual(result['results'][0]['recovery_assessment']['format_id'], 'openssl-salted')
        self.assertFalse(result['results'][0]['recovery_assessment']['recovery_demonstrated'])
