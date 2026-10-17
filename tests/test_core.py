import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest

from cyber_core.service import Core, CoreError


class CoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.scope = self.root / 'inputs'
        self.scope.mkdir()
        self.source = self.scope / 'sample.bin'
        self.source.write_bytes(b'\x7fELF' + bytes(range(256)) * 32)
        self.core = Core(self.root / 'state')
        self.addCleanup(self.core.close)
        self.case = self.core.investigate('synthetic', 'Identify synthetic binary', str(self.scope), 'owner', 'Synthetic laboratory authorization')

    def test_analysis_persists_and_original_is_unchanged(self):
        before = self.source.read_bytes()
        task = self.core.enqueue(self.case, self.source)
        result = self.core.run_one(self.case)
        self.assertEqual(result['format'], 'ELF signature')
        self.assertEqual(result['sha256'], hashlib.sha256(before).hexdigest())
        self.assertGreater(result['entropy'], 7.99)
        self.assertEqual(self.source.read_bytes(), before)
        self.assertEqual(self.core.tasks(self.case)[0]['status'], 'done')
        self.assertEqual(self.core.tasks(self.case)[0]['id'], task)
        self.assertTrue(self.core.analysis_notes(self.case))
        self.assertTrue(self.core.checkpoints(self.case))
        self.assertIn(result['sha256'], self.core.report(self.case).read_text(encoding='utf-8'))
        self.assertEqual(self.core.get(self.case)['state'], 'EM INVESTIGACAO')

    def test_pause_and_reopen_resume_without_duplicate(self):
        self.core.enqueue(self.case, self.source)
        self.core.pause(self.case)
        with self.assertRaises(CoreError):
            self.core.run_one(self.case)
        other = Core(self.root / 'state')
        self.addCleanup(other.close)
        other.resume(self.case)
        self.assertIsNotNone(other.run_one(self.case))
        self.assertIsNone(other.run_one(self.case))
        self.assertEqual(len(other.results(self.case)), 1)

    def test_requires_authorization_and_scope(self):
        for scope, owner, reason in [('', 'owner', 'ok'), (str(self.scope), '', 'ok'), (str(self.scope), 'owner', '')]:
            with self.assertRaises(CoreError):
                self.core.investigate('x', 'x', scope, owner, reason)
        outside = self.root / 'outside.bin'
        outside.write_bytes(b'private')
        with self.assertRaises(CoreError):
            self.core.enqueue(self.case, outside)

    def test_revocation_rechecked_at_execution(self):
        self.core.enqueue(self.case, self.source)
        self.core.revoke(self.case)
        with self.assertRaises(CoreError):
            self.core.run_one(self.case)
        self.assertFalse(self.core.results(self.case))

    def test_unknown_tool_rejected(self):
        with self.assertRaises(CoreError):
            self.core.enqueue(self.case, self.source, tool='shell')

    def test_limits_fail_with_audit(self):
        small = Core(self.root / 'small', max_bytes=10)
        self.addCleanup(small.close)
        case = small.investigate('x', 'x', str(self.scope), 'owner', 'ok')
        small.enqueue(case, self.source)
        with self.assertRaises(CoreError):
            small.run_one(case)
        self.assertEqual(small.tasks(case)[0]['status'], 'failed')
        self.assertTrue(any(a['event'] == 'task_failed' for a in small.audit(case)))

    def test_unsafe_paths_rejected(self):
        for path in ['\\\\server\\share', '\\\\?\\C:\\data', str(self.scope / '..' / 'inputs'), str(self.scope / 'x:stream')]:
            with self.subTest(path=path), self.assertRaises(CoreError):
                self.core.investigate('x', 'x', path, 'owner', 'ok')

    def test_audit_chain_detects_edits(self):
        self.assertTrue(self.core.verify_audit(self.case))
        self.core.db.execute("UPDATE audit SET event='tampered' WHERE case_id=?", (self.case,))
        self.core.db.commit()
        self.assertFalse(self.core.verify_audit(self.case))

    def test_expired_running_task_recovers(self):
        self.core.enqueue(self.case, self.source)
        self.core.db.execute("UPDATE tasks SET status='running',lease_until=0,attempts=1 WHERE case_id=?", (self.case,))
        self.core.db.commit()
        self.assertIsNotNone(self.core.run_one(self.case))
        self.assertEqual(self.core.tasks(self.case)[0]['attempts'], 2)

    def test_attempt_budget_stops_recovery(self):
        self.core.enqueue(self.case, self.source)
        self.core.db.execute("UPDATE tasks SET status='running',lease_until=0,attempts=3 WHERE case_id=?", (self.case,))
        self.core.db.commit()
        self.assertIsNone(self.core.run_one(self.case))
        self.assertEqual(self.core.tasks(self.case)[0]['status'], 'failed')

    def test_expiration_rejects_execution(self):
        self.core.enqueue(self.case, self.source)
        self.core.db.execute('UPDATE investigations SET expires=0 WHERE id=?', (self.case,))
        self.core.db.commit()
        with self.assertRaises(CoreError):
            self.core.run_one(self.case)

    def test_empty_binary_entropy_is_zero(self):
        self.source.write_bytes(b'')
        self.core.enqueue(self.case, self.source)
        result = self.core.run_one(self.case)
        self.assertEqual(result['entropy'], 0)
        self.assertEqual(result['sha256'], 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')

    def test_cloud_summary_requires_separate_approval(self):
        from cyber_core.orchestrator import review_summary
        with self.assertRaises(CoreError):
            review_summary(self.core, self.case)
        self.assertEqual(self.core.get(self.case)['agent_calls'], 0)

    def test_version_one_database_upgrades_without_losing_evidence(self):
        self.core.enqueue(self.case, self.source)
        result = self.core.run_one(self.case)
        self.core.db.execute('DROP TABLE IF EXISTS task_limits')
        self.core.db.execute('PRAGMA user_version=1')
        self.core.db.commit()
        upgraded = Core(self.root / 'state')
        self.addCleanup(upgraded.close)
        self.assertEqual(upgraded.db.execute('PRAGMA user_version').fetchone()[0], 4)
        self.assertEqual(upgraded.results(self.case)[0]['sha256'], result['sha256'])
        self.assertTrue(upgraded.verify_audit(self.case))


if __name__ == '__main__':
    unittest.main()
