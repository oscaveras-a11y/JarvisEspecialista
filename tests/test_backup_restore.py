"""Item 5 (Memória persistente): durable backup/restore, proven outside a single
job — the gap flagged by the PR #9 independent review ('comprovar backup/
restauração e recuperação durável fora de um único job')."""
import tempfile
import unittest
from pathlib import Path

from cyber_core.service import Core, CoreError


class BackupRestoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.scope = self.root / 'inputs'
        self.scope.mkdir()
        self.sample = self.scope / 'ev.bin'
        self.sample.write_bytes(b'conteudo de evidencia para backup')
        self.core = Core(self.root / 'state')
        self.addCleanup(self.core.close)
        self.case = self.core.investigate('p', 'Backup e restauração', str(self.scope), 'owner', 'auth')
        task = self.core.enqueue(self.case, self.sample, tool='analyze-file')
        self.result = self.core.run_one(self.case, task_id=task)

    def test_backup_then_restore_in_a_different_home_preserves_everything(self):
        backup_file = self.root / 'backup.sqlite3'
        info = self.core.backup(str(backup_file))
        self.assertTrue(backup_file.is_file())
        self.assertEqual(info['size'], backup_file.stat().st_size)

        # Restore into a BRAND NEW home, simulating recovery outside the
        # original job/session that created the data.
        new_home = self.root / 'restored-state'
        restored = Core.restore(new_home, str(backup_file))
        try:
            self.assertEqual(restored.get(self.case)['project'], 'p')
            self.assertEqual(restored.results(self.case)[0]['sha256'], self.result['sha256'])
            self.assertTrue(restored.verify_audit(self.case))
            # The audit chain carries over exactly, byte for byte.
            self.assertEqual(restored.audit(self.case), self.core.audit(self.case))
        finally:
            restored.close()

    def test_backup_refuses_to_overwrite_existing_destination(self):
        backup_file = self.root / 'exists.sqlite3'
        backup_file.write_text('not a database')
        with self.assertRaises(CoreError):
            self.core.backup(str(backup_file))

    def test_restore_refuses_to_overwrite_an_existing_store(self):
        backup_file = self.root / 'b2.sqlite3'
        self.core.backup(str(backup_file))
        # restoring into self.core's own home: a live store is already there
        with self.assertRaises(CoreError):
            Core.restore(self.root / 'state', str(backup_file))

    def test_restore_rejects_a_non_database_source(self):
        bogus = self.root / 'bogus.sqlite3'
        bogus.write_bytes(b'not a sqlite file at all')
        with self.assertRaises(CoreError):
            Core.restore(self.root / 'another-home', str(bogus))
        self.assertFalse((self.root / 'another-home' / 'core.sqlite3').exists())


if __name__ == '__main__':
    unittest.main()
