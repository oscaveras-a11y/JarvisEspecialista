import tempfile
import unittest
from pathlib import Path

from cyber_core.service import Core, CoreError


class DecompositionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.scope = root / 'inputs'
        self.scope.mkdir()
        self.sample = self.scope / 'sample.bin'
        self.sample.write_bytes(bytes(range(256)) * 8)
        self.core = Core(root / 'state')
        self.addCleanup(self.core.close)
        # Forensics objective -> analyze-file tool, which accepts arbitrary bytes.
        self.case = self.core.investigate('p', 'Perícia forense de arquivo: metadados e linha do tempo', str(self.scope), 'owner', 'auth')

    def test_decompose_creates_task_linked_to_plan_and_assigned(self):
        out = self.core.decompose(self.case, str(self.sample))
        self.assertEqual(len(out['tasks']), 1)
        task = out['tasks'][0]['task']
        # task is queued and linked to a plan
        link = self.core.db.execute('SELECT plan_id FROM plan_tasks WHERE task_id=?', (task,)).fetchone()
        self.assertEqual(link['plan_id'], out['plan'])
        # broker assigned an executor
        self.assertEqual(out['tasks'][0]['executor'], 'core')
        self.assertTrue(self.core.assignments(self.case))
        self.assertTrue(self.core.verify_audit(self.case))

    def test_decomposed_task_runs_to_completion(self):
        out = self.core.decompose(self.case, str(self.sample))
        task = out['tasks'][0]['task']
        result = self.core.run_one(self.case, task_id=task)
        self.assertEqual(result['tool'], 'analyze-file')
        self.assertEqual(self.core.tasks(self.case)[0]['status'], 'done')

    def test_decompose_reuses_existing_plan(self):
        first = self.core.plan(self.case)
        out = self.core.decompose(self.case, str(self.sample))
        self.assertEqual(out['plan'], first['plan'])
        plans = self.core.db.execute('SELECT COUNT(*) AS c FROM plans WHERE case_id=?', (self.case,)).fetchone()
        self.assertEqual(plans['c'], 1)

    def test_assign_unknown_task_rejected(self):
        with self.assertRaises(CoreError):
            self.core.assign(self.case, 'deadbeef')

    def test_cancelled_case_rejects_decompose(self):
        self.core.cancel(self.case, reason='t')
        with self.assertRaises(CoreError):
            self.core.decompose(self.case, str(self.sample))


if __name__ == '__main__':
    unittest.main()
