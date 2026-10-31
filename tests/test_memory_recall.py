import tempfile
import unittest
from pathlib import Path

from cyber_core.service import Core, CoreError


class MemoryRecallTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.core = Core(self.root / 'state')
        self.addCleanup(self.core.close)

    def _case_with_analysis(self, name, payload):
        scope = self.root / name
        scope.mkdir()
        sample = scope / 'ev.bin'
        sample.write_bytes(payload)
        case = self.core.investigate(name, 'Perícia forense de arquivo', str(scope), 'owner', 'auth')
        task = self.core.enqueue(case, sample, tool='analyze-file')
        result = self.core.run_one(case, task_id=task)
        return case, result

    def test_recall_by_hash_finds_same_artifact_across_cases(self):
        payload = b'arquivo identico' * 10
        case_a, result_a = self._case_with_analysis('a', payload)
        case_b, result_b = self._case_with_analysis('b', payload)
        self.assertEqual(result_a['sha256'], result_b['sha256'])
        matches = self.core.recall_by_hash(result_a['sha256'])
        found_cases = {m['case_id'] for m in matches}
        self.assertEqual(found_cases, {case_a, case_b})
        for m in matches:
            self.assertNotIn('copy', m)  # never exposes the stored copy path

    def test_recall_by_hash_unknown_is_empty(self):
        self.assertEqual(self.core.recall_by_hash('0' * 64), [])

    def test_recall_by_hash_rejects_bad_hash(self):
        with self.assertRaises(CoreError):
            self.core.recall_by_hash('not-a-hash')

    def test_recall_by_type_lists_prior_cases(self):
        scope = self.root / 'c'
        scope.mkdir()
        case = self.core.investigate('c', 'Analisar firmware .bin de ECU', str(scope), 'owner', 'auth')
        self.core.classify(case)
        cases = self.core.recall_by_type('firmware')
        self.assertTrue(any(row['case_id'] == case for row in cases))

    def test_recall_by_type_rejects_bad_limit(self):
        with self.assertRaises(CoreError):
            self.core.recall_by_type('firmware', limit=0)


if __name__ == '__main__':
    unittest.main()
