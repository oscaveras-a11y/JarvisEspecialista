import tempfile
import unittest
from pathlib import Path

from cyber_core.service import Core, CoreError
from cyber_core.protocol import analyze_capture, compare_captures


class ProtocolUnitTests(unittest.TestCase):
    def test_parses_ids_lengths_and_uniques(self):
        text = '100#DEADBEEF\n100#DEADBEEF\n200#0102\nbadline zz\n'
        out = analyze_capture(text)
        self.assertEqual(out['messages'], 3)
        self.assertEqual(out['skipped'], 1)
        self.assertEqual(out['unique_payloads'], 2)
        self.assertEqual(out['id_histogram'].get('100'), 2)
        self.assertEqual(out['length_histogram'].get(4), 2)

    def test_accepts_space_and_colon_separators(self):
        self.assertEqual(analyze_capture('DE AD BE EF\nDE:AD\n')['messages'], 2)

    def test_compare_reports_differences(self):
        cmp = compare_captures('100#AABB\n100#CCDD\n', '100#AABB\n100#EEFF\n')
        self.assertIn('ccdd', cmp['only_in_first'])
        self.assertIn('eeff', cmp['only_in_second'])
        self.assertEqual(cmp['common_unique_payloads'], 1)

    def test_rejects_non_string(self):
        with self.assertRaises(CoreError):
            analyze_capture(b'bytes')


class ProtocolServiceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.scope = root / 'inputs'
        self.scope.mkdir()
        self.core = Core(root / 'state')
        self.addCleanup(self.core.close)
        self.case = self.core.investigate('p', 'Análise de captura', str(self.scope), 'owner', 'auth')

    def test_analyze_capture_audits(self):
        cap = self.scope / 'cap.txt'
        cap.write_text('100#DEADBEEF\n200#0102\n', encoding='utf-8')
        result = self.core.analyze_capture(self.case, str(cap))
        self.assertEqual(result['messages'], 2)
        self.assertTrue(any(e['event'] == 'capture_analyzed' for e in self.core.audit(self.case)))
        self.assertTrue(self.core.verify_audit(self.case))


if __name__ == '__main__':
    unittest.main()
