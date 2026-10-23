import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cyber_core.service import Core, CoreError
from cyber_core.protocol import analyze_capture, compare_captures
import cyber_core.protocol as protocol_module


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

    def test_known_ids_keep_counting_past_distinct_cap(self):
        # Regression: hitting _MAX_DISTINCT previously dropped a NEW id/payload
        # silently, with no signal in the result. An already-known id must keep
        # counting (no data loss for what's already tracked), and the drop of a
        # genuinely new id/payload past the cap must be reported.
        with patch.object(protocol_module, '_MAX_DISTINCT', 2):
            out = analyze_capture('a#01\nb#02\nc#03\na#01\n')
        self.assertEqual(out['id_histogram']['a'], 2)
        self.assertTrue(out['ids_truncated'])
        self.assertTrue(out['payloads_truncated'])

    def test_no_false_positive_truncation_under_the_cap(self):
        with patch.object(protocol_module, '_MAX_DISTINCT', 10):
            out = analyze_capture('a#01\nb#02\n')
        self.assertFalse(out['ids_truncated'])
        self.assertFalse(out['payloads_truncated'])

    def test_comparison_exposes_incomplete_payload_sets(self):
        with patch.object(protocol_module, '_MAX_DISTINCT', 2):
            cmp = compare_captures('01\n02\n03\n', '01\n')
        self.assertTrue(cmp['comparison_truncated'])

    def test_comparison_not_truncated_for_a_small_capture(self):
        cmp = compare_captures('100#AABB\n100#CCDD\n', '100#AABB\n100#EEFF\n')
        self.assertFalse(cmp['comparison_truncated'])


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

    def test_cut_mid_record_is_not_counted_as_a_complete_message(self):
        # Regression: the sample cap previously cut mid-record and that partial
        # tail could be misread as a (wrong) complete message. write_bytes (not
        # write_text) keeps the byte count exact across platforms, since
        # Path.write_text() translates '\n' to '\r\n' on Windows.
        cap = self.scope / 'cap.txt'
        cap.write_bytes(b'010203\n')
        result = self.core.analyze_capture(self.case, str(cap), max_sample=2)
        self.assertEqual(result['messages'], 0)
        self.assertTrue(result['partial_record_discarded'])
        self.assertTrue(result['sample_truncated'])

    def test_paired_captures_keep_independent_truncation_flags(self):
        # Regression: both sides of a comparison previously shared a single
        # truncation flag, so a large first file could wrongly mark an untruncated
        # second file as truncated too. write_bytes (not write_text) keeps the byte
        # count exact across platforms, since Path.write_text() translates '\n' to
        # '\r\n' on Windows, which would silently cross the max_sample boundary.
        first = self.scope / 'a.txt'
        first.write_bytes(b'01\n02\n')
        second = self.scope / 'b.txt'
        second.write_bytes(b'03\n')
        result = self.core.analyze_capture(self.case, str(first), second_path=str(second), max_sample=3)
        self.assertTrue(result['first']['sample_truncated'])
        self.assertFalse(result['second']['sample_truncated'])
        self.assertFalse(result['second']['truncated'])
        self.assertTrue(result['sample_truncated'])


if __name__ == '__main__':
    unittest.main()
