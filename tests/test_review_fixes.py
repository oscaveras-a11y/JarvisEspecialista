"""Regression tests for the 5 findings reproduced in PR #9's independent review
(docs/2026-10-17-project-status-report.md) against the Claude candidate.

F1 (secret leaked through another finding) and F5 (similar-domain misclassification)
have their own regressions in tests/test_vulnerability.py and tests/test_research.py.
This file covers F2 (pause ignored by new analysis routes), F3 (new analyses not
reconstructable from normal history) and F4 (capture truncation not reported).
"""
import tempfile
import unittest
from pathlib import Path

from cyber_core.service import Core, CoreError


class PauseGuardTests(unittest.TestCase):
    """F2: new_config_analysis_executes_while_paused=true was reproduced for
    audit_config; the same guard was missing on every other new analysis route."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.scope = root / 'inputs'
        self.scope.mkdir()
        self.sample = self.scope / 'f.txt'
        self.sample.write_text('password=x\n100#AA\n', encoding='utf-8')
        self.core = Core(root / 'state')
        self.addCleanup(self.core.close)
        self.case = self.core.investigate('p', 'Guard de pausa', str(self.scope), 'owner', 'auth')
        self.core.pause(self.case)

    def test_audit_config_rejects_while_paused(self):
        with self.assertRaises(CoreError):
            self.core.audit_config(self.case, str(self.sample))

    def test_differentiate_content_rejects_while_paused(self):
        with self.assertRaises(CoreError):
            self.core.differentiate_content(self.case, str(self.sample))

    def test_extract_strings_rejects_while_paused(self):
        with self.assertRaises(CoreError):
            self.core.extract_strings(self.case, str(self.sample))

    def test_analyze_capture_rejects_while_paused(self):
        with self.assertRaises(CoreError):
            self.core.analyze_capture(self.case, str(self.sample))

    def test_classify_plan_decompose_reject_while_paused(self):
        with self.assertRaises(CoreError):
            self.core.classify(self.case)
        with self.assertRaises(CoreError):
            self.core.plan(self.case)
        with self.assertRaises(CoreError):
            self.core.decompose(self.case, str(self.sample))


class SideAnalysisPersistenceTests(unittest.TestCase):
    """F3: config_analysis_persisted_tasks=0 / persisted_results=0 — new analyses
    could not be reconstructed from normal case history, only audit counts."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.scope = root / 'inputs'
        self.scope.mkdir()
        self.core = Core(root / 'state')
        self.addCleanup(self.core.close)
        self.case = self.core.investigate('p', 'Persistência de análises', str(self.scope), 'owner', 'auth')

    def test_audit_config_is_reconstructable_from_side_analyses(self):
        cfg = self.scope / 'app.conf'
        cfg.write_text('password=HARDCODED_PWD\n', encoding='utf-8')
        live = self.core.audit_config(self.case, str(cfg))
        stored = self.core.side_analyses(self.case, kind='config_audit')
        self.assertEqual(len(stored), 1)
        # The persisted record reconstructs the same findings the operator saw live.
        self.assertEqual(stored[0]['data']['findings'], live['findings'])
        self.assertNotIn('HARDCODED_PWD', str(stored[0]['data']))

    def test_all_four_side_analysis_kinds_persist_and_filter(self):
        cfg = self.scope / 'mixed.bin'
        cfg.write_bytes(b'hello world strings here and a config line\n')
        self.core.extract_strings(self.case, str(cfg))
        self.core.differentiate_content(self.case, str(cfg))
        self.core.audit_config(self.case, str(cfg))
        cap = self.scope / 'cap.txt'
        cap.write_text('100#AABB\n', encoding='utf-8')
        self.core.analyze_capture(self.case, str(cap))
        every = self.core.side_analyses(self.case)
        self.assertEqual({e['kind'] for e in every}, {'strings', 'differentiate', 'config_audit', 'capture'})
        only_strings = self.core.side_analyses(self.case, kind='strings')
        self.assertEqual(len(only_strings), 1)

    def test_side_analyses_appear_in_the_technical_report(self):
        cfg = self.scope / 'app.conf'
        cfg.write_text('debug=true\n', encoding='utf-8')
        self.core.audit_config(self.case, str(cfg))
        report_path = self.core.report(self.case)
        import json
        text = report_path.read_text(encoding='utf-8')
        start = text.index('```json\n') + len('```json\n')
        payload = json.loads(text[start:text.rindex('```')])
        self.assertIn('side_analyses', payload)
        self.assertEqual(payload['side_analyses'][0]['kind'], 'config_audit')


class CaptureTruncationTests(unittest.TestCase):
    """F4: a 2-message capture sampled at 3 bytes reported 1 message and
    capture_truncation_reported=false — byte-level truncation was silently lost
    because the whole file was read before slicing to max_sample."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.scope = root / 'inputs'
        self.scope.mkdir()
        self.core = Core(root / 'state')
        self.addCleanup(self.core.close)
        self.case = self.core.investigate('p', 'Truncamento de captura', str(self.scope), 'owner', 'auth')

    def test_byte_level_truncation_is_reported_even_without_hitting_message_cap(self):
        cap = self.scope / 'cap.txt'
        cap.write_text('100#AABBCCDD\n200#EEFF\n', encoding='utf-8')
        result = self.core.analyze_capture(self.case, str(cap), max_sample=3)
        self.assertTrue(result['truncated'])
        self.assertTrue(result['sample_truncated'])

    def test_untruncated_capture_reports_false(self):
        cap = self.scope / 'cap.txt'
        cap.write_text('100#AABB\n', encoding='utf-8')
        result = self.core.analyze_capture(self.case, str(cap), max_sample=4096)
        self.assertFalse(result['truncated'])
        self.assertFalse(result['sample_truncated'])

    def test_compare_mode_also_reports_byte_truncation(self):
        first = self.scope / 'a.txt'
        second = self.scope / 'b.txt'
        first.write_text('100#AABBCCDD\n', encoding='utf-8')
        second.write_text('100#AABBCCDD\n', encoding='utf-8')
        result = self.core.analyze_capture(self.case, str(first), second_path=str(second), max_sample=3)
        self.assertTrue(result['sample_truncated'])
        self.assertTrue(result['first']['truncated'])
        self.assertTrue(result['second']['truncated'])


if __name__ == '__main__':
    unittest.main()
