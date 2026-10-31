"""Tests for the optional YARA signature-scan module (item 9)."""
import json
import tempfile
import unittest
from pathlib import Path

from cyber_core.errors import CoreError
from cyber_core.service import Core
from cyber_core.vulnerability import yara_scan

# Synthetic marker only; never a real malware signature or secret.
SYNTHETIC_RULE = """
rule synthetic_marker
{
    meta:
        description = "Synthetic test marker; never a real malware signature"
    strings:
        $marker = "SYNTHETIC_YARA_MARKER_YARA_TEST"
    condition:
        $marker
}
"""


class YaraScanUnitTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.rules_path = Path(self.tmp.name) / 'rules.yar'
        self.rules_path.write_text(SYNTHETIC_RULE, encoding='utf-8')

    def test_rejects_relative_rules_path(self):
        with self.assertRaises(CoreError):
            yara_scan.configure_rules('relative/rules.yar')

    def test_rejects_missing_rules_path(self):
        with self.assertRaises(CoreError):
            yara_scan.configure_rules(str(Path(self.tmp.name) / 'missing.yar'))

    def test_rejects_symlinked_rule_file(self):
        target = Path(self.tmp.name) / 'real.yar'
        target.write_text(SYNTHETIC_RULE, encoding='utf-8')
        link = Path(self.tmp.name) / 'link.yar'
        link.symlink_to(target)
        with self.assertRaises(CoreError):
            yara_scan.configure_rules(str(link))

    def test_configure_rules_accepts_directory_of_rules(self):
        directory = Path(self.tmp.name) / 'rules_dir'
        directory.mkdir()
        (directory / 'a.yar').write_text(SYNTHETIC_RULE, encoding='utf-8')
        resolved = yara_scan.configure_rules(str(directory))
        self.assertEqual(resolved, str(directory.resolve()))

    def test_scan_matches_or_reports_dependency_unavailable(self):
        result = yara_scan.scan_bytes(b'prefix SYNTHETIC_YARA_MARKER_YARA_TEST suffix', str(self.rules_path))
        self.assertIn(result['status'], ('completed', 'dependency_unavailable'))
        if result['status'] == 'completed':
            self.assertEqual(len(result['matches']), 1)
            self.assertEqual(result['matches'][0]['rule'], 'synthetic_marker')
            self.assertEqual(result['matches'][0]['strings'][0]['identifier'], '$marker')
            self.assertGreaterEqual(result['matches'][0]['strings'][0]['offset_count'], 1)
            # Matched byte content must never be exposed, only identifier/offset.
            blob = json.dumps(result)
            self.assertNotIn('SYNTHETIC_YARA_MARKER_YARA_TEST', blob)

    def test_clean_input_has_no_matches_when_available(self):
        result = yara_scan.scan_bytes(b'nothing interesting here', str(self.rules_path))
        if result['status'] == 'completed':
            self.assertEqual(result['matches'], [])

    def test_invalid_rule_source_raises(self):
        try:
            import yara  # noqa: F401
        except ImportError:
            self.skipTest('yara-python not installed in this environment')
        bad = Path(self.tmp.name) / 'bad.yar'
        bad.write_text('this is not valid yara syntax {{{', encoding='utf-8')
        with self.assertRaises(CoreError):
            yara_scan.scan_bytes(b'anything', str(bad))

    def test_rejects_non_bytes_input(self):
        with self.assertRaises(CoreError):
            yara_scan.scan_bytes('not bytes', str(self.rules_path))

    def test_rejects_invalid_timeout(self):
        with self.assertRaises(CoreError):
            yara_scan.scan_bytes(b'data', str(self.rules_path), timeout=0)

    def test_rejects_oversized_rule_set(self):
        directory = Path(self.tmp.name) / 'huge_rules'
        directory.mkdir()
        for index in range(yara_scan.MAX_RULE_FILES + 1):
            (directory / f'r{index}.yar').write_text(SYNTHETIC_RULE, encoding='utf-8')
        with self.assertRaises(CoreError):
            yara_scan.configure_rules(str(directory))


class YaraScanServiceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.scope = root / 'inputs'
        self.scope.mkdir()
        self.rules_path = root / 'rules.yar'
        self.rules_path.write_text(SYNTHETIC_RULE, encoding='utf-8')
        self.core = Core(root / 'state')
        self.addCleanup(self.core.close)
        self.case = self.core.investigate('p', 'Varredura YARA', str(self.scope), 'owner', 'auth')

    def file(self, name, data):
        path = self.scope / name
        path.write_bytes(data)
        return path

    def test_requires_rules_configured_first(self):
        sample = self.file('sample.bin', b'anything')
        with self.assertRaises(CoreError):
            self.core.scan_with_yara(self.case, str(sample))

    def test_scan_persists_and_audits_without_leaking_match_content(self):
        self.core.configure_yara_rules(str(self.rules_path))
        sample = self.file('sample.bin', b'prefix SYNTHETIC_YARA_MARKER_YARA_TEST suffix')
        result = self.core.scan_with_yara(self.case, str(sample))
        self.assertTrue(any(e['event'] == 'yara_scanned' for e in self.core.audit(self.case)))
        blob = json.dumps(self.core.audit(self.case))
        self.assertNotIn('SYNTHETIC_YARA_MARKER_YARA_TEST', blob)
        self.assertTrue(self.core.verify_audit(self.case))
        side = self.core.side_analyses(self.case, kind='yara_scan')
        self.assertEqual(len(side), 1)
        self.assertNotIn('SYNTHETIC_YARA_MARKER_YARA_TEST', json.dumps(side))

    def test_report_does_not_reexpose_matched_content(self):
        self.core.configure_yara_rules(str(self.rules_path))
        sample = self.file('sample.bin', b'prefix SYNTHETIC_YARA_MARKER_YARA_TEST suffix')
        self.core.scan_with_yara(self.case, str(sample))
        self.assertNotIn('SYNTHETIC_YARA_MARKER_YARA_TEST', self.core.report(self.case).read_text())

    def test_respects_pause(self):
        self.core.configure_yara_rules(str(self.rules_path))
        sample = self.file('sample.bin', b'anything')
        self.core.pause(self.case)
        with self.assertRaises(CoreError):
            self.core.scan_with_yara(self.case, str(sample))

    def test_sample_truncation_is_reported(self):
        self.core.configure_yara_rules(str(self.rules_path))
        sample = self.file('sample.bin', b'0123456789')
        result = self.core.scan_with_yara(self.case, str(sample), max_sample=4)
        self.assertTrue(result['sample_truncated'])


if __name__ == '__main__':
    unittest.main()
