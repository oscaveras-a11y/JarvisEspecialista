"""Follow-up regressions against the current candidate, not the old prototype."""
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from cyber_core.service import Core
from cyber_core.vulnerability import audit_config
from cyber_core.protocol import analyze_capture, compare_captures

class OutputTests(unittest.TestCase):
    def test_unknown_secret_syntax_never_reaches_any_excerpt(self):
        result = audit_config('DEBUG=true opaque_key="SYNTHETIC_UNKNOWN_SECRET"')
        self.assertEqual(result["summary"]["medium"], 1)
        self.assertNotIn("SYNTHETIC_UNKNOWN_SECRET", json.dumps(result))

    def test_short_or_spaced_secrets_are_not_echoed(self):
        for value in ('password=x DEBUG=true', 'password="SYNTHETIC SPACED SECRET" DEBUG=true',
                      'http://synthetic-user:synthetic-pass@example.test DEBUG=true'):
            with self.subTest(value=value):
                result = audit_config(value)
                self.assertTrue(result["findings"])
                for finding in result["findings"]:
                    self.assertEqual(finding["excerpt"], "[source text omitted; inspect authorized evidence]")

    def test_known_ids_keep_counting_after_distinct_limit(self):
        with patch("cyber_core.protocol._MAX_DISTINCT", 2):
            result = analyze_capture("a#01\nb#02\nc#03\na#01\n")
        self.assertEqual(result["id_histogram"]["a"], 2)
        self.assertTrue(result.get("ids_truncated", False))
        self.assertTrue(result.get("payloads_truncated", False))

    def test_comparison_exposes_incomplete_payload_sets(self):
        with patch("cyber_core.protocol._MAX_DISTINCT", 2):
            result = compare_captures("01\n02\n03\n", "01\n")
        self.assertTrue(result.get("comparison_truncated", False))

class CaptureServiceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.scope = root / "inputs"
        self.scope.mkdir()
        self.core = Core(root / "store")
        self.addCleanup(self.core.close)
        self.case = self.core.investigate("synthetic", "Capture boundaries", str(self.scope), "owner", "Synthetic input")

    def file(self, name, data):
        path = self.scope / name
        path.write_bytes(data)
        return path

    def test_cut_record_is_not_a_complete_message(self):
        result = self.core.analyze_capture(self.case, self.file("a.txt", b"010203\n"), max_sample=2)
        self.assertEqual(result["messages"], 0)
        self.assertTrue(result.get("partial_record_discarded", False))

    def test_paired_inputs_keep_independent_truncation_flags(self):
        first = self.file("a.txt", b"01\n02\n")
        second = self.file("b.txt", b"03\n")
        result = self.core.analyze_capture(self.case, first, second_path=second, max_sample=3)
        self.assertTrue(result["first"].get("sample_truncated", False))
        self.assertFalse(result["second"].get("sample_truncated", True))
        self.assertFalse(result["second"]["truncated"])
        self.assertTrue(result["sample_truncated"])

    def test_report_does_not_reexpose_unrecognized_secret(self):
        path = self.file("config.txt", b'DEBUG=true opaque_key="SYNTHETIC_REPORT_SECRET"')
        self.core.audit_config(self.case, path)
        self.assertNotIn("SYNTHETIC_REPORT_SECRET", self.core.report(self.case).read_text())
        self.assertTrue(self.core.verify_audit(self.case))

if __name__ == "__main__":
    unittest.main()
