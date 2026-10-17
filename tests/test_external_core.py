"""External tools must operate through acquired evidence and durable CORE results."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from cyber_core.service import Core, CoreError

class ExternalCoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.scope = self.root / "inputs"
        self.scope.mkdir()
        self.core = Core(self.root / "store", timeout=30)
        self.addCleanup(self.core.close)
        self.case = self.core.investigate("synthetic", "Optional external analysis", str(self.scope), "owner", "Synthetic files")
        self.path = self.scope / "sample.bin"
        self.path.write_bytes(b"synthetic firmware")

    def test_missing_explicit_backend_is_recorded_and_persisted(self):
        self.core.external_tools = {"binwalk": {"executable": str(self.root / "missing-binwalk")}}
        task = self.core.enqueue(self.case, self.path, tool="analyze-firmware")
        result = self.core.run_one(self.case, task)
        self.assertIn("external_analysis", result["firmware"])
        external = result["firmware"]["external_analysis"]["binwalk"]
        self.assertEqual(external["status"], "dependency_unavailable")
        self.assertEqual(external["input_sha256"], result["sha256"])
        self.assertEqual(result["copy"], str(next((self.core.home / "cases" / self.case / "evidence").iterdir())))
        self.assertEqual(self.core.results(self.case)[0]["firmware"]["external_analysis"], result["firmware"]["external_analysis"])
        report = self.core.report(self.case).read_text()
        self.assertIn("dependency_unavailable", report)
        self.assertTrue(self.core.verify_audit(self.case))

    def test_relative_configuration_is_rejected_before_work(self):
        with self.assertRaises(CoreError):
            Core(self.root / "other-store", external_tools={"binwalk": {"executable": "binwalk"}})

    def test_other_analysis_does_not_start_external_backends(self):
        self.core.external_tools = {"binwalk": {"executable": str(self.root / "missing-binwalk")}}
        task = self.core.enqueue(self.case, self.path)
        result = self.core.run_one(self.case, task)
        self.assertNotIn("external_analysis", result)
        self.assertEqual(self.core.results(self.case)[0]["tool"], "analyze-file")

    def test_unconfigured_firmware_remains_usable(self):
        task = self.core.enqueue(self.case, self.path, tool="analyze-firmware")
        result = self.core.run_one(self.case, task)
        self.assertEqual(result["sha256"], hashlib.sha256(self.path.read_bytes()).hexdigest())
        self.assertTrue(result["copy_verified"])
        self.assertNotIn("external_analysis", result["firmware"])

if __name__ == "__main__":
    unittest.main()
