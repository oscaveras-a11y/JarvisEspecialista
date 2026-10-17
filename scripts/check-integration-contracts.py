"""Compatibility probes for the immutable PR #3 + process-beta combination.

Run only in the integration workflow after the candidate merge. These tests use
synthetic evidence and do not require or modify any operator installation.
"""
import hashlib
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from cyber_core.service import Core


class IntegrationContracts(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.inputs = self.root / 'inputs'
        self.inputs.mkdir()
        self.source = self.inputs / 'sample.bin'
        self.source.write_bytes(b'synthetic integration evidence')

    def make_core(self, **limits):
        core = Core(self.root / 'state', **limits)
        self.addCleanup(core.close)
        case = core.investigate('integration', 'Check shared execution contracts',
                                str(self.inputs), 'operator', 'Synthetic lab')
        core.enqueue(case, self.source)
        return core, case

    def test_day_timeout_reaches_real_analysis_child(self):
        core, case = self.make_core(timeout=86400)
        result = core.run_one(case)
        self.assertEqual(result['sha256'], hashlib.sha256(self.source.read_bytes()).hexdigest())
        self.assertEqual(core.tasks(case)[0]['status'], 'done')
        self.assertTrue(core.verify_audit(case))

    def test_interruption_uses_configured_attempt_limit(self):
        core, case = self.make_core(max_attempts=1)
        with patch('cyber_core.service.analyze_in_process', side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                core.run_one(case)
        self.assertEqual(core.tasks(case)[0]['attempts'], 1)
        self.assertEqual(core.tasks(case)[0]['status'], 'failed',
                         'Exhausted interrupted claim must not remain pending')
        self.assertIsNone(core.run_one(case))
        self.assertTrue(core.verify_audit(case))


if __name__ == '__main__':
    unittest.main(verbosity=2)
