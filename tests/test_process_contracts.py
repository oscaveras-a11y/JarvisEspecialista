"""Execution contracts independent of optional configuration changes."""
import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from cyber_core.analysis_process import analyze_in_process, child, supervisor
from cyber_core.errors import CoreError
from cyber_core.service import Core


class ProcessContractTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.source = self.root / 'sample.bin'
        self.source.write_bytes(b'synthetic long-budget evidence')
        self.output = self.root / 'copy.bin'

    def test_long_budget_reaches_supervisor_and_real_child(self):
        result = analyze_in_process(self.source, self.output, 1024, 86400)
        self.assertEqual(result['sha256'], hashlib.sha256(self.source.read_bytes()).hexdigest())
        self.assertEqual(self.output.read_bytes(), self.source.read_bytes())

    def test_invalid_timeouts_are_rejected_before_start_or_copy(self):
        request = {'source': str(self.source), 'destination': str(self.output),
                   'tool': 'analyze-file', 'max_bytes': 1024}
        for invalid in (0, -1, True, float('nan'), float('inf'), 365 * 86400 + 1, '86400'):
            with self.subTest(timeout=invalid):
                with patch.object(supervisor, '_command') as command:
                    with self.assertRaises(CoreError):
                        supervisor.run_monitored({}, cwd=self.root, timeout=invalid)
                    command.assert_not_called()
                with self.assertRaises(CoreError):
                    child.execute(dict(request, timeout=invalid))
                self.assertFalse(self.output.exists())

    def test_interrupted_claim_uses_effective_attempt_limit(self):
        core = Core(self.root / 'state')
        self.addCleanup(core.close)
        # The shared constructor in PR #3 assigns this effective limit. Exercise
        # the interruption boundary here without importing its configuration API.
        core.max_attempts = 1
        case = core.investigate('integration', 'Synthetic retry limit', str(self.root),
                                'operator', 'Synthetic lab')
        core.enqueue(case, self.source)
        with patch('cyber_core.service.analyze_in_process', side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                core.run_one(case)
        self.assertEqual(core.tasks(case)[0]['status'], 'failed')
        self.assertFalse(core.results(case))
        self.assertTrue(core.verify_audit(case))


if __name__ == '__main__':
    unittest.main()
