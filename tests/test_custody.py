import tempfile
import unittest
from pathlib import Path

from cyber_core.service import Core


class CustodyTimelineTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.scope = root / 'inputs'
        self.scope.mkdir()
        self.sample = self.scope / 'ev.bin'
        self.sample.write_bytes(b'evidence bytes for custody')
        self.core = Core(root / 'state')
        self.addCleanup(self.core.close)
        self.case = self.core.investigate('p', 'Perícia com custódia', str(self.scope), 'owner', 'auth')

    def test_timeline_reflects_acquisition_and_is_chain_valid(self):
        task = self.core.enqueue(self.case, self.sample, tool='analyze-file')
        result = self.core.run_one(self.case, task_id=task)
        timeline = self.core.custody_timeline(self.case)
        self.assertTrue(timeline['chain_valid'])
        self.assertTrue(any(e['event'] == 'authorization_registered' for e in timeline['events']))
        self.assertEqual(timeline['acquisitions'][0]['sha256'], result['sha256'])
        # ordered by sequence
        seqs = [e['seq'] for e in timeline['events']]
        self.assertEqual(seqs, sorted(seqs))

    def test_timeline_detects_tampering(self):
        task = self.core.enqueue(self.case, self.sample, tool='analyze-file')
        self.core.run_one(self.case, task_id=task)
        # Tamper with an audit row directly; the chain must report invalid.
        self.core.db.execute("UPDATE audit SET data='{\"x\":1}' WHERE case_id=? AND id=(SELECT MIN(id) FROM audit WHERE case_id=?)",
                             (self.case, self.case))
        self.core.db.commit()
        self.assertFalse(self.core.custody_timeline(self.case)['chain_valid'])


if __name__ == '__main__':
    unittest.main()
