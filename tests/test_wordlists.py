import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cyber_core.service import Core, CoreError


class WordlistMaterializationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.scope = root / 'inputs'
        self.scope.mkdir()
        self.core = Core(root / 'state')
        self.addCleanup(self.core.close)
        self.case = self.core.investigate('p', 'Materializar wordlist', str(self.scope), 'owner', 'auth')

    def test_materializes_a_bounded_prefix_as_a_real_scope_file(self):
        with patch('cyber_core.cryptanalysis.wordlists.iter_builtin_wordlist',
                  return_value=iter(['alpha', 'beta', 'gamma', 'delta'])):
            out = self.core.materialize_wordlist(self.case, str(self.scope / 'rockyou.txt'), limit=2)
        self.assertEqual(out, {'path': str(self.scope / 'rockyou.txt'), 'source': 'rockyou', 'lines': 2})
        self.assertEqual((self.scope / 'rockyou.txt').read_text().splitlines(), ['alpha', 'beta'])

    def test_uses_the_real_bundled_rockyou_list_by_default(self):
        out = self.core.materialize_wordlist(self.case, str(self.scope / 'rockyou.txt'), limit=5)
        self.assertEqual(out['lines'], 5)
        lines = (self.scope / 'rockyou.txt').read_text().splitlines()
        # The well-known top of rockyou.txt; also proves the real bundled file loads.
        self.assertEqual(lines, ['123456', '12345', '123456789', 'password', 'iloveyou'])

    def test_rejects_unknown_source(self):
        with self.assertRaises(CoreError):
            self.core.materialize_wordlist(self.case, str(self.scope / 'x.txt'), source='other')

    def test_rejects_invalid_limit(self):
        with self.assertRaises(CoreError):
            self.core.materialize_wordlist(self.case, str(self.scope / 'x.txt'), limit=0)
        with self.assertRaises(CoreError):
            self.core.materialize_wordlist(self.case, str(self.scope / 'x.txt'), limit=100001)

    def test_rejects_destination_outside_scope(self):
        with tempfile.TemporaryDirectory() as other:
            with self.assertRaises(CoreError):
                self.core.materialize_wordlist(self.case, str(Path(other) / 'x.txt'), limit=1)

    def test_rejects_existing_destination(self):
        (self.scope / 'x.txt').write_text('already here')
        with self.assertRaises(CoreError):
            self.core.materialize_wordlist(self.case, str(self.scope / 'x.txt'), limit=1)

    def test_rejects_while_paused(self):
        self.core.pause(self.case)
        with self.assertRaises(CoreError):
            self.core.materialize_wordlist(self.case, str(self.scope / 'x.txt'), limit=1)


if __name__ == '__main__':
    unittest.main()
