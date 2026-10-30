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
        self.assertEqual(out['source'], 'rockyou')
        self.assertEqual(out['lines'], 2)
        # Compare by identity, not literal string: on Windows the authorized
        # path can come back through its 8.3 short-name alias (RUNNER~1 vs
        # runneradmin), which is still the same file.
        self.assertTrue(Path(out['path']).samefile(self.scope / 'rockyou.txt'))
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


class GeneratedWordlistMaterializationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.scope = root / 'inputs'
        self.scope.mkdir()
        self.core = Core(root / 'state')
        self.addCleanup(self.core.close)
        self.case = self.core.investigate('p', 'Gerar wordlist a partir de pistas', str(self.scope), 'owner', 'auth')

    def test_materializes_rule_based_variations_from_hint_words(self):
        out = self.core.materialize_generated_wordlist(self.case, str(self.scope / 'hints.txt'), ['Rex'], limit=50)
        self.assertEqual(out['source'], 'generated')
        self.assertEqual(out['lines'], 50)
        lines = (self.scope / 'hints.txt').read_text().splitlines()
        self.assertEqual(len(lines), 50)
        self.assertIn('Rex', lines)
        self.assertIn('Rex123', lines)

    def test_hint_words_never_reach_the_audit_trail(self):
        self.core.materialize_generated_wordlist(self.case, str(self.scope / 'hints.txt'),
                                                  ['UnlikelySecretHintWord'], limit=10)
        import json
        blob = json.dumps(self.core.audit(self.case))
        self.assertNotIn('UnlikelySecretHintWord', blob)

    def test_rejects_invalid_words(self):
        with self.assertRaises(CoreError):
            self.core.materialize_generated_wordlist(self.case, str(self.scope / 'x.txt'), [])

    def test_rejects_destination_outside_scope(self):
        with tempfile.TemporaryDirectory() as other:
            with self.assertRaises(CoreError):
                self.core.materialize_generated_wordlist(self.case, str(Path(other) / 'x.txt'), ['rex'])

    def test_rejects_existing_destination(self):
        (self.scope / 'x.txt').write_text('already here')
        with self.assertRaises(CoreError):
            self.core.materialize_generated_wordlist(self.case, str(self.scope / 'x.txt'), ['rex'])

    def test_rejects_while_paused(self):
        self.core.pause(self.case)
        with self.assertRaises(CoreError):
            self.core.materialize_generated_wordlist(self.case, str(self.scope / 'x.txt'), ['rex'])


if __name__ == '__main__':
    unittest.main()
