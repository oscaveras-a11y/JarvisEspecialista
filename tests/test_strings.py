import json
import tempfile
import unittest
from pathlib import Path

from cyber_core.service import Core, CoreError
from cyber_core.reverse_engineering.strings import extract_strings


class StringsUnitTests(unittest.TestCase):
    def test_ascii_runs_with_min_length(self):
        data = b'\x00\x01hello\x00ab\x00world!\x00'
        out = extract_strings(data, min_length=4)
        self.assertIn('hello', out['ascii'])
        self.assertIn('world!', out['ascii'])
        self.assertNotIn('ab', out['ascii'])  # shorter than min_length

    def test_utf16le_runs(self):
        data = 'DATA'.encode('utf-16le') + b'\xff\xfe'
        out = extract_strings(data, min_length=4)
        self.assertIn('DATA', out['utf16le'])

    def test_max_strings_cap(self):
        data = (b'abcd\x00' * 10)
        out = extract_strings(data, min_length=4, max_strings=3)
        self.assertEqual(len(out['ascii']), 3)
        self.assertTrue(out['truncated'])

    def test_rejects_bad_params(self):
        with self.assertRaises(CoreError):
            extract_strings(b'abcd', min_length=0)
        with self.assertRaises(CoreError):
            extract_strings('not bytes')


class StringsServiceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.scope = root / 'inputs'
        self.scope.mkdir()
        self.core = Core(root / 'state')
        self.addCleanup(self.core.close)
        self.case = self.core.investigate('p', 'Extração de strings', str(self.scope), 'owner', 'auth')

    def test_extract_strings_returns_to_operator_but_audits_only_counts(self):
        sample = self.scope / 'bin.dat'
        sample.write_bytes(b'\x00\x01SENHA_SECRETA_NAO_VAZA\x00\x02')
        result = self.core.extract_strings(self.case, str(sample), min_length=4)
        self.assertIn('SENHA_SECRETA_NAO_VAZA', result['ascii'])
        blob = json.dumps(self.core.audit(self.case))
        self.assertNotIn('SENHA_SECRETA_NAO_VAZA', blob)  # evidence content stays out of the audit
        self.assertTrue(self.core.verify_audit(self.case))


if __name__ == '__main__':
    unittest.main()
