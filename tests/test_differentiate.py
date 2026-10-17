import os
import tempfile
import unittest
from pathlib import Path

from cyber_core.service import Core, CoreError
from cyber_core.cryptanalysis.differentiate import differentiate


class DifferentiateUnitTests(unittest.TestCase):
    def test_signatures(self):
        self.assertEqual(differentiate(b'\x1f\x8b\x08rest')['content_class'], 'compression')
        self.assertEqual(differentiate(b'PK\x03\x04rest')['content_class'], 'archive')
        self.assertEqual(differentiate(b'CCAES1' + b'x' * 40)['content_class'], 'encrypted')
        self.assertEqual(differentiate(b'Salted__' + b'x' * 20)['label'], 'openssl-salted')

    def test_encoding_hex_and_base64(self):
        self.assertEqual(differentiate(b'0123456789abcdef0123')['label'], 'hex')
        self.assertEqual(differentiate(b'QUJDREVGR0hJSktMTU5PUFFSUw==')['label'], 'base64')

    def test_text(self):
        self.assertEqual(differentiate(b'Hello, this is plain readable text.\n')['content_class'], 'text')

    def test_high_entropy_is_not_asserted_as_encryption(self):
        report = differentiate(os.urandom(4096))
        self.assertEqual(report['content_class'], 'high-entropy')
        self.assertIn('encrypted-or-compressed', report['label'])
        self.assertTrue(any('não prova' in limit for limit in report['limitations']))

    def test_structured_low_entropy(self):
        self.assertEqual(differentiate(bytes([0, 1, 2, 3]) * 200)['content_class'], 'structured')

    def test_non_bytes_rejected(self):
        with self.assertRaises(CoreError):
            differentiate('not bytes')


class DifferentiateServiceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.scope = root / 'inputs'
        self.scope.mkdir()
        self.core = Core(root / 'state')
        self.addCleanup(self.core.close)
        self.case = self.core.investigate('p', 'Diferenciação de conteúdo', str(self.scope), 'owner', 'auth')

    def test_differentiate_content_audits(self):
        sample = self.scope / 'f.gz'
        sample.write_bytes(b'\x1f\x8b\x08' + b'payload')
        result = self.core.differentiate_content(self.case, str(sample))
        self.assertEqual(result['content_class'], 'compression')
        self.assertTrue(any(e['event'] == 'content_differentiated' for e in self.core.audit(self.case)))
        self.assertTrue(self.core.verify_audit(self.case))


if __name__ == '__main__':
    unittest.main()
