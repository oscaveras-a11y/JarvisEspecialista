import hashlib
from pathlib import Path
import tempfile
import unittest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cyber_core.service import Core, CoreError


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.scope = self.root / 'inputs'
        self.scope.mkdir()
        self.key = bytes(range(32))
        self.plain = b'%PDF-1.7\nAuthorized synthetic recovery only.\n'
        nonce = bytes(range(12))
        self.source = self.scope / 'encrypted.ccaes'
        self.source.write_bytes(b'CCAES1' + nonce + AESGCM(self.key).encrypt(nonce, self.plain, b'CCAES1'))
        self.core = Core(self.root / 'state')
        self.addCleanup(self.core.close)
        self.case = self.core.investigate('synthetic', 'recover', str(self.scope), 'owner', 'Explicit synthetic recovery authorization', recovery=True)

    def test_known_key_integrity_and_audit(self):
        expected = hashlib.sha256(self.plain).hexdigest()
        result = self.core.recover(self.case, self.source, self.key, expected_sha256=expected, expected_format='PDF signature')
        self.assertEqual(Path(result['output']).read_bytes(), self.plain)
        self.assertTrue(result['authenticated'])
        self.assertEqual(result['sha256'], expected)
        self.assertTrue(self.core.verify_audit(self.case))
        self.assertTrue(any(a['event'] == 'recovery_verified' for a in self.core.audit(self.case)))
        self.assertNotIn(self.key.hex(), repr(self.core.audit(self.case)))
        self.assertNotIn(self.key.hex(), self.core.report(self.case).read_text())

    def test_no_authorization(self):
        case = self.core.investigate('x', 'x', str(self.scope), 'owner', 'Static analysis only')
        with self.assertRaises(CoreError):
            self.core.recover(case, self.source, self.key)
        self.assertTrue(any(a['event'] == 'recovery_rejected' for a in self.core.audit(case)))

    def test_wrong_key_no_plaintext(self):
        with self.assertRaises(CoreError):
            self.core.recover(self.case, self.source, b'x' * 32)
        self.assertFalse(list((self.core.home / 'cases').rglob('*.recovered')))

    def test_invalid_key_lengths(self):
        for key in (b'', b'x' * 16, b'x' * 33):
            with self.subTest(length=len(key)), self.assertRaises(CoreError):
                self.core.recover(self.case, self.source, key)

    def test_tampered_tag(self):
        data = bytearray(self.source.read_bytes())
        data[-1] ^= 1
        self.source.write_bytes(data)
        with self.assertRaises(CoreError):
            self.core.recover(self.case, self.source, self.key)

    def test_integrity_expectation_must_match(self):
        with self.assertRaises(CoreError):
            self.core.recover(self.case, self.source, self.key, expected_sha256='0' * 64)
        self.assertFalse(list((self.core.home / 'cases').rglob('*.recovered')))

    def test_attempt_limit(self):
        for _ in range(3):
            with self.assertRaises(CoreError):
                self.core.recover(self.case, self.source, b'x' * 32)
        with self.assertRaisesRegex(CoreError, 'budget'):
            self.core.recover(self.case, self.source, self.key)

    def test_outside_scope_and_revoked(self):
        outside = self.root / 'copy.ccaes'
        outside.write_bytes(self.source.read_bytes())
        with self.assertRaises(CoreError):
            self.core.recover(self.case, outside, self.key)
        self.core.revoke(self.case)
        with self.assertRaises(CoreError):
            self.core.recover(self.case, self.source, self.key)
