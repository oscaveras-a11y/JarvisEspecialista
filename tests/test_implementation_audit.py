import json
import tempfile
import unittest
from pathlib import Path

from cyber_core.service import Core, CoreError
from cyber_core.cryptanalysis.implementation_audit import audit_implementation


class ImplementationAuditUnitTests(unittest.TestCase):
    def test_detects_broken_cipher_and_ecb_mode(self):
        report = audit_implementation('cipher = DES.new(key, DES.MODE_ECB)\n')
        kinds = {f['kind'] for f in report['findings']}
        self.assertIn('broken_cipher', kinds)
        self.assertIn('ecb_mode', kinds)
        self.assertEqual(report['summary']['high'], 2)

    def test_detects_static_iv_and_hardcoded_key_redacted(self):
        report = audit_implementation('key = "abcdef0123456789abcdef"\niv: 0x00000000000000000000000000000000\n')
        kinds = {f['kind'] for f in report['findings']}
        self.assertIn('hardcoded_key_literal', kinds)
        self.assertIn('static_iv_or_nonce', kinds)
        self.assertNotIn('abcdef0123456789abcdef', json.dumps(report))

    def test_detects_weak_random_and_short_key(self):
        report = audit_implementation('token = random.random()\nkey_size = 56\n')
        kinds = {f['kind'] for f in report['findings']}
        self.assertIn('weak_random_for_crypto', kinds)
        self.assertIn('short_key_length', kinds)

    def test_detects_insufficient_pbkdf2_iterations(self):
        weak = audit_implementation('key = PBKDF2(password, salt, iterations=1000)\n')
        self.assertIn('insufficient_kdf_iterations', {f['kind'] for f in weak['findings']})
        strong = audit_implementation('key = PBKDF2(password, salt, iterations=600000)\n')
        self.assertNotIn('insufficient_kdf_iterations', {f['kind'] for f in strong['findings']})

    def test_clean_code_has_no_findings(self):
        report = audit_implementation('from cryptography.hazmat.primitives.ciphers.aead import AESGCM\nkey = os.urandom(32)\n')
        self.assertEqual(report['findings'], [])

    def test_rejects_non_string(self):
        with self.assertRaises(CoreError):
            audit_implementation(b'bytes')

    def test_secret_not_leaked_through_another_finding_on_same_line(self):
        # Same cross-finding leak class fixed in vulnerability/__init__.py (F1).
        report = audit_implementation('key="abcdef0123456789abcdef" cipher=DES.new(key)\n')
        for finding in report['findings']:
            self.assertNotIn('abcdef0123456789abcdef', finding['excerpt'])


class ImplementationAuditServiceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.scope = root / 'inputs'
        self.scope.mkdir()
        self.core = Core(root / 'state')
        self.addCleanup(self.core.close)
        self.case = self.core.investigate('p', 'Auditoria de implementação criptográfica', str(self.scope), 'owner', 'auth')

    def test_audit_crypto_implementation_persists_and_audits_only_counts(self):
        src = self.scope / 'crypto.py'
        src.write_text('key = "HARDCODED_KEY_VALUE_1234"\ncipher = AES.new(key, AES.MODE_ECB)\n', encoding='utf-8')
        result = self.core.audit_crypto_implementation(self.case, str(src))
        self.assertGreaterEqual(result['summary']['high'], 1)
        stored = self.core.side_analyses(self.case, kind='crypto_audit')
        self.assertEqual(len(stored), 1)
        self.assertEqual(stored[0]['data']['findings'], result['findings'])
        blob = json.dumps(self.core.audit(self.case))
        self.assertNotIn('HARDCODED_KEY_VALUE_1234', blob)
        self.assertTrue(self.core.verify_audit(self.case))

    def test_rejects_while_paused(self):
        src = self.scope / 'crypto.py'
        src.write_text('cipher = DES.new(key)\n', encoding='utf-8')
        self.core.pause(self.case)
        with self.assertRaises(CoreError):
            self.core.audit_crypto_implementation(self.case, str(src))


if __name__ == '__main__':
    unittest.main()
