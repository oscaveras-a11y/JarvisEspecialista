import json
import tempfile
import time
import unittest
from pathlib import Path

import py7zr

from cyber_core.service import Core, CoreError
from cyber_core.cryptanalysis.sevenzip_cracker import attempt_7z_password


def _protected_7z(path, password, *, content=b'conteudo autorizado de teste 7z', encrypt_headers=False):
    with tempfile.TemporaryDirectory() as tmp:
        source = Path(tmp) / 'doc.txt'
        source.write_bytes(content)
        with py7zr.SevenZipFile(path, 'w', password=password) as archive:
            if encrypt_headers:
                archive.set_encrypted_header(True)
            archive.write(source, 'doc.txt')


class SevenZipCrackerUnitTests(unittest.TestCase):
    def test_recovers_known_password_content_only_encryption(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'protected.7z'
            _protected_7z(path, 'correct-7z-password')
            out = attempt_7z_password(path, ['wrong-1', 'correct-7z-password', 'wrong-2'],
                                      max_attempts=100, deadline=time.monotonic() + 10)
            self.assertTrue(out['recovered'])
            self.assertEqual(out['attempts'], 2)
            self.assertEqual(out['password'], 'correct-7z-password')

    def test_recovers_known_password_with_encrypted_headers(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'protected.7z'
            _protected_7z(path, 'correct-7z-password-hdr', encrypt_headers=True)
            out = attempt_7z_password(path, ['wrong-1', 'correct-7z-password-hdr', 'wrong-2'],
                                      max_attempts=100, deadline=time.monotonic() + 10)
            self.assertTrue(out['recovered'])
            self.assertEqual(out['password'], 'correct-7z-password-hdr')

    def test_absent_password_is_honest_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'protected.7z'
            _protected_7z(path, 'a-strong-absent-password')
            out = attempt_7z_password(path, ['a', 'b', 'c'], max_attempts=100, deadline=time.monotonic() + 10)
            self.assertFalse(out['recovered'])
            self.assertEqual(out['status'], 'candidates_exhausted')

    def test_attempt_budget_bounds(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'protected.7z'
            _protected_7z(path, 'zzz-the-real-one')
            out = attempt_7z_password(path, ['a', 'b', 'c', 'zzz-the-real-one'],
                                      max_attempts=2, deadline=time.monotonic() + 10)
            self.assertFalse(out['recovered'])
            self.assertEqual(out['status'], 'attempt_budget_exhausted')

    def test_unprotected_7z_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'plain.7z'
            with tempfile.TemporaryDirectory() as src_dir:
                source = Path(src_dir) / 'doc.txt'
                source.write_bytes(b'sem senha nenhuma')
                with py7zr.SevenZipFile(path, 'w') as archive:
                    archive.write(source, 'doc.txt')
            with self.assertRaises(CoreError):
                attempt_7z_password(path, ['a'], max_attempts=10, deadline=time.monotonic() + 10)

    def test_not_a_7z_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'notz.7z'
            path.write_bytes(b'not a 7z file at all, just junk bytes')
            with self.assertRaises(CoreError):
                attempt_7z_password(path, ['a'], max_attempts=10, deadline=time.monotonic() + 10)


class SevenZipRecoveryServiceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.scope = root / 'inputs'
        self.scope.mkdir()
        self.core = Core(root / 'state')
        self.addCleanup(self.core.close)
        self.case = self.core.investigate('p', 'Recuperar senha de 7z real', str(self.scope), 'owner', 'auth', recovery=True)
        self.core.set_authorization_basis(self.case, kind='owner_consent', authority='dono', reference='termo', examiner='op', scope_note='arquivo proprio')

    def test_dispatches_to_sevenzip_cracker_and_omits_password_from_audit(self):
        path = self.scope / 'archive.7z'
        _protected_7z(path, 'minha-senha-7z-real')
        out = self.core.recover_password(self.case, str(path), ['nope', 'minha-senha-7z-real'])
        self.assertTrue(out['recovered'])
        self.assertEqual(out['format_id'], '7z')
        self.assertEqual(out['password'], 'minha-senha-7z-real')
        blob = json.dumps(self.core.audit(self.case))
        self.assertNotIn('minha-senha-7z-real', blob)
        self.assertTrue(self.core.verify_audit(self.case))


if __name__ == '__main__':
    unittest.main()
