import json
import tempfile
import time
import unittest
from pathlib import Path

import pikepdf

from cyber_core.service import Core, CoreError
from cyber_core.cryptanalysis.pdf_cracker import attempt_pdf_password


def _protected_pdf(path, user_password, *, owner_password='owner-of-the-lab-pdf', revision=4):
    doc = pikepdf.new()
    doc.add_blank_page()
    doc.save(path, encryption=pikepdf.Encryption(user=user_password, owner=owner_password, R=revision))
    doc.close()


class PdfCrackerUnitTests(unittest.TestCase):
    def test_recovers_known_user_password(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'protected.pdf'
            _protected_pdf(path, 'correct-pdf-password')
            out = attempt_pdf_password(path, ['wrong-1', 'correct-pdf-password', 'wrong-2'],
                                       max_attempts=100, deadline=time.monotonic() + 10)
            self.assertTrue(out['recovered'])
            self.assertEqual(out['attempts'], 2)
            self.assertEqual(out['password'], 'correct-pdf-password')

    def test_owner_password_also_recovers(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'protected.pdf'
            _protected_pdf(path, 'the-user-password', owner_password='the-owner-password')
            out = attempt_pdf_password(path, ['the-owner-password'], max_attempts=10, deadline=time.monotonic() + 10)
            self.assertTrue(out['recovered'])
            self.assertEqual(out['password'], 'the-owner-password')

    def test_aes256_revision_6_also_works(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'protected.pdf'
            _protected_pdf(path, 'aes256-password', revision=6)
            out = attempt_pdf_password(path, ['nope', 'aes256-password'], max_attempts=10, deadline=time.monotonic() + 10)
            self.assertTrue(out['recovered'])
            self.assertEqual(out['password'], 'aes256-password')

    def test_absent_password_is_honest_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'protected.pdf'
            _protected_pdf(path, 'a-strong-absent-password')
            out = attempt_pdf_password(path, ['a', 'b', 'c'], max_attempts=100, deadline=time.monotonic() + 10)
            self.assertFalse(out['recovered'])
            self.assertEqual(out['status'], 'candidates_exhausted')

    def test_attempt_budget_bounds(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'protected.pdf'
            _protected_pdf(path, 'zzz-the-real-one')
            out = attempt_pdf_password(path, ['a', 'b', 'c', 'zzz-the-real-one'],
                                       max_attempts=2, deadline=time.monotonic() + 10)
            self.assertFalse(out['recovered'])
            self.assertEqual(out['status'], 'attempt_budget_exhausted')

    def test_unprotected_pdf_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'plain.pdf'
            doc = pikepdf.new()
            doc.add_blank_page()
            doc.save(path)
            doc.close()
            with self.assertRaises(CoreError):
                attempt_pdf_password(path, ['a'], max_attempts=10, deadline=time.monotonic() + 10)

    def test_not_a_pdf_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'notpdf.bin'
            path.write_bytes(b'%PDF-1.7\nnot actually a real pdf structure')
            with self.assertRaises(CoreError):
                attempt_pdf_password(path, ['a'], max_attempts=10, deadline=time.monotonic() + 10)


class PasswordRecoveryDispatcherServiceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.scope = root / 'inputs'
        self.scope.mkdir()
        self.core = Core(root / 'state')
        self.addCleanup(self.core.close)
        self.case = self.core.investigate('p', 'Recuperar senha real', str(self.scope), 'owner', 'auth', recovery=True)
        self.core.set_authorization_basis(self.case, kind='owner_consent', authority='dono', reference='termo', examiner='op', scope_note='arquivo proprio')

    def test_dispatches_to_pdf_cracker_and_omits_password_from_audit(self):
        path = self.scope / 'doc.pdf'
        _protected_pdf(path, 'minha-senha-pdf-real')
        out = self.core.recover_password(self.case, str(path), ['nope', 'minha-senha-pdf-real'])
        self.assertTrue(out['recovered'])
        self.assertEqual(out['format_id'], 'pdf')
        self.assertEqual(out['password'], 'minha-senha-pdf-real')
        blob = json.dumps(self.core.audit(self.case))
        self.assertNotIn('minha-senha-pdf-real', blob)
        self.assertTrue(self.core.verify_audit(self.case))

    def test_unsupported_format_is_reported_honestly_not_as_wrong_password(self):
        path = self.scope / 'archive.rar'
        path.write_bytes(b'Rar!\x1a\x07\x01\x00' + b'\x00' * 32)
        out = self.core.recover_password(self.case, str(path), ['anything'])
        self.assertFalse(out['recovered'])
        self.assertEqual(out['status'], 'unsupported_format')
        self.assertEqual(out['format_id'], 'rar5')
        self.assertIn('not yet supported', out['note'])


if __name__ == '__main__':
    unittest.main()
