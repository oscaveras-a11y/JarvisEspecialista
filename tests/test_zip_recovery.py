import json
import tempfile
import time
import unittest
import zipfile
from pathlib import Path

from cyber_core.service import Core, CoreError
from cyber_core.cryptanalysis.zip_cracker import attempt_zip_password


class ZipCrackerUnitTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import shutil
        cls.zip_tool = shutil.which('zip')

    def _make_protected_zip(self, directory, password, *, name='doc.txt', content=b'conteudo protegido de teste'):
        import subprocess
        source = directory / name
        source.write_bytes(content)
        archive = directory / 'protected.zip'
        subprocess.run(['zip', '-q', '-e', '-P', password, str(archive), '-j', str(source)],
                       check=True, capture_output=True)
        return archive

    def test_recovers_known_password_and_reports_member(self):
        if not self.zip_tool:
            self.skipTest('zip CLI not available in this environment')
        with tempfile.TemporaryDirectory() as tmp:
            archive = self._make_protected_zip(Path(tmp), 'correct-horse-42')
            out = attempt_zip_password(archive, ['wrong-1', 'correct-horse-42', 'wrong-2'],
                                       max_attempts=100, deadline=time.monotonic() + 10)
            self.assertTrue(out['recovered'])
            self.assertEqual(out['attempts'], 2)
            self.assertEqual(out['password'], 'correct-horse-42')
            self.assertEqual(out['member'], 'doc.txt')

    def test_absent_password_is_honest_failure(self):
        if not self.zip_tool:
            self.skipTest('zip CLI not available in this environment')
        with tempfile.TemporaryDirectory() as tmp:
            archive = self._make_protected_zip(Path(tmp), 'a-strong-absent-password')
            out = attempt_zip_password(archive, ['a', 'b', 'c'], max_attempts=100, deadline=time.monotonic() + 10)
            self.assertFalse(out['recovered'])
            self.assertEqual(out['status'], 'candidates_exhausted')

    def test_attempt_budget_bounds(self):
        if not self.zip_tool:
            self.skipTest('zip CLI not available in this environment')
        with tempfile.TemporaryDirectory() as tmp:
            archive = self._make_protected_zip(Path(tmp), 'zzz-the-real-one')
            out = attempt_zip_password(archive, ['a', 'b', 'c', 'zzz-the-real-one'],
                                       max_attempts=2, deadline=time.monotonic() + 10)
            self.assertFalse(out['recovered'])
            self.assertEqual(out['status'], 'attempt_budget_exhausted')

    def test_unprotected_zip_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'plain.zip'
            with zipfile.ZipFile(path, 'w') as archive:
                archive.writestr('a.txt', b'sem senha nenhuma')
            with self.assertRaises(CoreError):
                attempt_zip_password(path, ['a'], max_attempts=10, deadline=time.monotonic() + 10)

    def test_not_a_zip_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'notzip.bin'
            path.write_bytes(b'not a zip file at all')
            with self.assertRaises(CoreError):
                attempt_zip_password(path, ['a'], max_attempts=10, deadline=time.monotonic() + 10)


class ZipRecoveryServiceTests(unittest.TestCase):
    def setUp(self):
        import shutil
        self.zip_tool = shutil.which('zip')
        if not self.zip_tool:
            self.skipTest('zip CLI not available in this environment')
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.scope = root / 'inputs'
        self.scope.mkdir()
        self.core = Core(root / 'state')
        self.addCleanup(self.core.close)
        self.case = self.core.investigate('p', 'Recuperar senha de ZIP próprio', str(self.scope), 'owner', 'auth', recovery=True)
        import subprocess
        source = self.scope / 'doc.txt'
        source.write_bytes(b'conteudo autorizado de teste')
        self.archive = self.scope / 'protected.zip'
        subprocess.run(['zip', '-q', '-e', '-P', 'minha-senha-real', str(self.archive), '-j', str(source)],
                       check=True, capture_output=True)

    def test_requires_owner_consent_basis(self):
        with self.assertRaises(CoreError):
            self.core.recover_zip_password(self.case, str(self.archive), ['minha-senha-real'])
        self.core.set_authorization_basis(self.case, kind='legal_authority', authority='a', reference='b', examiner='c', scope_note='d')
        with self.assertRaises(CoreError):
            self.core.recover_zip_password(self.case, str(self.archive), ['minha-senha-real'])

    def test_recovers_and_returns_password_without_auditing_it(self):
        self.core.set_authorization_basis(self.case, kind='owner_consent', authority='dono', reference='termo', examiner='op', scope_note='arquivo proprio')
        out = self.core.recover_zip_password(self.case, str(self.archive), ['nope', 'minha-senha-real', 'other'])
        self.assertTrue(out['recovered'])
        self.assertEqual(out['password'], 'minha-senha-real')
        blob = json.dumps(self.core.audit(self.case))
        self.assertNotIn('minha-senha-real', blob)
        self.assertTrue(self.core.verify_audit(self.case))

    def test_rejects_while_paused(self):
        self.core.set_authorization_basis(self.case, kind='owner_consent', authority='dono', reference='termo', examiner='op', scope_note='arquivo proprio')
        self.core.pause(self.case)
        with self.assertRaises(CoreError):
            self.core.recover_zip_password(self.case, str(self.archive), ['minha-senha-real'])

    def test_rejects_without_recovery_allowed(self):
        case = self.core.investigate('p2', 'Sem permissao de recuperacao', str(self.scope), 'owner', 'auth', recovery=False)
        self.core.set_authorization_basis(case, kind='owner_consent', authority='dono', reference='termo', examiner='op', scope_note='arquivo proprio')
        with self.assertRaises(CoreError):
            self.core.recover_zip_password(case, str(self.archive), ['minha-senha-real'])


if __name__ == '__main__':
    unittest.main()
