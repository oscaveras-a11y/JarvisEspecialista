import json
import tempfile
import time
import unittest
from pathlib import Path

from cyber_core.service import Core, CoreError
from cyber_core.cryptanalysis.selftest import seal, attempt, MAGIC


class SelfTestUnitTests(unittest.TestCase):
    def test_seal_then_recover_weak_candidate(self):
        env = seal('abc', b'segredo de laboratorio')
        self.assertTrue(env.startswith(MAGIC))
        out = attempt(env, ['x', 'y', 'abc', 'z'], max_attempts=100, deadline=time.monotonic() + 10)
        self.assertTrue(out['recovered'])
        self.assertEqual(out['attempts'], 3)
        self.assertNotIn('passphrase', out)  # never leaks the passphrase

    def test_absent_candidate_not_recovered(self):
        env = seal('senha-forte-ausente', b'dados')
        out = attempt(env, ['a', 'b', 'c'], max_attempts=100, deadline=time.monotonic() + 10)
        self.assertFalse(out['recovered'])
        self.assertEqual(out['status'], 'candidates_exhausted')

    def test_attempt_budget_bounds(self):
        env = seal('zzz', b'dados')
        out = attempt(env, ['a', 'b', 'c', 'zzz'], max_attempts=2, deadline=time.monotonic() + 10)
        self.assertFalse(out['recovered'])
        self.assertEqual(out['status'], 'attempt_budget_exhausted')

    def test_truncated_envelope_rejected(self):
        with self.assertRaises(CoreError):
            attempt(b'CCPW1short', ['a'], max_attempts=10, deadline=time.monotonic() + 10)


class AuthorizationAndSelfTestServiceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.scope = root / 'inputs'
        self.scope.mkdir()
        self.core = Core(root / 'state')
        self.addCleanup(self.core.close)
        self.case = self.core.investigate('p', 'Autoteste de recuperação em arquivo próprio', str(self.scope), 'owner', 'auth')
        self.target = self.scope / 'lab.ccpw1'
        self.target.write_bytes(seal('abc123', b'conteudo de laboratorio proprio'))

    def test_legal_authority_basis_requires_fields(self):
        with self.assertRaises(CoreError):
            self.core.set_authorization_basis(self.case, kind='legal_authority', authority='Vara X',
                                              reference='', examiner='Perito', scope_note='dispositivo A')
        out = self.core.set_authorization_basis(self.case, kind='legal_authority', authority='Vara X',
                                                reference='Proc 123', examiner='Perito', scope_note='dispositivo A')
        self.assertEqual(out['kind'], 'legal_authority')
        self.assertEqual(self.core.authorization_basis(self.case)['reference'], 'Proc 123')

    def test_self_test_requires_owner_consent_basis(self):
        with self.assertRaises(CoreError):
            self.core.self_test_recovery(self.case, str(self.target), ['abc123'])
        # legal_authority is not the self-test basis
        self.core.set_authorization_basis(self.case, kind='legal_authority', authority='a', reference='b', examiner='c', scope_note='d')
        with self.assertRaises(CoreError):
            self.core.self_test_recovery(self.case, str(self.target), ['abc123'])

    def test_self_test_recovers_weak_and_audits_without_secret(self):
        self.core.set_authorization_basis(self.case, kind='owner_consent', authority='dono', reference='termo', examiner='op', scope_note='arquivo proprio')
        out = self.core.self_test_recovery(self.case, str(self.target), ['nope', 'abc123', 'other'])
        self.assertTrue(out['recovered'] and out['recovery_demonstrated'])
        blob = json.dumps(self.core.audit(self.case))
        self.assertNotIn('abc123', blob)  # passphrase never audited

    def test_self_test_strong_absent_is_honest_failure(self):
        self.core.set_authorization_basis(self.case, kind='owner_consent', authority='dono', reference='termo', examiner='op', scope_note='arquivo proprio')
        out = self.core.self_test_recovery(self.case, str(self.target), ['aaa', 'bbb'])
        self.assertFalse(out['recovered'])
        self.assertFalse(out['recovery_demonstrated'])

    def test_make_lab_envelope_then_self_test_end_to_end(self):
        self.core.set_authorization_basis(self.case, kind='owner_consent', authority='dono', reference='termo', examiner='op', scope_note='arquivo proprio')
        made = self.core.make_lab_envelope(self.case, str(self.scope / 'made.ccpw1'), passphrase='senha123', content=b'conteudo de lab')
        self.assertEqual(made['format'], 'CCPW1')
        recovered = self.core.self_test_recovery(self.case, made['path'], ['x', 'senha123', 'y'])
        self.assertTrue(recovered['recovered'])
        self.assertNotIn('senha123', __import__('json').dumps(self.core.audit(self.case)))

    def test_make_lab_envelope_requires_owner_consent_and_no_overwrite(self):
        with self.assertRaises(CoreError):
            self.core.make_lab_envelope(self.case, str(self.scope / 'z.ccpw1'), passphrase='p', content=b'c')
        self.core.set_authorization_basis(self.case, kind='owner_consent', authority='d', reference='t', examiner='o', scope_note='s')
        self.core.make_lab_envelope(self.case, str(self.scope / 'z.ccpw1'), passphrase='p', content=b'c')
        with self.assertRaises(CoreError):  # refuses to overwrite an existing path
            self.core.make_lab_envelope(self.case, str(self.scope / 'z.ccpw1'), passphrase='p', content=b'c')


if __name__ == '__main__':
    unittest.main()
