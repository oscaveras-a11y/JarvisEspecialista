import tempfile
import unittest
from pathlib import Path

from cyber_core.service import Core, CoreError
from cyber_core.investigation.workflow import Workflow


class VerificationStateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        scope = root / 'inputs'
        scope.mkdir()
        self.core = Core(root / 'state')
        self.addCleanup(self.core.close)
        self.flow = Workflow(self.core)
        self.case = self.core.investigate('p', 'Estados de verificação', str(scope), 'owner', 'auth')

    def test_awaiting_information_and_authorization_states_allowed(self):
        for state in ('AGUARDANDO INFORMACOES', 'AGUARDANDO AUTORIZACAO', 'AGUARDANDO RECURSOS'):
            out = self.flow.finalize(self.case, state, actor='op', reason='motivo')
            self.assertEqual(out['state'], state)
            self.assertFalse(out['validated'])  # non-terminal states are not "validated"
            self.assertEqual(self.core.get(self.case)['state'], state)

    def test_unknown_state_still_rejected(self):
        with self.assertRaises(CoreError):
            self.flow.finalize(self.case, 'ESTADO INVENTADO', actor='op', reason='x')

    def test_falha_de_execucao_is_the_seventh_state(self):
        # Regression (PR #9 review): the scope lists 7 states; an earlier fix in
        # this project only reached 6, missing FALHA DE EXECUCAO entirely.
        out = self.flow.finalize(self.case, 'FALHA DE EXECUCAO', actor='op', reason='infra indisponível')
        self.assertEqual(out['state'], 'FALHA DE EXECUCAO')
        self.assertFalse(out['validated'])
        self.assertEqual(self.core.get(self.case)['state'], 'FALHA DE EXECUCAO')

    def test_falha_de_execucao_does_not_require_clean_tasks(self):
        # Unlike RESOLVIDO/SEM SOLUCAO VIAVEL DEMONSTRADA, declaring an execution
        # failure must not itself be blocked by a failed task it describes. A direct
        # failed task row is used (which tool fails on which bytes is an
        # implementation detail of other modules, not what this test verifies).
        from pathlib import Path
        from cyber_core.memory import utc
        scope = Path(self.core.get(self.case)['scope'])
        sample = scope / 'f.bin'
        sample.write_bytes(b'\x00')
        self.core.db.execute('INSERT INTO tasks(id,case_id,tool,path,status,error,created) VALUES(?,?,?,?,?,?,?)',
                             ('deadbeefdeadbeefdeadbeefdeadbeef', self.case, 'analyze-file', str(sample), 'failed', 'infra error', utc()))
        self.core.db.commit()
        self.assertEqual(self.core.tasks(self.case)[0]['status'], 'failed')
        out = self.flow.finalize(self.case, 'FALHA DE EXECUCAO', actor='op', reason='infra indisponível')
        self.assertEqual(out['state'], 'FALHA DE EXECUCAO')

    def test_new_work_reopens_falha_de_execucao(self):
        self.flow.finalize(self.case, 'FALHA DE EXECUCAO', actor='op', reason='motivo')
        from pathlib import Path
        scope = Path(self.core.get(self.case)['scope'])
        sample = scope / 'g.bin'
        sample.write_bytes(b'conteudo')
        self.core.enqueue(self.case, sample)
        self.assertEqual(self.core.get(self.case)['state'], 'EM INVESTIGACAO')


if __name__ == '__main__':
    unittest.main()
