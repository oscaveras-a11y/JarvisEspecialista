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


if __name__ == '__main__':
    unittest.main()
