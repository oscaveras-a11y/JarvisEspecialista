import tempfile
import unittest
from pathlib import Path

from cyber_core.service import Core, CoreError
from cyber_core.planning import classify_investigation, select_tool, build_plan, TOOLS


class PlanningUnitTests(unittest.TestCase):
    def test_classify_by_objective_keywords(self):
        self.assertEqual(classify_investigation('Analisar firmware .bin de uma ECU')['type'], 'firmware')
        self.assertEqual(classify_investigation('Triagem de arquivo criptografado, recuperar senha')['type'], 'crypto')
        self.assertEqual(classify_investigation('Perícia forense com linha do tempo e cadeia de custódia')['type'], 'forensics')
        self.assertEqual(classify_investigation('Capturar e comparar mensagens do barramento CAN')['type'], 'automotive')

    def test_classify_generic_when_no_signal(self):
        result = classify_investigation('Objetivo sem palavras técnicas específicas')
        self.assertEqual(result['type'], 'generic')
        self.assertEqual(result['confidence'], 0.0)
        self.assertEqual(result['signals'], [])

    def test_observed_format_reinforces_type(self):
        result = classify_investigation('objetivo neutro', observed_format='CYBER CORE AES-GCM envelope')
        self.assertEqual(result['type'], 'crypto')

    def test_empty_objective_rejected(self):
        with self.assertRaises(CoreError):
            classify_investigation('   ')

    def test_select_tool_stays_in_allowlist(self):
        for kind in ('firmware', 'automotive', 'crypto', 'forensics', 'vulnerability', 'generic'):
            self.assertIn(select_tool(kind)['tool'], TOOLS)

    def test_select_tool_rejects_tool_outside_available(self):
        with self.assertRaises(CoreError):
            select_tool('firmware', available=('analyze-file',))

    def test_build_plan_is_ordered_and_tooled(self):
        steps = build_plan('crypto')
        self.assertGreaterEqual(len(steps), 2)
        for step in steps:
            self.assertIn(step['candidate_tool'], TOOLS)
            self.assertTrue(step['goal'] and step['success_criterion'])


class PlanningServiceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        scope = root / 'inputs'
        scope.mkdir()
        self.core = Core(root / 'state')
        self.addCleanup(self.core.close)
        self.case = self.core.investigate('p', 'Recuperar senha de arquivo criptografado AES', str(scope), 'owner', 'auth')

    def test_classify_persists_and_is_audited(self):
        result = self.core.classify(self.case)
        self.assertEqual(result['type'], 'crypto')
        stored = self.core.db.execute('SELECT type FROM investigation_type WHERE case_id=?', (self.case,)).fetchone()
        self.assertEqual(stored['type'], 'crypto')
        self.assertTrue(any(e['event'] == 'investigation_classified' for e in self.core.audit(self.case)))
        self.assertTrue(self.core.verify_audit(self.case))

    def test_plan_creates_ordered_steps(self):
        out = self.core.plan(self.case)
        self.assertEqual(out['type'], 'crypto')
        plans = self.core.plans(self.case)
        self.assertEqual(len(plans), 1)
        ordinals = [s['ordinal'] for s in plans[0]['steps']]
        self.assertEqual(ordinals, sorted(ordinals))
        self.assertTrue(self.core.verify_audit(self.case))

    def test_plan_reclassifies_only_once(self):
        self.core.classify(self.case)
        self.core.plan(self.case)
        rows = self.core.db.execute('SELECT COUNT(*) AS c FROM investigation_type WHERE case_id=?', (self.case,)).fetchone()
        self.assertEqual(rows['c'], 1)

    def test_cancelled_case_rejects_planning(self):
        self.core.cancel(self.case, reason='test')
        with self.assertRaises(CoreError):
            self.core.plan(self.case)


if __name__ == '__main__':
    unittest.main()
