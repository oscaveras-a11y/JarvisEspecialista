import hashlib
from pathlib import Path
import tempfile
import unittest
from cyber_core.errors import CoreError
from cyber_core.investigation.workflow import Workflow
from cyber_core.service import Core


class ScientificWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.inputs = self.root / 'inputs'
        self.inputs.mkdir()
        self.source = self.inputs / 'control.bin'
        self.source.write_bytes(b'\x7fELF' + bytes(range(256)))
        self.core = Core(self.root / 'state')
        self.addCleanup(self.core.close)
        self.case = self.core.investigate('lab', 'Verify known control', str(self.inputs), 'owner', 'Authorized synthetic investigation')
        self.flow = Workflow(self.core)

    def plan(self):
        hypothesis = self.flow.add_hypothesis(self.case, 'Control matches known bytes', author='analyst', plausibility=.7)
        digest = hashlib.sha256(self.source.read_bytes()).hexdigest()
        experiment = self.flow.plan_experiment(self.case, hypothesis, 'Hash and copy check', author='analyst',
                                               criterion='Both known hash and verified copy must match',
                                               assertions=[{'field': 'sha256', 'op': 'eq', 'value': digest},
                                                           {'field': 'copy_verified', 'op': 'eq', 'value': True}],
                                               tool='analyze-file')
        task = self.core.enqueue(self.case, self.source)
        self.core.run_one(self.case, task_id=task)
        return hypothesis, experiment, task

    def reviewed(self):
        hypothesis, experiment, task = self.plan()
        run = self.flow.evaluate(self.case, experiment, task, operator='analyst')
        self.flow.review(self.case, run['id'], reviewer='independent-reviewer', decision='accepted', reason='Recomputed control SHA and inspected verified evidence')
        return hypothesis, experiment, task, run

    def test_solution_requires_real_result_and_independent_review(self):
        _, experiment, task = self.plan()
        with self.assertRaises(CoreError):
            self.flow.finalize(self.case, 'RESOLVIDO', actor='owner', reason='Agent said so')
        run = self.flow.evaluate(self.case, experiment, task, operator='analyst')
        self.assertEqual(run['outcome'], 'supports')
        with self.assertRaises(CoreError):
            self.flow.finalize(self.case, 'RESOLVIDO', actor='owner', reason='Unreviewed result')
        self.flow.review(self.case, run['id'], reviewer='reviewer', decision='accepted', reason='Reproduced hash')
        verdict = self.flow.finalize(self.case, 'RESOLVIDO', actor='owner', reason='Known synthetic hash demonstrated')
        self.assertTrue(verdict['validated'])
        self.assertEqual(self.core.get(self.case)['state'], 'RESOLVIDO')

    def test_same_author_cannot_self_review(self):
        _, experiment, task = self.plan()
        run = self.flow.evaluate(self.case, experiment, task, operator='analyst')
        with self.assertRaises(CoreError):
            self.flow.review(self.case, run['id'], reviewer=' ANALYST ', decision='accepted', reason='self')

    def test_same_evidence_does_not_count_as_new_progress(self):
        _, experiment, task = self.plan()
        self.flow.evaluate(self.case, experiment, task, operator='analyst')
        duplicate = self.core.enqueue(self.case, self.source)
        self.core.run_one(self.case, duplicate)
        with self.assertRaisesRegex(CoreError, 'Repeat'):
            self.flow.evaluate(self.case, experiment, duplicate, operator='analyst')

    def test_same_paired_inputs_do_not_count_as_new_progress(self):
        first, second = self.inputs / 'first.bin', self.inputs / 'second.bin'
        first.write_bytes(b'abc'); second.write_bytes(b'axc')
        hypothesis = self.flow.add_hypothesis(self.case, 'One byte changed', author='a', plausibility=.5)
        experiment = self.flow.plan_experiment(self.case, hypothesis, 'Compare pair', author='a', criterion='One difference',
                                              assertions=[{'field': 'firmware_comparison.differing_bytes', 'op': 'eq', 'value': 1}], tool='analyze-firmware')
        for index in range(2):
            task = self.core.enqueue(self.case, first, tool='analyze-firmware', second_path=second)
            self.core.run_one(self.case, task)
            if index == 0:
                self.flow.evaluate(self.case, experiment, task, operator='a')
            else:
                with self.assertRaisesRegex(CoreError, 'Repeat'):
                    self.flow.evaluate(self.case, experiment, task, operator='a')

    def test_paired_secondary_copy_is_also_verified(self):
        second = self.inputs / 'second.bin'
        first = self.inputs / 'first.bin'
        first.write_bytes(b'abc'); second.write_bytes(b'axc')
        hypothesis = self.flow.add_hypothesis(self.case, 'Second control has three bytes', author='a', plausibility=.5)
        experiment = self.flow.plan_experiment(self.case, hypothesis, 'Secondary size', author='a', criterion='Three verified bytes',
                                              assertions=[{'field': 'secondary.size', 'op': 'eq', 'value': 3}], tool='analyze-firmware')
        task = self.core.enqueue(self.case, first, tool='analyze-firmware', second_path=second)
        result = self.core.run_one(self.case, task)
        Path(result['secondary']['copy']).write_bytes(b'bad')
        with self.assertRaises(CoreError):
            self.flow.evaluate(self.case, experiment, task, operator='a')

    def test_tampered_copy_cannot_be_evidence(self):
        _, experiment, task = self.plan()
        evidence = Path(self.core.results(self.case)[0]['copy'])
        evidence.write_bytes(b'tampered')
        with self.assertRaises(CoreError):
            self.flow.evaluate(self.case, experiment, task, operator='analyst')

    def test_reviewed_evidence_rechecked_at_finalization(self):
        self.reviewed()
        evidence = Path(self.core.results(self.case)[0]['copy'])
        evidence.write_bytes(b'tampered')
        with self.assertRaises(CoreError):
            self.flow.finalize(self.case, 'RESOLVIDO', actor='owner', reason='Stale review')

    def test_hypothesis_revision_invalidates_prior_review(self):
        hypothesis, _, _, _ = self.reviewed()
        self.flow.revise_hypothesis(self.case, hypothesis, author='analyst', plausibility=.8, reason='New interpretation')
        with self.assertRaises(CoreError):
            self.flow.finalize(self.case, 'RESOLVIDO', actor='owner', reason='Cannot reuse prior revision review')
        self.assertEqual(len(self.flow.history(self.case, hypothesis)), 2)

    def test_case_isolation(self):
        _, experiment, task = self.plan()
        other = self.core.investigate('other', 'other', str(self.inputs), 'owner', 'authorized')
        with self.assertRaises(CoreError):
            self.flow.evaluate(other, experiment, task, operator='analyst')

    def test_unreviewed_contrary_run_blocks_resolution(self):
        _, experiment, _, _ = self.reviewed()
        self.source.write_bytes(b'new contrary evidence')
        task = self.core.enqueue(self.case, self.source)
        self.core.run_one(self.case, task)
        self.assertEqual(self.flow.evaluate(self.case, experiment, task, operator='analyst')['outcome'], 'refutes')
        with self.assertRaises(CoreError):
            self.flow.finalize(self.case, 'RESOLVIDO', actor='owner', reason='Unreviewed contrary run remains')

    def test_supported_solutions_cannot_be_labelled_no_viable_solution(self):
        hypothesis, _, task, _ = self.reviewed()
        experiment = self.flow.plan_experiment(self.case, hypothesis, 'Independent size condition', author='analyst', criterion='260 bytes',
                                               assertions=[{'field': 'size', 'op': 'eq', 'value': 260}], tool='analyze-file')
        run = self.flow.evaluate(self.case, experiment, task, operator='analyst')
        self.flow.review(self.case, run['id'], reviewer='reviewer', decision='accepted', reason='Rechecked exact size')
        with self.assertRaises(CoreError):
            self.flow.finalize(self.case, 'SEM SOLUCAO VIAVEL DEMONSTRADA', actor='owner', reason='Contradicts supported conditions')

    def test_pending_tasks_block_resolution(self):
        self.reviewed()
        self.core.enqueue(self.case, self.source)
        with self.assertRaises(CoreError):
            self.flow.finalize(self.case, 'RESOLVIDO', actor='owner', reason='Queue remains')

    def test_new_work_reopens_a_resolved_case(self):
        self.reviewed()
        self.flow.finalize(self.case, 'RESOLVIDO', actor='owner', reason='Validated')
        self.core.enqueue(self.case, self.source)
        self.assertEqual(self.core.get(self.case)['state'], 'EM INVESTIGACAO')

    def test_failed_assertion_refutes_instead_of_claiming_success(self):
        hypothesis = self.flow.add_hypothesis(self.case, 'File is empty', author='a', plausibility=.3)
        experiment = self.flow.plan_experiment(self.case, hypothesis, 'Measure size', author='a', criterion='Zero bytes',
                                               assertions=[{'field': 'size', 'op': 'eq', 'value': 0}], tool='analyze-file')
        task = self.core.enqueue(self.case, self.source)
        self.core.run_one(self.case, task)
        run = self.flow.evaluate(self.case, experiment, task, operator='a')
        self.assertEqual(run['outcome'], 'refutes')
        self.flow.review(self.case, run['id'], reviewer='b', decision='accepted', reason='Confirmed nonempty evidence')
        with self.assertRaises(CoreError):
            self.flow.finalize(self.case, 'RESOLVIDO', actor='owner', reason='Refutation is not a demonstrated solution')

    def test_no_viable_solution_requires_more_than_first_failed_strategy(self):
        with self.assertRaises(CoreError):
            self.flow.finalize(self.case, 'SEM SOLUCAO VIAVEL DEMONSTRADA', actor='owner', reason='First strategy failed')
        result = self.flow.finalize(self.case, 'AGUARDANDO RECURSOS', actor='owner', reason='Need a format-specific control and independent review')
        self.assertFalse(result['validated'])

    def test_invalid_assertion_is_not_executable(self):
        hypothesis = self.flow.add_hypothesis(self.case, 'test', author='a', plausibility=.5)
        with self.assertRaises(CoreError):
            self.flow.plan_experiment(self.case, hypothesis, 'bad', author='a', criterion='bad', tool='analyze-file',
                                      assertions=[{'field': '__class__.__subclasses__', 'op': 'execute', 'value': 'cmd'}])

    def test_nonfinite_plausibility_rejected(self):
        for value in (float('nan'), float('inf'), -1, 2):
            with self.subTest(value=value), self.assertRaises(CoreError):
                self.flow.add_hypothesis(self.case, 'x', author='a', plausibility=value)

    def test_sources_and_history_search(self):
        source = self.flow.add_source(self.case, title='Official control format', url='https://example.org/spec', version='1.0',
                                      provenance='documented', author='analyst')
        self.assertTrue(source)
        matches = self.flow.search('control', project='lab')
        self.assertEqual(matches[0]['id'], self.case)
        self.assertFalse(self.flow.search('control', project='another-client'))
        self.assertEqual(self.flow.snapshot(self.case)['sources'][0]['provenance'], 'documented')

    def test_missing_observation_is_inconclusive_not_a_refutation(self):
        hypothesis = self.flow.add_hypothesis(self.case, 'Unknown architecture', author='a', plausibility=.5)
        experiment = self.flow.plan_experiment(self.case, hypothesis, 'Architecture check', author='a', criterion='Observe a parsed architecture',
                                               assertions=[{'field': 'firmware.metadata.machine', 'op': 'eq', 'value': 40}], tool='analyze-file')
        task = self.core.enqueue(self.case, self.source)
        self.core.run_one(self.case, task)
        self.assertEqual(self.flow.evaluate(self.case, experiment, task, operator='a')['outcome'], 'inconclusive')

    def test_new_task_during_final_verification_invalidates_snapshot(self):
        self.reviewed()
        from unittest.mock import patch
        from cyber_core.investigation import workflow
        original = workflow.verified_result

        def with_new_work(*args, **kwargs):
            result = original(*args, **kwargs)
            self.core.enqueue(self.case, self.source)
            return result

        with patch.object(workflow, 'verified_result', side_effect=with_new_work):
            with self.assertRaises(CoreError):
                self.flow.finalize(self.case, 'RESOLVIDO', actor='owner', reason='Concurrent evidence')
        self.assertEqual(self.core.get(self.case)['state'], 'EM INVESTIGACAO')

    def test_result_claim_must_match_audited_acquisition(self):
        _, experiment, task = self.plan()
        import json
        row = self.core.db.execute('SELECT data FROM results WHERE task_id=?', (task,)).fetchone()
        changed = json.loads(row['data'])
        changed['sha256'] = '0' * 64
        self.core.db.execute('UPDATE results SET data=? WHERE task_id=?', (json.dumps(changed), task))
        self.core.db.commit()
        with self.assertRaises(CoreError):
            self.flow.evaluate(self.case, experiment, task, operator='a')
