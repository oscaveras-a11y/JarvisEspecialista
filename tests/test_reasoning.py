"""Item 4: synthetic, real monitored analyses and persistent scientific records."""
import hashlib
import json
import math
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from cyber_core.errors import CoreError
from cyber_core.service import Core
from cyber_core.investigation.workflow import Workflow
from cyber_core.investigation.reasoning import Reasoning


class ReasoningTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.inputs = self.root / 'inputs'
        self.inputs.mkdir()
        self.source = self.inputs / 'control.bin'
        self.source.write_bytes(b'abc')
        self.home = self.root / 'state'
        self.core = Core(self.home)
        self.addCleanup(self.core.close)
        self.case = self.core.investigate('item4', 'Identify and validate synthetic control',
                                          str(self.inputs), 'owner', 'Synthetic lab')
        self.flow = Workflow(self.core)
        self.engine = Reasoning(self.core)

    def strategy(self, value=3, *, plausibility=.5, cost=1, risk=0, alternative_to=None):
        hypothesis = self.flow.add_hypothesis(self.case, 'Control size is ' + str(value),
                                              author='analyst', plausibility=plausibility)
        experiment = self.flow.plan_experiment(self.case, hypothesis, 'Measure control',
                                               author='analyst', criterion='Size matches declared control',
                                               assertions=[{'field': 'size', 'op': 'eq', 'value': value}],
                                               tool='analyze-file')
        strategy = self.engine.register(self.case, experiment, actor='analyst', cost=cost, risk=risk,
                                        alternative_to=alternative_to, rationale='Falsifiable synthetic test')
        return strategy, hypothesis, experiment

    def test_rank_uses_declared_cost_risk_plausibility_and_verified_evidence(self):
        first, _, _ = self.strategy(cost=10, plausibility=.2)
        second, _, _ = self.strategy(cost=0, plausibility=.8)
        ranking = self.engine.rank(self.case)
        self.assertEqual(ranking[0]['id'], second)
        self.assertLess(ranking[1]['score'], ranking[0]['score'])
        self.assertTrue(all(r['eligible'] for r in ranking))
        self.assertEqual({r['id'] for r in ranking}, {first, second})

    def test_step_runs_real_child_evaluates_and_requires_review(self):
        strategy, _, _ = self.strategy()
        out = self.engine.step(self.case, self.source, actor='operator')
        self.assertEqual(out['status'], 'evaluated')
        self.assertEqual(out['run']['outcome'], 'supports')
        self.assertEqual(self.core.get(self.case)['state'], 'EM INVESTIGACAO')
        self.assertEqual(self.engine.rank(self.case)[0]['status'], 'awaiting_review')
        self.assertTrue(any(e['event'] == 'analysis_process_started' for e in self.core.audit(self.case)))
        self.assertTrue(self.core.verify_audit(self.case))
        self.assertEqual(len(self.core.results(self.case)), 1)

    def test_accepted_refutation_unlocks_declared_alternative(self):
        first, _, _ = self.strategy(value=99)
        alternative, _, _ = self.strategy(value=3, alternative_to=first)
        self.assertFalse(next(r for r in self.engine.rank(self.case) if r['id'] == alternative)['eligible'])
        out = self.engine.step(self.case, self.source, actor='operator')
        self.assertEqual(out['run']['outcome'], 'refutes')
        self.assertFalse(next(r for r in self.engine.rank(self.case) if r['id'] == alternative)['eligible'])
        self.flow.review(self.case, out['run']['id'], reviewer='reviewer', decision='accepted', reason='Size independently checked')
        ranking = self.engine.rank(self.case)
        self.assertEqual(next(r for r in ranking if r['id'] == first)['status'], 'refuted')
        self.assertTrue(next(r for r in ranking if r['id'] == alternative)['eligible'])
        next_out = self.engine.step(self.case, self.source, actor='operator')
        self.assertEqual(next_out['run']['outcome'], 'supports')
        self.assertEqual(len(self.core.results(self.case)), 2)

    def test_blockers_are_specific_and_resolution_does_not_grant_permission(self):
        strategy, _, _ = self.strategy()
        blocker = self.engine.block(self.case, strategy, kind='data', detail='Missing control metadata', actor='analyst')
        self.assertFalse(self.engine.rank(self.case)[0]['eligible'])
        self.assertEqual(self.engine.step(self.case, self.source, actor='operator')['status'], 'blocked')
        self.assertFalse(self.core.tasks(self.case))
        self.engine.unblock(self.case, blocker, reason='Control metadata supplied', actor='analyst')
        self.assertTrue(self.engine.rank(self.case)[0]['eligible'])
        self.core.revoke(self.case)
        with self.assertRaises(CoreError):
            self.engine.step(self.case, self.source, actor='operator')

    def test_full_risk_blocks_automatic_execution(self):
        self.strategy(risk=1)
        self.assertEqual(self.engine.step(self.case, self.source, actor='operator')['status'], 'blocked')
        self.assertFalse(self.core.tasks(self.case))

    def test_invalid_metrics_and_unknown_references_are_rejected(self):
        _, _, experiment = self.strategy()
        for metrics in ({'cost': -1}, {'risk': 1.1}, {'cost': True}, {'cost': math.inf}, {'risk': math.nan}):
            with self.subTest(metrics=metrics), self.assertRaises(CoreError):
                self.engine.register(self.case, experiment, actor='analyst', rationale='x', **metrics)
        with self.assertRaises(CoreError):
            self.engine.register(self.case, 'missing', actor='a', rationale='x')
        with self.assertRaises(CoreError):
            self.engine.note(self.case, 'FACT', 'Invented discovery', actor='agent')

    def test_source_and_evidence_links_are_checked_and_kept_in_snapshot(self):
        task = self.core.enqueue(self.case, self.source)
        self.core.run_one(self.case, task)
        source = self.flow.add_source(self.case, title='Synthetic reference', url='https://example.org/spec',
                                     version='1', provenance='documented', author='analyst')
        hypothesis = self.flow.add_hypothesis(self.case, 'Control has three bytes', author='a')
        experiment = self.flow.plan_experiment(self.case, hypothesis, 'Size', author='a', criterion='Three bytes',
                                               assertions=[{'field': 'size', 'op': 'eq', 'value': 3}], tool='analyze-file')
        strategy = self.engine.register(self.case, experiment, actor='a', rationale='Referenced test',
                                        evidence=[task], sources=[source])
        snap = self.engine.snapshot(self.case)
        self.assertEqual(snap['contract_version'], 1)
        self.assertEqual(snap['facts'][0]['sha256'], hashlib.sha256(b'abc').hexdigest())
        self.assertEqual(snap['strategies'][0]['sources'], [source])
        self.assertEqual(snap['strategies'][0]['evidence'], [task])
        self.assertEqual(snap['strategies'][0]['id'], strategy)
        self.assertNotIn('copy', snap['facts'][0])

    def test_tampered_evidence_cannot_raise_priority_or_become_fact(self):
        task = self.core.enqueue(self.case, self.source)
        result = self.core.run_one(self.case, task)
        _, _, experiment = self.strategy()
        Path(result['copy']).write_bytes(b'tampered')
        with self.assertRaises(CoreError):
            self.engine.register(self.case, experiment, actor='a', rationale='bad', evidence=[task])
        with self.assertRaises(CoreError):
            self.engine.snapshot(self.case)

    def test_inference_unknown_and_hypothesis_remain_distinct(self):
        self.strategy()
        self.engine.note(self.case, 'INFERENCE', 'May contain structured data', actor='analyst')
        self.engine.note(self.case, 'UNKNOWN', 'Hardware family is not supplied', actor='analyst')
        snapshot = self.engine.snapshot(self.case)
        self.assertEqual(len(snapshot['inferences']), 1)
        self.assertTrue(any(n['statement'] == 'Hardware family is not supplied' for n in snapshot['unknowns']))
        self.assertEqual(len(snapshot['hypotheses']), 1)
        self.assertFalse(snapshot['facts'])

    def test_scope_and_cancelled_case_reject_execution(self):
        self.strategy()
        outside = self.root / 'outside.bin'
        outside.write_bytes(b'private')
        with self.assertRaises(CoreError):
            self.engine.step(self.case, outside, actor='operator')
        self.assertFalse(self.core.tasks(self.case))
        self.core.cancel(self.case, reason='Stop')
        with self.assertRaises(CoreError):
            self.engine.step(self.case, self.source, actor='operator')

    def test_pause_does_not_queue_work(self):
        self.strategy()
        self.core.pause(self.case)
        with self.assertRaises(CoreError):
            self.engine.step(self.case, self.source, actor='operator')
        self.assertFalse(self.core.tasks(self.case))

    def test_cross_case_references_are_rejected(self):
        _, _, experiment = self.strategy()
        other = self.core.investigate('other', 'other', str(self.inputs), 'owner', 'lab')
        with self.assertRaises(CoreError):
            self.engine.register(other, experiment, actor='a', rationale='bad')
        strategy, _, _ = self.strategy()
        with self.assertRaises(CoreError):
            self.engine.block(other, strategy, kind='data', detail='bad', actor='a')

    def test_restart_preserves_strategy_and_does_not_repeat_evaluated_input(self):
        self.strategy()
        first = self.engine.step(self.case, self.source, actor='operator')
        other = Core(self.home)
        self.addCleanup(other.close)
        engine = Reasoning(other)
        out = engine.step(self.case, self.source, actor='operator')
        self.assertIn(out['status'], ('waiting_review', 'repeated'))
        self.assertEqual(len(other.tasks(self.case)), 1)
        self.assertEqual(engine.snapshot(self.case)['cycles'][0]['task_id'], first['task'])

    def test_interruption_before_acquisition_resumes_same_task(self):
        self.strategy()
        with patch.object(self.core, 'run_one', side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                self.engine.step(self.case, self.source, actor='operator')
        self.assertEqual(len(self.core.tasks(self.case)), 1)
        out = Reasoning(self.core).step(self.case, self.source, actor='operator')
        self.assertEqual(out['run']['outcome'], 'supports')
        self.assertEqual(len(self.core.tasks(self.case)), 1)

    def test_interruption_after_evaluation_reuses_record_without_new_task(self):
        self.strategy()
        real_evaluate = self.engine.flow.evaluate
        def after_commit(*args, **kwargs):
            real_evaluate(*args, **kwargs)
            raise KeyboardInterrupt
        with patch.object(self.engine.flow, 'evaluate', side_effect=after_commit):
            with self.assertRaises(KeyboardInterrupt):
                self.engine.step(self.case, self.source, actor='operator')
        out = Reasoning(self.core).step(self.case, self.source, actor='operator')
        self.assertEqual(out['status'], 'evaluated')
        self.assertEqual(len(self.core.tasks(self.case)), 1)
        self.assertEqual(len(self.flow.snapshot(self.case)['runs']), 1)

    def test_hypothesis_change_during_acquisition_does_not_publish_new_revision_run(self):
        self.strategy()
        real = self.core.run_one
        def changed(*args, **kwargs):
            result = real(*args, **kwargs)
            hypothesis = self.flow.snapshot(self.case)['hypotheses'][0]['id']
            self.flow.revise_hypothesis(self.case, hypothesis, author='analyst', plausibility=.6, reason='Changed during acquisition')
            return result
        with patch.object(self.core, 'run_one', side_effect=changed):
            out = self.engine.step(self.case, self.source, actor='operator')
        self.assertEqual(out['status'], 'stale')
        self.assertFalse(self.flow.snapshot(self.case)['runs'])

    def test_bounded_run_stops_for_review_without_claiming_solution(self):
        self.strategy()
        out = self.engine.run(self.case, self.source, actor='operator', max_steps=3, max_seconds=20)
        self.assertEqual(len([s for s in out['steps'] if s['status'] == 'evaluated']), 1)
        self.assertEqual(out['stopped'], 'waiting_review')
        self.assertEqual(self.core.get(self.case)['state'], 'EM INVESTIGACAO')

    def test_invalid_run_limits_are_rejected_without_work(self):
        self.strategy()
        for kwargs in ({'max_steps': 0}, {'max_steps': True}, {'max_seconds': math.nan}, {'max_seconds': -1}):
            with self.subTest(kwargs=kwargs), self.assertRaises(CoreError):
                self.engine.run(self.case, self.source, actor='operator', **kwargs)
        self.assertFalse(self.core.tasks(self.case))

    def test_report_contains_reasoning_without_execution_or_fake_resolution(self):
        self.strategy()
        self.engine.note(self.case, 'UNKNOWN', 'Missing hardware', actor='analyst')
        report = self.core.report(self.case).read_text(encoding='utf-8')
        self.assertIn('contract_version', report)
        self.assertIn('Missing hardware', report)
        self.assertIn('EM INVESTIGACAO', report)
        self.assertFalse(self.core.tasks(self.case))

    def test_extension_preserves_global_schema_version_and_existing_audit(self):
        version = self.core.db.execute('PRAGMA user_version').fetchone()[0]
        self.strategy()
        Reasoning(self.core)
        self.assertEqual(self.core.db.execute('PRAGMA user_version').fetchone()[0], version)
        self.assertTrue(self.core.verify_audit(self.case))

    def test_two_connections_share_one_reservation_and_one_result(self):
        self.strategy()
        errors, outcomes = [], []
        barrier = threading.Barrier(2)
        def worker():
            core = Core(self.home)
            try:
                engine = Reasoning(core)
                barrier.wait(timeout=10)
                outcomes.append(engine.step(self.case, self.source, actor='operator'))
            except BaseException as exc:
                errors.append(exc)
            finally:
                core.close()
        workers = [threading.Thread(target=worker) for _ in range(2)]
        for worker in workers: worker.start()
        for worker in workers: worker.join(timeout=30)
        self.assertTrue(all(not worker.is_alive() for worker in workers))
        self.assertFalse(errors, repr(errors))
        self.assertEqual(len(self.core.tasks(self.case)), 1)
        self.assertEqual(len(self.core.results(self.case)), 1)
        self.assertEqual(len(self.flow.snapshot(self.case)['runs']), 1)
        self.assertTrue(self.core.verify_audit(self.case))

    def test_cli_rank_and_cycle_use_the_same_persistent_contract(self):
        self.strategy()
        base = [sys.executable, '-m', 'cyber_core', '--home', str(self.home), 'experiment']
        ranked = subprocess.run(base + ['rank', self.case], capture_output=True, text=True, timeout=20)
        self.assertEqual(ranked.returncode, 0, ranked.stderr)
        self.assertEqual(len(json.loads(ranked.stdout)), 1)
        run = subprocess.run(base + ['cycle', self.case, str(self.source), '--operator', 'operator', '--max-steps', '1'],
                             capture_output=True, text=True, timeout=30)
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(json.loads(run.stdout)['steps'][0]['status'], 'evaluated')


    def test_new_blocker_prevents_reserved_task_from_starting_after_restart(self):
        strategy, _, _ = self.strategy()
        with patch.object(self.core, 'run_one', side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                self.engine.step(self.case, self.source, actor='operator')
        blocker = self.engine.block(self.case, strategy, kind='hardware', detail='Required fixture missing', actor='analyst')
        out = Reasoning(self.core).step(self.case, self.source, actor='operator')
        self.assertEqual(out['status'], 'blocked')
        self.assertFalse(self.core.results(self.case))
        self.assertEqual(self.core.tasks(self.case)[0]['status'], 'pending')
        self.engine.unblock(self.case, blocker, actor='analyst', reason='Fixture supplied')
        self.assertEqual(self.engine.step(self.case, self.source, actor='operator')['status'], 'evaluated')
        self.assertEqual(len(self.core.tasks(self.case)), 1)

    def test_revision_changed_at_evaluation_boundary_never_crosses_cycle_revision(self):
        _, hypothesis, _ = self.strategy()
        other = Core(self.home)
        self.addCleanup(other.close)
        real = self.engine.flow.evaluate
        def concurrent_revision(*args, **kwargs):
            Workflow(other).revise_hypothesis(self.case, hypothesis, author='analyst',
                                              plausibility=.8, reason='Concurrent revision at evaluation boundary')
            return real(*args, **kwargs)
        with patch.object(self.engine.flow, 'evaluate', side_effect=concurrent_revision):
            out = self.engine.step(self.case, self.source, actor='operator')
        self.assertEqual(out['status'], 'stale')
        self.assertFalse(self.flow.snapshot(self.case)['runs'])
        self.assertEqual(self.engine.snapshot(self.case)['cycles'][0]['hypothesis_revision'], 1)

    def test_snapshot_exposes_priorities_and_remains_readable_after_cancellation(self):
        self.strategy()
        snap = self.engine.snapshot(self.case)
        self.assertEqual(len(snap['priorities']), 1)
        self.assertTrue(snap['priorities'][0]['eligible'])
        self.core.cancel(self.case, reason='Preserve report')
        report = self.core.report(self.case).read_text(encoding='utf-8')
        self.assertIn('priorities', report)
        self.assertIn('CANCELADO', report)
        self.assertFalse(self.core.tasks(self.case))

    def test_changed_input_after_reservation_is_not_evaluated_under_old_fingerprint(self):
        self.strategy()
        real = self.core.run_one
        def changed(*args, **kwargs):
            self.source.write_bytes(b'changed')
            return real(*args, **kwargs)
        with patch.object(self.core, 'run_one', side_effect=changed):
            out = self.engine.step(self.case, self.source, actor='operator')
        self.assertEqual(out['status'], 'stale')
        self.assertFalse(self.flow.snapshot(self.case)['runs'])
        self.assertEqual(len(self.core.results(self.case)), 1)


    def test_stored_outcome_cannot_unlock_an_alternative_without_reproducible_checks(self):
        parent, _, _ = self.strategy(value=3)
        alternative, _, _ = self.strategy(value=99, alternative_to=parent)
        out = self.engine.step(self.case, self.source, actor='operator')
        self.flow.review(self.case, out['run']['id'], reviewer='reviewer', decision='accepted',
                          reason='Three-byte size checked')
        self.core.db.execute("UPDATE experiment_runs SET outcome='refutes' WHERE id=?", (out['run']['id'],))
        self.core.db.commit()
        with self.assertRaises(CoreError):
            self.engine.rank(self.case)


    def test_failed_input_is_not_repeated_and_next_independent_strategy_can_run(self):
        hypothesis = self.flow.add_hypothesis(self.case, 'Input contains a CAN capture', author='analyst')
        experiment = self.flow.plan_experiment(self.case, hypothesis, 'Parse CAN', author='analyst',
                                               criterion='A capture is parsed',
                                               assertions=[{'field': 'can.frame_count', 'op': 'gt', 'value': 0}],
                                               tool='analyze-can')
        self.engine.register(self.case, experiment, actor='analyst', cost=0, rationale='Check a format hypothesis')
        self.strategy(cost=5)
        with self.assertRaises(CoreError):
            self.engine.step(self.case, self.source, actor='operator')
        self.assertEqual(self.core.tasks(self.case)[0]['status'], 'failed')
        out = self.engine.step(self.case, self.source, actor='operator')
        self.assertEqual(out['status'], 'evaluated')
        self.assertEqual(out['run']['outcome'], 'supports')
        self.assertEqual(len(self.core.tasks(self.case)), 2)


    def test_blocked_reservation_does_not_prevent_an_independent_ready_strategy(self):
        first, _, _ = self.strategy(cost=0)
        second, _, _ = self.strategy(cost=5)
        with patch.object(self.core, 'run_one', side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                self.engine.step(self.case, self.source, actor='operator')
        self.engine.block(self.case, first, kind='data', detail='Missing prerequisite', actor='analyst')
        out = self.engine.step(self.case, self.source, actor='operator')
        self.assertEqual(out['status'], 'evaluated')
        cycles = self.engine.snapshot(self.case)['cycles']
        self.assertEqual(next(c for c in cycles if c['strategy_id'] == first)['status'], 'QUEUED')
        self.assertEqual(next(c for c in cycles if c['strategy_id'] == second)['status'], 'EVALUATED')
        self.assertEqual(len(self.core.tasks(self.case)), 2)


if __name__ == '__main__':
    unittest.main()
