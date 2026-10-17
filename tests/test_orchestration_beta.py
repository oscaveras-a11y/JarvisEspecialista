"""Synthetic integration coverage for bounded queue execution and cancellation."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from cyber_core.errors import CoreError
from cyber_core.service import Core


class OrchestrationBetaTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.inputs = self.root / 'inputs'
        self.inputs.mkdir()
        self.home = self.root / 'state'
        self.core = Core(self.home)
        self.addCleanup(self.core.close)
        self.case = self.core.investigate('beta', 'Synthetic queue', str(self.inputs),
                                          'operator', 'Authorized synthetic files', recovery=True)
        self.source = self.inputs / 'sample.bin'
        self.source.write_bytes(b'abc')

    def worker(self, **kwargs):
        self.assertTrue(callable(getattr(self.core, 'run_queue', None)),
                        'Continuous bounded queue execution is missing')
        return self.core.run_queue(self.case, **kwargs)

    def cancel(self, reason='Operator stopped synthetic case'):
        self.assertTrue(callable(getattr(self.core, 'cancel', None)),
                        'Persistent cancellation is missing')
        return self.core.cancel(self.case, reason=reason)

    def queue(self, count=1):
        return [self.core.enqueue(self.case, self.source) for _ in range(count)]

    def cli(self, *args, success=True):
        run = subprocess.run([sys.executable, '-m', 'cyber_core', '--home', str(self.home),
                              *args], capture_output=True, text=True, timeout=60)
        self.assertEqual(run.returncode, 0 if success else 2, run.stderr)
        return json.loads(run.stdout) if success else run.stderr

    def test_drains_multiple_tasks_with_durable_checkpoints(self):
        self.queue(3)
        result = self.worker()
        self.assertEqual(result['status'], 'drained')
        self.assertEqual(result['completed'], 3)
        self.assertEqual(len(self.core.results(self.case)), 3)
        self.assertTrue(self.core.verify_audit(self.case))
        events = [row['event'] for row in self.core.checkpoints(self.case)]
        self.assertIn('worker_started', events)
        self.assertIn('worker_stopped', events)
        self.assertEqual(events.count('worker_progress'), 3)
        self.assertEqual(self.core.get(self.case)['state'], 'EM INVESTIGACAO')

    def test_task_budget_preserves_remaining_work_for_next_process(self):
        self.queue(2)
        result = self.worker(max_tasks=1)
        self.assertEqual(result['status'], 'task_limit')
        self.assertEqual(result['completed'], 1)
        resumed = self.cli('worker', self.case)
        self.assertEqual(resumed['status'], 'drained')
        self.assertEqual(len(self.core.results(self.case)), 2)
        self.assertTrue(all(t['attempts'] == 1 for t in self.core.tasks(self.case)))

    def test_pause_stops_between_tasks_and_resume_preserves_queue(self):
        self.queue(2)
        original = self.core.run_one
        def pause_after_first(*args, **kwargs):
            result = original(*args, **kwargs)
            self.core.pause(self.case)
            return result
        with patch.object(self.core, 'run_one', side_effect=pause_after_first):
            result = self.worker()
        self.assertEqual(result['status'], 'paused')
        self.assertEqual(result['completed'], 1)
        self.assertEqual(sum(t['status'] == 'pending' for t in self.core.tasks(self.case)), 1)
        self.core.resume(self.case)
        self.assertEqual(self.worker()['completed'], 1)

    def test_failed_task_does_not_stop_other_authorized_work(self):
        missing = self.inputs / 'removed.bin'
        missing.write_bytes(b'x')
        self.core.enqueue(self.case, missing)
        missing.unlink()
        self.queue()
        result = self.worker()
        self.assertEqual(result['status'], 'drained_with_errors')
        self.assertEqual(result['failed'], 1)
        self.assertEqual(result['completed'], 1)
        self.assertEqual(len(self.core.results(self.case)), 1)

    def test_resource_options_reject_nonfinite_and_boolean_values(self):
        for options in ({'max_tasks': 0}, {'max_tasks': True},
                        {'max_seconds': float('nan')}, {'max_seconds': float('inf')},
                        {'poll_interval': 0}, {'idle_timeout': -1}):
            with self.subTest(options=options), self.assertRaises(CoreError):
                self.worker(**options)
        self.assertFalse(self.core.checkpoints(self.case))

    def test_time_budget_does_not_dequeue_after_expiration(self):
        self.queue(2)
        from cyber_core.orchestrator import worker
        original = worker.time.monotonic
        clock = [0.0]
        real_run = self.core.run_one
        def advance_after_task(*args, **kwargs):
            result = real_run(*args, **kwargs)
            clock[0] = 20.0
            return result
        with patch.object(worker.time, 'monotonic', side_effect=lambda: clock[0]), \
             patch.object(self.core, 'run_one', side_effect=advance_after_task):
            result = self.worker(max_seconds=10)
        self.assertEqual(result['status'], 'time_limit')
        self.assertEqual(result['completed'], 1)
        self.assertEqual(sum(t['status'] == 'pending' for t in self.core.tasks(self.case)), 1)

    def test_live_lease_is_not_misreported_as_empty_queue(self):
        task = self.queue()[0]
        import time
        self.core.db.execute("UPDATE tasks SET status='running',lease_until=? WHERE id=?",
                             (time.time() + 60, task))
        self.core.db.commit()
        self.assertEqual(self.worker()['status'], 'awaiting_lease')
        self.assertFalse(self.core.results(self.case))

    def test_expired_lease_is_resumed_by_cli_without_duplicate_result(self):
        task = self.queue()[0]
        self.core.db.execute("UPDATE tasks SET status='running',lease_until=0,attempts=1 WHERE id=?", (task,))
        self.core.db.commit()
        self.assertEqual(self.cli('worker', self.case)['completed'], 1)
        self.assertEqual(self.core.tasks(self.case)[0]['attempts'], 2)
        self.assertEqual(len(self.core.results(self.case)), 1)

    def test_two_worker_processes_commit_each_task_once(self):
        self.queue(4)
        command = [sys.executable, '-m', 'cyber_core', '--home', str(self.home),
                   'worker', self.case, '--idle-timeout', '1', '--poll-interval', '.05']
        first = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        second = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.addCleanup(lambda: first.kill() if first.poll() is None else None)
        self.addCleanup(lambda: second.kill() if second.poll() is None else None)
        for process in (first, second):
            stdout, stderr = process.communicate(timeout=60)
            self.assertEqual(process.returncode, 0, stderr)
            self.assertIn(json.loads(stdout)['status'], ('drained', 'awaiting_lease'))
        self.assertEqual(len(self.core.results(self.case)), 4)
        self.assertTrue(all(t['status'] == 'done' and t['attempts'] == 1 for t in self.core.tasks(self.case)))
        self.assertTrue(self.core.verify_audit(self.case))

    def test_cancellation_is_idempotent_and_preserves_prior_evidence(self):
        self.queue()
        result = self.core.run_one(self.case)
        copy = Path(result['copy'])
        self.queue(2)
        self.cancel()
        before = len(self.core.audit(self.case))
        self.cancel()
        self.assertEqual(len(self.core.audit(self.case)), before)
        self.assertEqual(self.core.get(self.case)['state'], 'CANCELADO')
        self.assertEqual([t['status'] for t in self.core.tasks(self.case)].count('cancelled'), 2)
        self.assertEqual(copy.read_bytes(), b'abc')
        self.assertEqual(len(self.core.results(self.case)), 1)
        self.assertIn('CANCELADO', self.core.report(self.case).read_text(encoding='utf-8'))
        self.assertTrue(self.core.verify_audit(self.case))

    def test_cancelled_case_cannot_resume_enqueue_recover_or_finalize(self):
        self.cancel()
        from cyber_core.investigation.workflow import Workflow
        actions = [lambda: self.core.resume(self.case),
                   lambda: self.core.enqueue(self.case, self.source),
                   lambda: self.core.recover(self.case, self.source, b'x' * 32),
                   lambda: Workflow(self.core).finalize(self.case, 'EM INVESTIGACAO', actor='a', reason='cannot reopen')]
        for action in actions:
            with self.assertRaises(CoreError):
                action()
        self.assertEqual(self.worker()['status'], 'cancelled')
        self.assertEqual(self.core.get(self.case)['state'], 'CANCELADO')

    def test_late_analysis_is_discarded_after_other_connection_cancels(self):
        self.queue()
        from cyber_core import service
        original = service.analyze
        other = Core(self.home)
        self.addCleanup(other.close)
        self.assertTrue(callable(getattr(other, 'cancel', None)), 'Persistent cancellation is missing')
        def cancel_during_analysis(*args, **kwargs):
            result = original(*args, **kwargs)
            other.cancel(self.case, reason='Cancelled while analysis was running')
            return result
        with patch.object(service, 'analyze', side_effect=cancel_during_analysis):
            result = self.worker()
        self.assertEqual(result['status'], 'cancelled')
        self.assertFalse(self.core.results(self.case))
        self.assertEqual(self.core.tasks(self.case)[0]['status'], 'cancelled')
        self.assertFalse(list((self.home / 'cases' / self.case / 'evidence').glob('*.evidence')))
        self.assertTrue(self.core.verify_audit(self.case))

    def test_interruption_releases_claim_and_removes_partial_copy(self):
        self.queue()
        from cyber_core import service
        def interrupted(source, output, *args):
            output.write_bytes(b'partial')
            raise KeyboardInterrupt
        self.assertTrue(callable(getattr(self.core, 'run_queue', None)), 'Continuous bounded queue execution is missing')
        with patch.object(service, 'analyze', side_effect=interrupted):
            with self.assertRaises(KeyboardInterrupt):
                self.worker()
        self.assertEqual(self.core.tasks(self.case)[0]['status'], 'pending')
        self.assertFalse(list((self.home / 'cases' / self.case / 'evidence').glob('*.evidence')))
        self.assertEqual(self.cli('worker', self.case)['completed'], 1)
        self.assertTrue(any(c['event'] == 'worker_stopped' and 'interrupted' in c['data']
                            for c in self.core.checkpoints(self.case)))

    def test_cancel_cli_survives_reopen_and_rejects_empty_reason(self):
        self.queue()
        self.cli('cancel', self.case, '--reason', '', success=False)
        self.cli('cancel', self.case, '--reason', 'Owner requested stop')
        result = self.cli('worker', self.case)
        self.assertEqual(result['status'], 'cancelled')
        self.cli('resume', self.case, success=False)
        self.assertEqual(self.cli('status', self.case)['investigation']['state'], 'CANCELADO')

    def test_authorization_revocation_stops_worker_without_consuming_tasks(self):
        self.queue()
        self.core.revoke(self.case)
        result = self.worker()
        self.assertEqual(result['status'], 'blocked')
        self.assertEqual(self.core.tasks(self.case)[0]['status'], 'pending')
        self.assertEqual(self.core.tasks(self.case)[0]['attempts'], 0)

    def test_agent_proposal_is_not_accepted_after_cancellation(self):
        self.assertTrue(callable(getattr(self.core, 'cancel', None)), 'Persistent cancellation is missing')
        from cyber_core.orchestrator import review_summary
        other = Core(self.home)
        self.addCleanup(other.close)
        def late_review(*args, **kwargs):
            other.cancel(self.case, reason='Stop cloud review')
            return {'agent': 'synthetic-adapter', 'review': 'Late proposal', 'independent_validation': False}
        with patch('cyber_core.orchestrator.CodexAdapter.review', side_effect=late_review):
            with self.assertRaises(CoreError):
                review_summary(self.core, self.case, allow_cloud=True)
        self.assertFalse(any(e['event'] == 'agent_review_proposed' for e in self.core.audit(self.case)))

    def test_batch_cancellation_is_reported_as_cancelled_not_failures(self):
        self.assertTrue(callable(getattr(self.core, 'cancel', None)), 'Persistent cancellation is missing')
        (self.inputs / 'second.bin').write_bytes(b'def')
        original = self.core.run_one
        def cancel_after_first(*args, **kwargs):
            result = original(*args, **kwargs)
            self.core.cancel(self.case, reason='Stop batch after first acquisition')
            return result
        with patch.object(self.core, 'run_one', side_effect=cancel_after_first):
            result = self.core.assess_recovery(self.case, self.inputs)
        self.assertEqual(result['status'], 'cancelled')
        self.assertEqual(len(result['results']), 1)
        self.assertEqual(len(result['cancelled_tasks']), 1)
        self.assertFalse(result['pending_tasks'])
        self.assertFalse(result['failures'])

    def test_interrupt_after_commit_preserves_committed_evidence(self):
        self.assertTrue(callable(getattr(self.core, 'run_queue', None)), 'Continuous bounded queue execution is missing')
        self.queue()
        from cyber_core import service
        real_audit = service.audit
        def interrupt_after_commit(db, case, event, data):
            real_audit(db, case, event, data)
            if event == 'analysis_verified':
                db.commit()
                raise KeyboardInterrupt
        with patch.object(service, 'audit', side_effect=interrupt_after_commit):
            with self.assertRaises(KeyboardInterrupt):
                self.worker()
        result = self.core.results(self.case)[0]
        self.assertEqual(self.core.tasks(self.case)[0]['status'], 'done')
        self.assertEqual(Path(result['copy']).read_bytes(), b'abc')
        self.assertTrue(self.core.verify_audit(self.case))
        self.assertEqual(self.worker()['status'], 'drained')
        self.assertEqual(len(self.core.results(self.case)), 1)

    def test_aes_acceptance_and_cancellation_have_serial_commit_order(self):
        self.assertTrue(callable(getattr(self.core, 'cancel', None)), 'Persistent cancellation is missing')
        import os
        import threading
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        key = b'k' * 32
        nonce = os.urandom(12)
        encrypted = self.inputs / 'control.ccaes'
        encrypted.write_bytes(b'CCAES1' + nonce + AESGCM(key).encrypt(nonce, b'control', b'CCAES1'))
        started, finished = threading.Event(), threading.Event()
        errors = []
        def cancel_on_other_connection():
            other = Core(self.home)
            try:
                started.set()
                other.cancel(self.case, reason='Concurrent cancellation at final recovery acceptance')
            except BaseException as exc:
                errors.append(exc)
            finally:
                other.close()
                finished.set()
        thread = threading.Thread(target=cancel_on_other_connection)
        real_authorize = self.core.authorize
        calls = [0]
        def schedule_cancellation(*args, **kwargs):
            row = real_authorize(*args, **kwargs)
            calls[0] += 1
            if calls[0] == 4:
                thread.start()
                self.assertTrue(started.wait(5))
                # Without a final writer lock cancel commits here; with the lock it waits.
                finished.wait(.5)
            return row
        with patch.object(self.core, 'authorize', side_effect=schedule_cancellation):
            recovered = self.core.recover(self.case, encrypted, key)
        self.assertTrue(finished.wait(15))
        thread.join(timeout=1)
        self.assertFalse(errors, repr(errors))
        events = [row['event'] for row in self.core.audit(self.case)]
        self.assertLess(events.index('recovery_verified'), events.index('investigation_cancelled'))
        self.assertEqual(Path(recovered['output']).read_bytes(), b'control')
        self.assertEqual(self.core.get(self.case)['state'], 'CANCELADO')

    def test_batch_cancellation_reconciles_items_leased_by_another_worker(self):
        self.assertTrue(callable(getattr(self.core, 'cancel', None)), 'Persistent cancellation is missing')
        (self.inputs / 'second.bin').write_bytes(b'def')
        other = Core(self.home)
        self.addCleanup(other.close)
        real_run = self.core.run_one
        calls = [0]
        leased = []
        def run_with_concurrent_claim(*args, **kwargs):
            calls[0] += 1
            if calls[0] == 1:
                claim = other._claim(self.case, kwargs['task_id'])
                leased.append(claim['id'])
                return real_run(*args, **kwargs)
            result = real_run(*args, **kwargs)
            other.cancel(self.case, reason='Stop batch with a separately leased earlier item')
            return result
        with patch.object(self.core, 'run_one', side_effect=run_with_concurrent_claim):
            result = self.core.assess_recovery(self.case, self.inputs)
        self.assertEqual(result['status'], 'cancelled')
        self.assertEqual(result['cancelled_tasks'], leased)
        self.assertFalse(result['pending_tasks'])
        self.assertFalse(result['failures'])
        self.assertEqual(len(result['results']), 1)
