"""Durable broker contracts; synthetic adapters never contact providers."""
import importlib.util
import json
from pathlib import Path
import tempfile
import time
import unittest
from cyber_core.errors import CoreError
from cyber_core.service import Core

class FixtureAgent:
    def __init__(self, name='codex', action=None):
        self.name, self.action = name, action
        self.requests = []
    def check_available(self):
        return None
    def review(self, summary, workspace, *, should_stop=None):
        self.requests.append(summary)
        if self.action:
            self.action()
        if should_stop and should_stop():
            raise CoreError('Agent stopped')
        return {'agent': self.name, 'review': 'Signature needs structural validation.',
                'independent_validation': False, 'usage': {'input_tokens': 12, 'output_tokens': 4}}

class BrokerTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(importlib.util.find_spec('cyber_core.orchestrator.broker'),
                             'Persistent broker implementation is required')
        from cyber_core.orchestrator.broker import Broker
        self.Broker = Broker
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.scope = self.root / 'inputs'
        self.scope.mkdir()
        self.sample = self.scope / 'private-name.bin'
        self.sample.write_bytes(b'\x7fELF' + bytes(range(256)) * 4)
        self.core = Core(self.root / 'state')
        self.addCleanup(self.core.close)
        self.case = self.core.investigate('private project', 'private objective', self.scope,
                                          'declared owner', 'private authorization')
        self.task = self.core.enqueue(self.case, self.sample)
        self.core.run_one(self.case, task_id=self.task)
        self.agent = FixtureAgent()
        self.broker = Broker(self.core, adapters={'codex': self.agent})
    def enqueue(self, **kwargs):
        return self.broker.enqueue(self.case, allow_cloud=True, **kwargs)
    def test_transfer_requires_explicit_approval_without_reserving_calls(self):
        with self.assertRaises(CoreError):
            self.broker.enqueue(self.case)
        self.assertEqual(self.broker.jobs(self.case), [])
        self.assertEqual(self.core.get(self.case)['agent_calls'], 0)
    def test_review_is_durable_and_only_sanitized_metadata_leaves_core(self):
        job = self.enqueue()
        out = self.broker.run_one(self.case, job)
        self.assertEqual(out['status'], 'done')
        self.assertFalse(out['response']['independent_validation'])
        text = json.dumps(self.agent.requests)
        for forbidden in ('private-name', 'private objective', 'private project',
                          'private authorization', str(self.sample), 'declared owner', 'sha256'):
            self.assertNotIn(forbidden, text)
        self.assertEqual(set(self.agent.requests[0]['observations'][0]),
                         {'size', 'entropy', 'format', 'copy_verified'})
        self.assertEqual(self.core.get(self.case)['agent_calls'], 1)
        self.assertEqual(self.Broker(self.core, adapters={}).get(self.case, job)['status'], 'done')
        self.assertTrue(self.core.verify_audit(self.case))
    def test_duplicate_job_reuses_completed_review_without_new_call(self):
        first = self.enqueue()
        self.broker.run_one(self.case, first)
        self.assertEqual(self.enqueue(), first)
        self.assertIsNone(self.broker.run_one(self.case, first))
        self.assertEqual(self.core.get(self.case)['agent_calls'], 1)
    def test_cross_review_is_separate_and_bound_to_primary_response(self):
        first = self.enqueue()
        with self.assertRaises(CoreError):
            self.enqueue(agent='claude', depends_on=first)
        self.broker.run_one(self.case, first)
        reviewer = FixtureAgent('claude')
        broker = self.Broker(self.core, adapters={'claude': reviewer})
        second = broker.enqueue(self.case, agent='claude', allow_cloud=True, depends_on=first)
        out = broker.run_one(self.case, second)
        self.assertEqual(out['status'], 'done')
        self.assertEqual(out['depends_on'], first)
        self.assertEqual(reviewer.requests[0]['prior_review']['agent'], 'codex')
        self.assertEqual(reviewer.requests[0]['prior_review']['digest'], out['dependency_digest'])
        with self.assertRaises(CoreError):
            self.enqueue(depends_on=first)
    def test_missing_agent_waits_for_resources_and_local_analysis_still_works(self):
        job = self.enqueue(agent='claude')
        self.assertEqual(self.broker.run_one(self.case, job)['status'], 'awaiting_resources')
        self.assertEqual(self.core.get(self.case)['agent_calls'], 0)
        task = self.core.enqueue(self.case, self.sample)
        self.assertIsNotNone(self.core.run_one(self.case, task_id=task))
    def test_pause_before_send_preserves_pending_job_and_budget(self):
        job = self.enqueue()
        self.core.pause(self.case)
        with self.assertRaises(CoreError):
            self.broker.run_one(self.case, job)
        self.assertEqual(self.broker.get(self.case, job)['status'], 'pending')
        self.assertEqual(self.core.get(self.case)['agent_calls'], 0)
    def test_cancel_during_response_discards_late_proposal(self):
        self.agent.action = lambda: self.core.cancel(self.case, reason='synthetic stop')
        job = self.enqueue()
        out = self.broker.run_one(self.case, job)
        self.assertEqual(out['status'], 'cancelled')
        self.assertIsNone(out['response'])
        self.assertNotIn('agent_job_completed', [x['event'] for x in self.core.audit(self.case)])
    def test_revocation_during_response_discards_late_proposal(self):
        self.agent.action = lambda: self.core.revoke(self.case)
        job = self.enqueue()
        self.assertEqual(self.broker.run_one(self.case, job)['status'], 'blocked')
        self.assertIsNone(self.broker.get(self.case, job)['response'])
    def test_new_observation_makes_existing_job_stale(self):
        job = self.enqueue()
        task = self.core.enqueue(self.case, self.sample)
        self.core.run_one(self.case, task_id=task)
        self.assertEqual(self.broker.run_one(self.case, job)['status'], 'stale')
        self.assertEqual(self.core.get(self.case)['agent_calls'], 0)
    def test_evidence_tamper_after_enqueue_is_rejected_before_send(self):
        job = self.enqueue()
        Path(self.core.results(self.case)[0]['copy']).write_bytes(b'tampered')
        self.assertEqual(self.broker.run_one(self.case, job)['status'], 'stale')
        self.assertEqual(self.core.get(self.case)['agent_calls'], 0)
    def test_case_budget_is_shared_with_legacy_reviews(self):
        self.broker = self.Broker(self.core, adapters={'codex': self.agent}, call_limit=1)
        self.core.db.execute('UPDATE investigations SET agent_calls=1 WHERE id=?', (self.case,))
        self.core.db.commit()
        job = self.enqueue()
        self.assertEqual(self.broker.run_one(self.case, job)['status'], 'awaiting_resources')
        self.assertEqual(self.core.get(self.case)['agent_calls'], 1)
    def test_expired_sent_claim_becomes_uncertain_without_automatic_retry(self):
        job = self.enqueue()
        with self.core.db:
            self.core.db.execute("UPDATE agent_jobs SET status='running',sent=1,attempts=1,token='lost',lease_until=? WHERE id=?",
                                 (time.time() - 1, job))
        self.assertIsNone(self.broker.run_one(self.case, job))
        self.assertEqual(self.broker.get(self.case, job)['status'], 'uncertain')
        with self.assertRaises(CoreError):
            self.broker.retry(self.case, job, allow_cloud=True, reason='try again')
        self.assertEqual(self.core.get(self.case)['agent_calls'], 0)
    def test_uncertain_retry_requires_explicit_acknowledgment(self):
        job = self.enqueue()
        with self.core.db:
            self.core.db.execute("UPDATE agent_jobs SET status='uncertain',sent=1 WHERE id=?", (job,))
        self.broker.retry(self.case, job, allow_cloud=True, acknowledge_uncertain=True,
                          reason='Owner explicitly accepts possible duplicate provider charge')
        self.assertEqual(self.broker.run_one(self.case, job)['status'], 'done')
    def test_stale_claim_cannot_publish_over_new_claim(self):
        job = self.enqueue()
        def replace_claim():
            with self.core.db:
                self.core.db.execute("UPDATE agent_jobs SET token='different-worker' WHERE id=?", (job,))
        self.agent.action = replace_claim
        with self.assertRaises(CoreError):
            self.broker.run_one(self.case, job)
        self.assertIsNone(self.broker.get(self.case, job)['response'])
    def test_initialization_keeps_core_schema_version_and_existing_audit(self):
        before = self.core.db.execute('PRAGMA user_version').fetchone()[0]
        self.Broker(self.core)
        self.assertEqual(self.core.db.execute('PRAGMA user_version').fetchone()[0], before)
        self.assertTrue(self.core.verify_audit(self.case))
    def test_live_claim_is_not_sent_by_second_worker(self):
        job = self.enqueue()
        with self.core.db:
            self.core.db.execute("UPDATE agent_jobs SET status='running',token='other',lease_until=? WHERE id=?",
                                 (time.time() + 60, job))
        other = Core(self.root / 'state')
        try:
            second = self.Broker(other, adapters={'codex': FixtureAgent()})
            self.assertIsNone(second.run_one(self.case, job))
            self.assertEqual(other.get(self.case)['agent_calls'], 0)
        finally:
            other.close()
    def test_interruption_after_send_is_uncertain_and_requires_operator_decision(self):
        def interrupt():
            raise KeyboardInterrupt()
        self.agent.action = interrupt
        job = self.enqueue()
        with self.assertRaises(KeyboardInterrupt):
            self.broker.run_one(self.case, job)
        self.assertEqual(self.broker.get(self.case, job)['status'], 'uncertain')
        self.assertEqual(self.core.get(self.case)['agent_calls'], 1)
    def test_resource_failure_is_recorded_without_raw_provider_message(self):
        from cyber_core.agents.runner import AgentResourceError
        def unavailable():
            raise AgentResourceError('authentication')
        self.agent.action = unavailable
        job = self.enqueue()
        out = self.broker.run_one(self.case, job)
        self.assertEqual(out['status'], 'awaiting_resources')
        self.assertEqual(out['error'], 'authentication')
        self.assertIsNone(out['response'])
    def test_malformed_adapter_usage_is_uncertain_without_unhandled_exception(self):
        class Malformed(FixtureAgent):
            def review(self, summary, workspace, *, should_stop=None):
                return {'agent': 'codex', 'review': 'proposal',
                        'independent_validation': False, 'usage': []}
        self.broker = self.Broker(self.core, adapters={'codex': Malformed()})
        job = self.enqueue()
        self.assertEqual(self.broker.run_one(self.case, job)['status'], 'uncertain')
    def test_schema_seven_is_not_downgraded_by_broker_initialization(self):
        with self.core.db:
            self.core.db.execute('PRAGMA user_version=7')
        self.Broker(self.core)
        self.assertEqual(self.core.db.execute('PRAGMA user_version').fetchone()[0], 7)
    def test_pause_during_response_discards_proposal(self):
        self.agent.action = lambda: self.core.pause(self.case)
        job = self.enqueue()
        self.assertEqual(self.broker.run_one(self.case, job)['status'], 'paused')
        self.assertIsNone(self.broker.get(self.case, job)['response'])
    def test_new_evidence_during_review_discards_proposal(self):
        def more_evidence():
            task = self.core.enqueue(self.case, self.sample)
            self.core.run_one(self.case, task_id=task)
        self.agent.action = more_evidence
        job = self.enqueue()
        self.assertEqual(self.broker.run_one(self.case, job)['status'], 'stale')
        self.assertIsNone(self.broker.get(self.case, job)['response'])
    def test_no_evidence_cannot_be_reported_as_completed_review(self):
        empty = self.core.investigate('p', 'o', self.scope, 'owner', 'authorized')
        with self.assertRaises(CoreError):
            self.broker.enqueue(empty, allow_cloud=True)

if __name__ == '__main__':
    unittest.main()
