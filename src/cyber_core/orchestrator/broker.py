"""Durable metadata review and cross-review; agents never execute evidence tools."""
import json
import math
from pathlib import Path
import time

from cyber_core.agents.runner import CodexAdapter, ClaudeAdapter, AgentResourceError
from cyber_core.errors import CoreError
from cyber_core.memory import encoded, utc
from cyber_core.permissions import storage_root
from cyber_core.verification.artifacts import verified_result, result_digest
from cyber_core.orchestrator.broker_store import Store

QUESTION = 'Which additional static validation distinguishes a format signature from a valid file?'

class Broker:
    def __init__(self, core, *, adapters=None, call_limit=None, max_attempts=3):
        self.core, self.db = core, core.db
        self.call_limit = getattr(core, 'agent_calls_per_case', 5) if call_limit is None else call_limit
        if type(self.call_limit) is not int or not 0 <= self.call_limit <= 100:
            raise CoreError('Invalid agent call limit')
        if type(max_attempts) is not int or not 1 <= max_attempts <= 100:
            raise CoreError('Invalid agent attempt limit')
        self.max_attempts = max_attempts
        timeout = min(core.timeout, 120)
        self.adapters = ({'codex': CodexAdapter(timeout=timeout), 'claude': ClaudeAdapter(timeout=timeout)}
                         if adapters is None else dict(adapters))
        if any(key not in ('codex', 'claude') or getattr(value, 'name', None) != key
               for key, value in self.adapters.items()):
            raise CoreError('Invalid named agent adapter')
        self.store = Store(core)

    def _ready(self, case):
        row = self.core.authorize(case)
        if row['paused']:
            raise CoreError('Investigation is paused')
        return row

    def get(self, case, job):
        self.core.get(case)
        return self.store.public(self.store.row(case, job))

    def jobs(self, case):
        self.core.get(case)
        return [self.store.public(dict(row)) for row in
                self.db.execute('SELECT * FROM agent_jobs WHERE case_id=? ORDER BY rowid', (case,))]

    def _snapshot(self, case, *, verify=True):
        if not self.core.verify_audit(case):
            raise CoreError('Audit chain integrity failed')
        records = self.db.execute('SELECT task_id,data FROM results WHERE case_id=? ORDER BY task_id', (case,)).fetchall()
        if not records:
            raise CoreError('Agent review requires a verified completed observation')
        if len(records) > 100:
            raise CoreError('Agent observation limit exceeded')
        observations, fingerprints = [], []
        for record in records:
            try:
                if verify:
                    data, digest = verified_result(self.core, case, record['task_id'])
                else:
                    data = json.loads(record['data'])
                    digest = result_digest(data)
                size, entropy, fmt, checked = (data.get(k) for k in ('size', 'entropy', 'format', 'copy_verified'))
                if (type(size) is not int or size < 0 or type(entropy) not in (int, float)
                        or not math.isfinite(entropy) or not 0 <= entropy <= 8
                        or not isinstance(fmt, str) or not 1 <= len(fmt) <= 100 or checked is not True):
                    raise CoreError('Observation does not meet the derived metadata contract')
            except (ValueError, TypeError, AttributeError) as exc:
                raise CoreError('Invalid observation metadata') from exc
            observations.append({'size': size, 'entropy': entropy, 'format': fmt, 'copy_verified': True})
            fingerprints.append([record['task_id'], digest])
        return {'observations': observations, 'question': QUESTION}, result_digest(fingerprints)

    def _anchor(self, case, row):
        # The mutable job table must still match its hash-linked enqueue record.
        for event in self.db.execute("SELECT data FROM audit WHERE case_id=? AND event='agent_job_enqueued' ORDER BY id DESC", (case,)):
            anchor = json.loads(event['data'])
            if anchor.get('job') == row['id']:
                if all(anchor.get(key) == row[key] for key in
                       ('agent', 'purpose', 'snapshot_digest', 'summary_digest', 'depends_on', 'dependency_digest')):
                    return
                break
        raise CoreError('Agent job differs from its audited request')

    def _dependency(self, case, job, agent, snapshot):
        if not job:
            return None, ''
        parent = self.store.row(case, job)
        self._anchor(case, parent)
        if (parent['status'] != 'done' or parent['agent'] == agent or parent['purpose'] != 'primary_review'
                or parent['snapshot_digest'] != snapshot or not parent['response']):
            raise CoreError('Cross-review requires a completed primary review by a different agent on current evidence')
        response = json.loads(parent['response'])
        digest = result_digest(response)
        if digest != parent['response_digest']:
            raise CoreError('Primary review response integrity failed')
        anchored = False
        for event in self.db.execute("SELECT data FROM audit WHERE case_id=? AND event='agent_job_completed' ORDER BY id DESC", (case,)):
            data = json.loads(event['data'])
            if data.get('job') == job:
                anchored = data.get('response_digest') == digest
                break
        if not anchored:
            raise CoreError('Primary review is not bound to audited response')
        return {'agent': parent['agent'], 'review': response['review'], 'digest': digest}, digest

    def _valid(self, case, row, *, verify=True):
        self._anchor(case, row)
        summary, snapshot = self._snapshot(case, verify=verify)
        if snapshot != row['snapshot_digest']:
            raise CoreError('Agent observation snapshot changed')
        prior, dependency = self._dependency(case, row['depends_on'], row['agent'], snapshot)
        if prior:
            summary['prior_review'] = prior
        if dependency != row['dependency_digest'] or result_digest(summary) != row['summary_digest']:
            raise CoreError('Agent summary or dependency changed')
        if encoded(summary) != row['summary']:
            raise CoreError('Agent summary differs from current approved metadata')
        return summary

    def enqueue(self, case, *, agent='codex', allow_cloud=False, depends_on=None):
        if allow_cloud is not True:
            raise CoreError('Cloud summary transfer requires explicit approval')
        if agent not in ('codex', 'claude'):
            raise CoreError('Unknown agent')
        with self.db:
            self.store.begin()
            self._ready(case)
            summary, snapshot = self._snapshot(case)
            prior, dependency = self._dependency(case, depends_on, agent, snapshot)
            if prior:
                summary['prior_review'] = prior
            if len(encoded(summary).encode('utf-8')) > 12000:
                raise CoreError('Agent summary input limit exceeded')
            return self.store.insert(case, agent, summary, snapshot, depends_on=depends_on,
                                     dependency_digest=dependency)

    def _state(self, case):
        row = self.core.get(case)
        if row['state'] == 'CANCELADO':
            return 'cancelled'
        try:
            self.core.authorize(case)
        except CoreError:
            return 'blocked'
        return 'paused' if row['paused'] else None

    def _stop(self, case, job, token):
        row = self.store.owned(case, job, token)
        state = self._state(case)
        if state:
            return state
        try:
            self._valid(case, row, verify=False)
        except CoreError:
            return 'stale'
        return None

    def _finish(self, case, job, token, status, *, response=None, error=None):
        with self.db:
            self.store.begin()
            return self.store.finish(case, job, token, status, response=response, error=error)

    def run_one(self, case, job_id=None):
        with self.db:
            self.store.begin()
            self._ready(case)
            row = self.store.claim(case, job=job_id, lease_seconds=min(self.core.timeout, 120) + 30)
        if row is None:
            return None
        job, token = row['id'], row['token']
        try:
            summary = self._valid(case, row)
        except CoreError:
            return self._finish(case, job, token, 'stale', error='snapshot_or_integrity_changed')
        adapter = self.adapters.get(row['agent'])
        try:
            if adapter is None:
                raise AgentResourceError('unavailable')
            adapter.check_available()
        except AgentResourceError as exc:
            return self._finish(case, job, token, 'awaiting_resources', error=exc.category)
        folder = storage_root(self.core.home / 'agent-workspaces' / job)
        # Reserve and persist intent before an external call can be started. A
        # crash from this point is uncertain, even if the CLI never received stdin.
        with self.db:
            self.store.begin()
            current = self.store.owned(case, job, token)
            state = self._state(case)
            if state:
                return self.store.finish(case, job, token, state, error=state)
            try:
                summary = self._valid(case, current)
            except CoreError:
                return self.store.finish(case, job, token, 'stale', error='snapshot_or_integrity_changed')
            budget = self.core.get(case)['agent_calls']
            if budget >= self.call_limit or current['attempts'] >= self.max_attempts:
                return self.store.finish(case, job, token, 'awaiting_resources', error='call_budget_exhausted')
            self.db.execute('UPDATE investigations SET agent_calls=agent_calls+1 WHERE id=?', (case,))
            self.db.execute('UPDATE agent_jobs SET attempts=attempts+1,sent=1,updated=? WHERE id=?', (utc(), job))
            self.store.event(case, 'agent_job_send_reserved',
                             {'job': job, 'agent': row['agent'], 'attempt': current['attempts'] + 1,
                              'summary_digest': row['summary_digest']})
        try:
            response = adapter.review(summary, folder, should_stop=lambda: self._stop(case, job, token))
            if (not isinstance(response, dict) or response.get('agent') != row['agent']
                    or response.get('independent_validation') is not False
                    or not isinstance(response.get('review'), str) or not response['review'].strip()
                    or len(response['review'].encode('utf-8')) > 8192):
                raise CoreError('Invalid agent review contract')
            # Do not persist arbitrary adapter/provider extras.
            response = {'agent': row['agent'], 'review': response['review'],
                        'independent_validation': False,
                        'usage': {key: value for key, value in response.get('usage', {}).items()
                                  if key in ('input_tokens', 'output_tokens', 'cached_input_tokens',
                                             'cache_read_input_tokens', 'cache_creation_input_tokens')
                                  and type(value) is int and value >= 0}}
        except AgentResourceError as exc:
            state = self._stop(case, job, token)
            return self._finish(case, job, token, state or 'awaiting_resources', error=state or exc.category)
        except CoreError:
            state = self._stop(case, job, token)
            # Includes timeout/invalid response: provider may already have processed
            # the request, so no automatic retry and no asserted non-billing.
            return self._finish(case, job, token, state or 'uncertain', error=state or 'provider_outcome_unconfirmed')
        except BaseException:
            self._finish(case, job, token, 'uncertain', error='interrupted_after_send')
            raise
        with self.db:
            self.store.begin()
            current = self.store.owned(case, job, token)
            state = self._state(case)
            if state:
                return self.store.finish(case, job, token, state, error=state)
            try:
                self._valid(case, current)
            except CoreError:
                return self.store.finish(case, job, token, 'stale', error='snapshot_or_integrity_changed')
            return self.store.finish(case, job, token, 'done', response=response)

    def retry(self, case, job, *, allow_cloud=False, acknowledge_uncertain=False, reason):
        if allow_cloud is not True or not isinstance(reason, str) or not reason.strip() or len(reason) > 1000:
            raise CoreError('Retry requires explicit cloud approval and a bounded reason')
        with self.db:
            self.store.begin()
            self._ready(case)
            row = self.store.row(case, job)
            if row['status'] not in ('awaiting_resources', 'uncertain', 'failed', 'paused'):
                raise CoreError('Agent job is not retryable')
            if row['status'] == 'uncertain' and acknowledge_uncertain is not True:
                raise CoreError('Uncertain provider outcome requires explicit duplicate-call acknowledgment')
            if row['attempts'] >= self.max_attempts:
                raise CoreError('Agent attempt budget exhausted')
            self._valid(case, row)
            self.db.execute("UPDATE agent_jobs SET status='pending',sent=0,token=NULL,lease_until=0,error=NULL,updated=? WHERE id=?",
                            (utc(), job))
            self.store.event(case, 'agent_job_retry_authorized',
                             {'job': job, 'previous_status': row['status'],
                              'acknowledge_uncertain': acknowledge_uncertain is True, 'reason': reason.strip()})
        return self.get(case, job)
