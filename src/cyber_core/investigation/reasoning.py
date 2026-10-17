"""Persistent, evidence-grounded investigation decisions (item 4).

No source/evidence text is executed. Hypotheses and falsifiable criteria use
Workflow; this layer ranks, schedules, resumes and explains their execution.
"""
import hashlib
import json
import math
import sqlite3
import time
from uuid import uuid4

from cyber_core.errors import CoreError
from cyber_core.memory import audit, encoded, utc
from cyber_core.investigation.workflow import Workflow, text
from cyber_core.investigation.reasoning_store import ensure, exists
from cyber_core.verification.artifacts import verified_result, result_digest


TOOLS = ('analyze-file', 'assess-recovery', 'analyze-firmware', 'analyze-can')
BLOCK_KINDS = ('data', 'hardware', 'key', 'authorization', 'resource')


def bounded_number(value, label, maximum):
    if type(value) not in (int, float) or not math.isfinite(value) or not 0 <= value <= maximum:
        raise CoreError('Invalid ' + label)
    return value


class Reasoning:
    def __init__(self, core):
        self.core, self.db, self.flow = core, core.db, Workflow(core)
        ensure(self.db)

    def _row(self, table, case, identifier):
        if table not in ('reasoning_strategies', 'reasoning_blockers', 'reasoning_cycles'):
            raise CoreError('Invalid reasoning record type')
        row = self.db.execute('SELECT * FROM ' + table + ' WHERE case_id=? AND id=?',
                              (case, identifier)).fetchone()
        if row is None:
            raise CoreError('Unknown reasoning record in this investigation')
        return dict(row)

    def _guard(self, case):
        self.flow._commit_guard(case)

    def _evidence(self, case, tasks):
        if not isinstance(tasks, (list, tuple)) or len(tasks) > 100 or any(not isinstance(t, str) for t in tasks):
            raise CoreError('Invalid evidence references')
        out = []
        for task in dict.fromkeys(tasks):
            result, _ = verified_result(self.core, case, task)
            out.append((task, result))
        return out

    def register(self, case, experiment, *, actor, cost=1, risk=0, evidence=(),
                 sources=(), alternative_to=None, rationale):
        self.flow._ready(case)
        actor, rationale = text(actor, 'actor', 200), text(rationale, 'strategy rationale')
        bounded_number(cost, 'strategy cost', 100)
        bounded_number(risk, 'strategy risk', 1)
        plan = self.flow._row('experiments', case, experiment)
        if plan['tool'] not in TOOLS:
            raise CoreError('Strategy tool is not executable by the allowlisted core')
        self._evidence(case, evidence)
        if not isinstance(sources, (list, tuple)) or len(sources) > 100 or any(not isinstance(s, str) for s in sources):
            raise CoreError('Invalid source references')
        if alternative_to:
            self._row('reasoning_strategies', case, alternative_to)
        identifier = uuid4().hex
        with self.db:
            self._guard(case)
            for source in sources:
                if not self.db.execute('SELECT 1 FROM source_records WHERE id=? AND case_id=?', (source, case)).fetchone():
                    raise CoreError('Unknown technical source in this investigation')
            if self.db.execute('SELECT 1 FROM reasoning_strategies WHERE experiment_id=?', (experiment,)).fetchone():
                raise CoreError('Experiment already has a reasoning strategy')
            if self.db.execute('SELECT COUNT(*) FROM reasoning_strategies WHERE case_id=?', (case,)).fetchone()[0] >= 1000:
                raise CoreError('Reasoning strategy limit exceeded')
            self.db.execute('INSERT INTO reasoning_strategies VALUES(?,?,?,?,?,?,?,?,?,?,?)',
                            (identifier, case, experiment, cost, risk, encoded(list(dict.fromkeys(evidence))),
                             encoded(list(dict.fromkeys(sources))), alternative_to, rationale, actor, utc()))
            self.core.reopen(case, reason='Investigation strategy registered')
            audit(self.db, case, 'reasoning_strategy_registered',
                  {'id': identifier, 'experiment': experiment, 'cost': cost, 'risk': risk,
                   'alternative_to': alternative_to, 'actor': actor})
        return identifier

    def note(self, case, kind, statement, *, actor):
        self.flow._ready(case)
        if kind not in ('INFERENCE', 'UNKNOWN'):
            raise CoreError('Only INFERENCE or UNKNOWN notes are accepted; facts require verified evidence')
        statement, actor = text(statement, 'reasoning note'), text(actor, 'actor', 200)
        identifier = uuid4().hex
        with self.db:
            self._guard(case)
            self.db.execute('INSERT INTO reasoning_notes VALUES(?,?,?,?,?,?)', (identifier, case, kind, statement, actor, utc()))
            self.core.reopen(case, reason='Investigation knowledge changed')
            audit(self.db, case, 'reasoning_note_registered', {'id': identifier, 'kind': kind, 'actor': actor})
        return identifier

    def block(self, case, strategy, *, kind, detail, actor):
        self.flow._ready(case)
        self._row('reasoning_strategies', case, strategy)
        if kind not in BLOCK_KINDS:
            raise CoreError('Unknown blocker kind')
        detail, actor = text(detail, 'blocker detail'), text(actor, 'actor', 200)
        identifier = uuid4().hex
        with self.db:
            self._guard(case)
            self.db.execute('INSERT INTO reasoning_blockers(id,case_id,strategy_id,kind,detail,actor,created) VALUES(?,?,?,?,?,?,?)',
                            (identifier, case, strategy, kind, detail, actor, utc()))
            self.core.reopen(case, reason='Investigation blocker registered')
            audit(self.db, case, 'reasoning_blocked', {'id': identifier, 'strategy': strategy, 'kind': kind, 'actor': actor})
        return identifier

    def unblock(self, case, blocker, *, reason, actor):
        self.flow._ready(case)
        self._row('reasoning_blockers', case, blocker)
        reason, actor = text(reason, 'blocker resolution'), text(actor, 'actor', 200)
        with self.db:
            self._guard(case)
            self.db.execute("UPDATE reasoning_blockers SET status='RESOLVED',resolution=?,resolved_by=? WHERE id=? AND case_id=?",
                            (reason, actor, blocker, case))
            audit(self.db, case, 'reasoning_blocker_resolved', {'id': blocker, 'reason': reason, 'actor': actor})
        return {'id': blocker, 'status': 'RESOLVED'}

    def _state(self, case, plan, hypothesis):
        rows = self.db.execute('SELECT * FROM experiment_runs WHERE experiment_id=? AND hypothesis_revision=?',
                               (plan['id'], hypothesis['revision'])).fetchall()
        outcomes = set()
        for row in rows:
            review = self.flow._latest_review(row['id'])
            if review is None:
                return 'awaiting_review'
            if review['decision'] == 'accepted':
                # A stale/tampered acquisition may never discard a strategy.
                _, digest = verified_result(self.core, case, row['task_id'])
                if digest != row['evidence_digest'] or digest != review['evidence_digest']:
                    raise CoreError('Stale strategy evidence')
                outcomes.add(row['outcome'])
        if len(outcomes) > 1:
            return 'conflicting'
        if outcomes:
            return {'supports': 'supported', 'refutes': 'refuted', 'inconclusive': 'inconclusive'}[next(iter(outcomes))]
        if rows:
            return 'inconclusive'
        count = self.db.execute('SELECT COUNT(*) FROM experiment_runs WHERE experiment_id=?', (plan['id'],)).fetchone()[0]
        return 'budget_exhausted' if count >= plan['max_runs'] else 'ready'

    def rank(self, case):
        self.flow._ready(case)
        return self._ranking(case)

    def _ranking(self, case):
        self.core.get(case)
        items = []
        for row in self.db.execute('SELECT * FROM reasoning_strategies WHERE case_id=? ORDER BY created,id', (case,)):
            strategy = dict(row)
            plan = self.flow._row('experiments', case, strategy['experiment_id'])
            hypothesis = self.flow._row('hypothesis_records', case, plan['hypothesis_id'])
            evidence = self._evidence(case, json.loads(strategy['evidence']))
            hashes = {r['sha256'] for _, r in evidence}
            state = self._state(case, plan, hypothesis)
            blockers = [dict(b) for b in self.db.execute("SELECT * FROM reasoning_blockers WHERE strategy_id=? AND status='OPEN'", (strategy['id'],))]
            reasons = []
            if blockers:
                reasons.extend(b['kind'] + ': ' + b['detail'] for b in blockers)
            if strategy['risk'] == 1:
                reasons.append('Risk ceiling blocks automatic execution')
            bounded_number(strategy['cost'], 'stored strategy cost', 100)
            bounded_number(strategy['risk'], 'stored strategy risk', 1)
            bounded_number(hypothesis['plausibility'], 'stored plausibility', 1)
            score = (.5 * hypothesis['plausibility'] + .5 * min(len(hashes) / 3, 1)) * (1-strategy['risk']) / (1+strategy['cost'])
            items.append({'id': strategy['id'], 'experiment': plan['id'], 'hypothesis': hypothesis['id'],
                          'revision': hypothesis['revision'], 'score': round(score, 6), 'status': state,
                          'eligible': state == 'ready' and not reasons, 'reasons': reasons,
                          'cost': strategy['cost'], 'risk': strategy['risk'], 'plausibility': hypothesis['plausibility'],
                          'verified_evidence_count': len(hashes), 'alternative_to': strategy['alternative_to']})
        by_id = {item['id']: item for item in items}
        for item in items:
            if item['alternative_to'] and by_id[item['alternative_to']]['status'] != 'refuted':
                item['reasons'].append('Alternative awaits accepted refutation of its parent strategy')
                item['eligible'] = False
            if item['reasons'] and item['status'] == 'ready':
                item['status'] = 'blocked'
        return sorted(items, key=lambda item: (-int(item['eligible']), -item['score'], item['id']))

    def _inputs(self, case, path, second_path, deadline):
        sources, hashes = [], []
        for value in (path, second_path):
            if value is None:
                continue
            source = self.core.authorize(case, value)
            checksum, size = hashlib.sha256(), 0
            with source.open('rb') as handle:
                before = source.stat()
                while block := handle.read(65536):
                    size += len(block)
                    if size > self.core.max_bytes or time.monotonic() >= deadline:
                        raise CoreError('Reasoning input verification resource limit exceeded')
                    checksum.update(block)
                after = source.stat()
            if (before.st_size, before.st_mtime_ns, before.st_ino) != (after.st_size, after.st_mtime_ns, after.st_ino):
                raise CoreError('Input changed during reasoning verification')
            sources.append(source)
            hashes.append(checksum.hexdigest())
        return sources, result_digest({'primary': hashes[0], 'secondary': hashes[1] if len(hashes) > 1 else None})

    @staticmethod
    def _idle(ranking):
        if any(r['status'] == 'awaiting_review' for r in ranking):
            return {'status': 'waiting_review'}
        if any(r['status'] in ('blocked', 'conflicting', 'budget_exhausted') for r in ranking):
            return {'status': 'blocked', 'reasons': [reason for r in ranking for reason in r['reasons']]}
        return {'status': 'exhausted' if ranking else 'no_strategy'}

    def _finish(self, case, cycle, status, *, run=None, error=None):
        with self.db:
            self._guard(case)
            self.db.execute('UPDATE reasoning_cycles SET status=?,run_id=?,outcome=?,error=?,updated=? WHERE id=?',
                            (status, run['id'] if run else None, run['outcome'] if run else None,
                             error, utc(), cycle['id']))
            data = {'cycle': cycle['id'], 'task': cycle['task_id'], 'status': status,
                    'run': run['id'] if run else None, 'outcome': run['outcome'] if run else None}
            self.db.execute('INSERT INTO checkpoints(case_id,event,data,created) VALUES(?,?,?,?)',
                            (case, 'reasoning_cycle', encoded(data), utc()))
            audit(self.db, case, 'reasoning_cycle_recorded', data)
        return {'status': status.lower(), 'cycle': cycle['id'], 'task': cycle['task_id'], 'run': run}

    def step(self, case, path, *, actor, second_path=None, strategy=None, time_budget=None):
        self.flow._ready(case)
        actor = text(actor, 'operator', 200)
        budget = self.core.timeout if time_budget is None else time_budget
        if type(budget) not in (int, float) or not math.isfinite(budget) or not 0 < budget <= self.core.timeout:
            raise CoreError('Invalid reasoning step time budget')
        deadline = time.monotonic() + budget
        ranking = self.rank(case)
        unfinished = self.db.execute("SELECT * FROM reasoning_cycles WHERE case_id=? AND status='QUEUED' ORDER BY created,id", (case,)).fetchall()
        eligible = [r for r in ranking if r['eligible'] and (strategy is None or r['id'] == strategy)]
        if strategy is not None:
            self._row('reasoning_strategies', case, strategy)
            unfinished = [r for r in unfinished if r['strategy_id'] == strategy]
        if not eligible and not unfinished:
            return self._idle(ranking)
        sources, fingerprint = self._inputs(case, path, second_path, deadline)
        with self.db:
            self._guard(case)
            current = self.rank(case)
            # Resume a reservation even if evaluation committed just before interruption.
            matches = [r for r in self.db.execute("SELECT * FROM reasoning_cycles WHERE case_id=? AND status='QUEUED' AND input_fingerprint=? ORDER BY created,id",
                                                  (case, fingerprint)) if strategy is None or r['strategy_id'] == strategy]
            if matches:
                cycle = dict(matches[0])
                projection = next(r for r in current if r['id'] == cycle['strategy_id'])
                if projection['revision'] != cycle['hypothesis_revision']:
                    return self._finish(case, cycle, 'STALE', error='Hypothesis changed before resuming reserved task')
                committed_run = self.db.execute('SELECT 1 FROM experiment_runs WHERE task_id=? AND experiment_id=? AND hypothesis_revision=?',
                                                (cycle['task_id'], projection['experiment'], cycle['hypothesis_revision'])).fetchone()
                if not projection['eligible'] and committed_run is None:
                    return self._idle([projection])
            else:
                selected = next((r for r in current if r['eligible'] and (strategy is None or r['id'] == strategy)), None)
                if selected is None:
                    return self._idle(current)
                duplicate = self.db.execute('SELECT id FROM reasoning_cycles WHERE strategy_id=? AND hypothesis_revision=? AND input_fingerprint=?',
                                             (selected['id'], selected['revision'], fingerprint)).fetchone()
                if duplicate:
                    audit(self.db, case, 'reasoning_repeat_rejected', {'strategy': selected['id'], 'cycle': duplicate['id']})
                    return {'status': 'repeated', 'cycle': duplicate['id']}
                record = self._row('reasoning_strategies', case, selected['id'])
                plan = self.flow._row('experiments', case, record['experiment_id'])
                if plan['tool'] not in TOOLS:
                    raise CoreError('Reasoning tool is not allowlisted')
                task = self.core._enqueue(case, sources[0], tool=plan['tool'],
                                          second_path=sources[1] if len(sources) > 1 else None)
                stamp, identifier = utc(), uuid4().hex
                self.db.execute('INSERT INTO reasoning_cycles VALUES(?,?,?,?,?,?,?,?,?,?,?,?)',
                                (identifier, case, selected['id'], selected['revision'], fingerprint,
                                 task, None, 'QUEUED', None, None, stamp, stamp))
                audit(self.db, case, 'reasoning_cycle_reserved', {'cycle': identifier, 'strategy': selected['id'], 'task': task, 'actor': actor})
                cycle = self._row('reasoning_cycles', case, identifier)
        task_row = next(t for t in self.core.tasks(case) if t['id'] == cycle['task_id'])
        if task_row['status'] != 'done':
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return {'status': 'time_budget', 'cycle': cycle['id'], 'task': cycle['task_id']}
            try:
                result = self.core.run_one(case, cycle['task_id'], time_budget=min(remaining, self.core.timeout))
            except CoreError:
                self._finish(case, cycle, 'FAILED', error='Execution failed; inspect audited task error')
                raise
            if result is None:
                task_row = next(t for t in self.core.tasks(case) if t['id'] == cycle['task_id'])
                if task_row['status'] != 'done':
                    if task_row['status'] in ('failed', 'cancelled'):
                        return self._finish(case, cycle, 'FAILED', error='Task cannot execute')
                    return {'status': 'running', 'cycle': cycle['id'], 'task': cycle['task_id']}
        result, _ = verified_result(self.core, case, cycle['task_id'])
        actual = result_digest({'primary': result['sha256'], 'secondary': result.get('secondary', {}).get('sha256')})
        record = self._row('reasoning_strategies', case, cycle['strategy_id'])
        plan = self.flow._row('experiments', case, record['experiment_id'])
        hypothesis = self.flow._row('hypothesis_records', case, plan['hypothesis_id'])
        if hypothesis['revision'] != cycle['hypothesis_revision'] or actual != fingerprint:
            return self._finish(case, cycle, 'STALE', error='Hypothesis or input changed after reservation')
        run = self.db.execute('SELECT * FROM experiment_runs WHERE experiment_id=? AND task_id=? AND hypothesis_revision=?',
                              (plan['id'], cycle['task_id'], cycle['hypothesis_revision'])).fetchone()
        if run is None:
            try:
                run = self.flow.evaluate(case, plan['id'], cycle['task_id'], operator=actor,
                                         expected_revision=cycle['hypothesis_revision'])
            except (CoreError, sqlite3.IntegrityError):
                # Concurrent resumers may observe the same committed evaluation.
                run = self.db.execute('SELECT * FROM experiment_runs WHERE experiment_id=? AND task_id=? AND hypothesis_revision=?',
                                      (plan['id'], cycle['task_id'], cycle['hypothesis_revision'])).fetchone()
                if run is None:
                    current_hypothesis = self.flow._row('hypothesis_records', case, plan['hypothesis_id'])
                    if current_hypothesis['revision'] != cycle['hypothesis_revision']:
                        return self._finish(case, cycle, 'STALE', error='Hypothesis changed at evaluation boundary')
                    raise
        return self._finish(case, cycle, 'EVALUATED', run=dict(run))

    def run(self, case, path, *, actor, max_steps=10, max_seconds=300, second_path=None):
        if type(max_steps) is not int or not 1 <= max_steps <= 100:
            raise CoreError('Invalid reasoning step limit')
        if type(max_seconds) not in (int, float) or not math.isfinite(max_seconds) or not 0 < max_seconds <= 3600:
            raise CoreError('Invalid reasoning run time limit')
        started, steps, stopped = time.monotonic(), [], 'step_limit'
        for _ in range(max_steps):
            remaining = max_seconds - (time.monotonic() - started)
            if remaining <= 0:
                stopped = 'time_budget'
                break
            out = self.step(case, path, actor=actor, second_path=second_path,
                            time_budget=min(remaining, self.core.timeout))
            steps.append(out)
            if out['status'] != 'evaluated':
                stopped = out['status']
                break
        return {'steps': steps, 'stopped': stopped, 'elapsed_seconds': round(time.monotonic()-started, 3),
                'validated_resolution': False}

    def snapshot(self, case):
        row = self.core.get(case)
        science = self.flow.snapshot(case)
        facts = []
        for stored in self.db.execute('SELECT task_id FROM results WHERE case_id=? ORDER BY created,task_id', (case,)):
            task, result = self._evidence(case, [stored['task_id']])[0]
            facts.append({'kind': 'FACT', 'task': task, **{key: result[key] for key in ('sha256', 'size', 'format', 'entropy')}})
        notes = [dict(r) for r in self.db.execute('SELECT * FROM reasoning_notes WHERE case_id=? ORDER BY created,id', (case,))]
        strategies = [dict(r) for r in self.db.execute('SELECT * FROM reasoning_strategies WHERE case_id=? ORDER BY created,id', (case,))]
        for strategy in strategies:
            strategy['evidence'], strategy['sources'] = json.loads(strategy['evidence']), json.loads(strategy['sources'])
        priorities = self._ranking(case)
        execution_allowed = not (row['paused'] or row['revoked'] or row['expires'] <= time.time() or row['state'] == 'CANCELADO')
        if not execution_allowed:
            for priority in priorities:
                priority['eligible'] = False
                priority['reasons'].append('Investigation is paused, cancelled, revoked or expired')
        return {'contract_version': 1, 'case': case, 'objective': row['objective'],
                'facts': facts, 'technologies': sorted({f['format'] for f in facts}),
                'hypotheses': science['hypotheses'], 'sources': science['sources'],
                'inferences': [n for n in notes if n['kind'] == 'INFERENCE'],
                'unknowns': [n for n in notes if n['kind'] == 'UNKNOWN'],
                'strategies': strategies, 'priorities': priorities, 'execution_allowed': execution_allowed,
                'blockers': [dict(r) for r in self.db.execute('SELECT * FROM reasoning_blockers WHERE case_id=? ORDER BY created,id', (case,))],
                'cycles': [dict(r) for r in self.db.execute('SELECT * FROM reasoning_cycles WHERE case_id=? ORDER BY created,id', (case,))],
                'validated_resolution': row['state'] == 'RESOLVIDO',
                'limitations': 'Priority uses declared estimates; signatures do not prove full technologies. References are registered consultations. Independent review is still required.'}


def snapshot_data(core, case):
    return Reasoning(core).snapshot(case) if exists(core.db) else None
