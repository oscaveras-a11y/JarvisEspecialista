import json
import math
import re
import sqlite3
import unicodedata
from urllib.parse import urlsplit
from uuid import uuid4
from cyber_core.errors import CoreError
from cyber_core.memory import audit, encoded, utc
from cyber_core.verification.artifacts import verified_result, result_digest, observation_fingerprint


def text(value, label, limit=4096):
    if not isinstance(value, str) or not value.strip() or len(value) > limit:
        raise CoreError('Invalid ' + label)
    return value.strip()


def identity(value):
    return unicodedata.normalize('NFKC', value).strip().casefold()


def assertions_checked(assertions):
    if not isinstance(assertions, list) or not 1 <= len(assertions) <= 20:
        raise CoreError('Provide 1 to 20 falsifiable assertions')
    for assertion in assertions:
        if not isinstance(assertion, dict) or set(assertion) != {'field', 'op', 'value'}:
            raise CoreError('Invalid assertion fields')
        field = assertion['field']
        if not isinstance(field, str) or len(field) > 200 or not re.fullmatch(r'[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*){0,7}', field):
            raise CoreError('Assertion fields must be bounded dictionary paths')
        if assertion['op'] not in ('eq', 'ne', 'gt', 'gte', 'lt', 'lte'):
            raise CoreError('Assertion operator is not allowlisted')
        value = assertion['value']
        if not isinstance(value, (str, int, float, bool, type(None))) or isinstance(value, float) and not math.isfinite(value):
            raise CoreError('Assertions require finite scalar values')
    if len(encoded(assertions)) > 16384:
        raise CoreError('Assertion definition is too large')
    return assertions


def evaluate_assertions(assertions, result):
    checks = []
    for assertion in assertions:
        actual, found = result, True
        for part in assertion['field'].split('.'):
            if not isinstance(actual, dict) or part not in actual:
                found = False
                break
            actual = actual[part]
        expected, operator = assertion['value'], assertion['op']
        passed, evaluated = False, False
        if found:
            # Do not let True equal 1, or silently compare strings and numeric values.
            same_type = type(actual) is type(expected) or (type(actual) in (int, float) and type(expected) in (int, float))
            if same_type:
                evaluated = operator in ('eq', 'ne') or (type(actual) in (int, float) and type(expected) in (int, float))
                if operator == 'eq': passed = actual == expected
                elif operator == 'ne': passed = actual != expected
                elif type(actual) in (int, float) and type(expected) in (int, float):
                    if operator == 'gt': passed = actual > expected
                    elif operator == 'gte': passed = actual >= expected
                    elif operator == 'lt': passed = actual < expected
                    elif operator == 'lte': passed = actual <= expected
        checks.append({'field': assertion['field'], 'op': operator, 'expected': expected,
                       'observed': actual if found and isinstance(actual, (str, int, float, bool, type(None))) else None,
                       'found': found, 'evaluated': evaluated, 'passed': passed})
    return checks


def outcome_for(checks):
    if not all(c['evaluated'] for c in checks):
        return 'inconclusive'
    return 'supports' if all(c['passed'] for c in checks) else 'refutes'


class Workflow:
    def __init__(self, core):
        self.core, self.db = core, core.db

    def _ready(self, case):
        row = self.core.authorize(case)
        if row['paused']:
            raise CoreError('Investigation is paused')
        return row

    def _commit_guard(self, case):
        if not self.db.in_transaction:
            self.db.execute('BEGIN IMMEDIATE')
        self._ready(case)

    def _row(self, table, case, identifier):
        if table not in ('hypothesis_records', 'experiments', 'experiment_runs'):
            raise CoreError('Invalid record type')
        row = self.db.execute('SELECT * FROM ' + table + ' WHERE id=? AND case_id=?', (identifier, case)).fetchone()
        if row is None:
            raise CoreError('Unknown record in this investigation')
        return dict(row)

    def _reopen(self, case):
        self.core.reopen(case, reason='Scientific record changed')

    def add_hypothesis(self, case, statement, *, author, plausibility=.5):
        self._ready(case)
        statement, author = text(statement, 'hypothesis'), text(author, 'author', 200)
        if isinstance(plausibility, bool) or not isinstance(plausibility, (int, float)) or not math.isfinite(plausibility) or not 0 <= plausibility <= 1:
            raise CoreError('Plausibility must be a finite value from zero to one')
        identifier = uuid4().hex
        with self.db:
            self._commit_guard(case)
            self.db.execute('INSERT INTO hypothesis_records(id,case_id,statement,author,plausibility,created) VALUES(?,?,?,?,?,?)',
                            (identifier, case, statement, author, plausibility, utc()))
            record = self._row('hypothesis_records', case, identifier)
            self.db.execute('INSERT INTO hypothesis_history(hypothesis_id,revision,data,reason,author,created) VALUES(?,?,?,?,?,?)',
                            (identifier, 1, encoded(record), 'Initial hypothesis', author, utc()))
            self._reopen(case)
            audit(self.db, case, 'hypothesis_registered', {'id': identifier, 'author': author, 'plausibility': plausibility})
        return identifier

    def revise_hypothesis(self, case, hypothesis, *, author, plausibility, reason):
        self._ready(case)
        before = self._row('hypothesis_records', case, hypothesis)
        author, reason = text(author, 'author', 200), text(reason, 'revision reason')
        if isinstance(plausibility, bool) or not isinstance(plausibility, (int, float)) or not math.isfinite(plausibility) or not 0 <= plausibility <= 1:
            raise CoreError('Invalid plausibility')
        with self.db:
            self._commit_guard(case)
            self.db.execute("UPDATE hypothesis_records SET plausibility=?,revision=revision+1,status='OPEN' WHERE id=?", (plausibility, hypothesis))
            record = self._row('hypothesis_records', case, hypothesis)
            self.db.execute('INSERT INTO hypothesis_history(hypothesis_id,revision,data,reason,author,created) VALUES(?,?,?,?,?,?)',
                            (hypothesis, record['revision'], encoded(record), reason, author, utc()))
            self._reopen(case)
            audit(self.db, case, 'hypothesis_revised', {'id': hypothesis, 'revision': record['revision'], 'author': author, 'reason': reason})
        return record

    def history(self, case, hypothesis):
        self.core.get(case)
        self._row('hypothesis_records', case, hypothesis)
        return [dict(r) for r in self.db.execute('SELECT * FROM hypothesis_history WHERE hypothesis_id=? ORDER BY id', (hypothesis,))]

    def plan_experiment(self, case, hypothesis, name, *, author, criterion, assertions, tool, max_runs=3):
        self._ready(case)
        self._row('hypothesis_records', case, hypothesis)
        name, author, criterion = text(name, 'experiment name', 500), text(author, 'author', 200), text(criterion, 'criterion')
        assertions_checked(assertions)
        if tool not in ('analyze-file', 'assess-recovery', 'analyze-firmware', 'analyze-can', 'forensic') or not isinstance(max_runs, int) or not 1 <= max_runs <= 10:
            raise CoreError('Invalid experiment tool or attempt limit')
        plan_hash = result_digest({'hypothesis': hypothesis, 'assertions': assertions, 'tool': tool})
        if self.db.execute('SELECT 1 FROM experiments WHERE case_id=? AND plan_hash=?', (case, plan_hash)).fetchone():
            raise CoreError('Repeated experiment plan; reuse it or choose a different falsifiable test')
        identifier = uuid4().hex
        with self.db:
            self._commit_guard(case)
            self.db.execute('INSERT INTO experiments VALUES(?,?,?,?,?,?,?,?,?,?,?)',
                            (identifier, case, hypothesis, name, criterion, encoded(assertions), tool, author, max_runs, plan_hash, utc()))
            self._reopen(case)
            audit(self.db, case, 'experiment_planned', {'id': identifier, 'hypothesis': hypothesis, 'criterion': criterion, 'max_runs': max_runs})
        return identifier

    def evaluate(self, case, experiment, task, *, operator):
        self._ready(case)
        operator = text(operator, 'operator', 200)
        plan = self._row('experiments', case, experiment)
        hypothesis = self._row('hypothesis_records', case, plan['hypothesis_id'])
        result, digest = verified_result(self.core, case, task)
        if result.get('tool') != plan['tool']:
            raise CoreError('Result tool differs from experiment plan')
        fingerprint = observation_fingerprint(result, hypothesis['revision'])
        if self.db.execute('SELECT 1 FROM experiment_runs WHERE experiment_id=? AND observation_fingerprint=?', (experiment, fingerprint)).fetchone():
            with self.db:
                self._commit_guard(case)
                audit(self.db, case, 'experiment_repeat_rejected', {'experiment': experiment, 'fingerprint': fingerprint})
            raise CoreError('Repeated evidence does not establish new progress')
        if self.db.execute('SELECT COUNT(*) FROM experiment_runs WHERE experiment_id=?', (experiment,)).fetchone()[0] >= plan['max_runs']:
            raise CoreError('Experiment attempt limit exceeded; revise the investigation strategy')
        checks = evaluate_assertions(json.loads(plan['assertions']), result)
        outcome = outcome_for(checks)
        identifier = uuid4().hex
        with self.db:
            self._commit_guard(case)
            current = self._row('hypothesis_records', case, plan['hypothesis_id'])
            if current['revision'] != hypothesis['revision']:
                raise CoreError('Hypothesis changed during evaluation')
            if self.db.execute('SELECT COUNT(*) FROM experiment_runs WHERE experiment_id=?', (experiment,)).fetchone()[0] >= plan['max_runs']:
                raise CoreError('Experiment attempt limit exceeded')
            self.db.execute('INSERT INTO experiment_runs VALUES(?,?,?,?,?,?,?,?,?,?,?)',
                            (identifier, case, experiment, task, hypothesis['revision'], operator, outcome, encoded(checks), digest, fingerprint, utc()))
            self._refresh_status(case, hypothesis)
            self._reopen(case)
            audit(self.db, case, 'experiment_evaluated', {'run': identifier, 'experiment': experiment, 'task': task, 'outcome': outcome, 'evidence_digest': digest})
        return self._row('experiment_runs', case, identifier)

    def _latest_review(self, run):
        row = self.db.execute('SELECT * FROM peer_reviews WHERE run_id=? ORDER BY rowid DESC LIMIT 1', (run,)).fetchone()
        return dict(row) if row else None

    def _accepted(self, case, hypothesis):
        accepted = []
        for row in self.db.execute('SELECT r.* FROM experiment_runs r JOIN experiments e ON e.id=r.experiment_id WHERE r.case_id=? AND e.hypothesis_id=? AND r.hypothesis_revision=? ORDER BY r.created', (case, hypothesis['id'], hypothesis['revision'])):
            review = self._latest_review(row['id'])
            if review and review['decision'] == 'accepted':
                accepted.append((dict(row), review))
        return accepted

    def _refresh_status(self, case, hypothesis):
        records = self.db.execute('SELECT r.* FROM experiment_runs r JOIN experiments e ON e.id=r.experiment_id WHERE r.case_id=? AND e.hypothesis_id=? AND r.hypothesis_revision=?', (case, hypothesis['id'], hypothesis['revision'])).fetchall()
        pending = any(self._latest_review(row['id']) is None for row in records)
        outcomes = {row['outcome'] for row, _ in self._accepted(case, hypothesis)}
        status = 'OPEN' if pending else 'SUPPORTED' if outcomes == {'supports'} else 'REFUTED' if outcomes == {'refutes'} else 'CONFLICTING' if len(outcomes) > 1 else 'OPEN'
        self.db.execute('UPDATE hypothesis_records SET status=? WHERE id=?', (status, hypothesis['id']))

    def review(self, case, run, *, reviewer, decision, reason):
        self._ready(case)
        reviewer, reason = text(reviewer, 'reviewer', 200), text(reason, 'review rationale')
        record = self._row('experiment_runs', case, run)
        plan = self._row('experiments', case, record['experiment_id'])
        hypothesis = self._row('hypothesis_records', case, plan['hypothesis_id'])
        if identity(reviewer) in {identity(record['operator']), identity(plan['author']), identity(hypothesis['author'])}:
            raise CoreError('Independent review must use a different declared reviewer')
        if decision not in ('accepted', 'rejected'):
            raise CoreError('Invalid review decision')
        _, digest = verified_result(self.core, case, record['task_id'])
        if digest != record['evidence_digest'] or record['hypothesis_revision'] != hypothesis['revision']:
            raise CoreError('Review targets stale evidence or hypothesis revision')
        identifier = uuid4().hex
        with self.db:
            self._commit_guard(case)
            current = self._row('hypothesis_records', case, plan['hypothesis_id'])
            if current['revision'] != record['hypothesis_revision']:
                raise CoreError('Hypothesis changed during review')
            self.db.execute('INSERT INTO peer_reviews VALUES(?,?,?,?,?,?,?,?)',
                            (identifier, case, run, reviewer, decision, reason, digest, utc()))
            self._refresh_status(case, hypothesis)
            self._reopen(case)
            audit(self.db, case, 'independent_review_recorded', {'id': identifier, 'run': run, 'reviewer': reviewer, 'decision': decision, 'reason': reason})
        return identifier

    def add_source(self, case, *, title, url, version, provenance, author):
        self._ready(case)
        title, url, version, author = text(title, 'title', 500), text(url, 'source URL', 2000), text(version, 'source version', 200), text(author, 'author', 200)
        parsed = urlsplit(url)
        if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password or provenance not in ('documented', 'inference', 'experimental'):
            raise CoreError('Invalid source URL or provenance')
        identifier = uuid4().hex
        with self.db:
            self._commit_guard(case)
            self.db.execute('INSERT INTO source_records VALUES(?,?,?,?,?,?,?,?)', (identifier, case, title, url, version, provenance, author, utc()))
            self._reopen(case)
            audit(self.db, case, 'source_registered', {'id': identifier, 'url': url, 'version': version, 'provenance': provenance})
        return identifier

    def snapshot(self, case):
        self.core.get(case)
        data = {name: [dict(r) for r in self.db.execute('SELECT * FROM ' + table + ' WHERE case_id=? ORDER BY rowid', (case,))]
                for name, table in (('hypotheses', 'hypothesis_records'), ('experiments', 'experiments'), ('runs', 'experiment_runs'),
                                    ('reviews', 'peer_reviews'), ('sources', 'source_records'), ('verifications', 'verification_records'))}
        data['tasks'] = self.core.tasks(case)
        data['acquisitions'] = [dict(r) for r in self.db.execute('SELECT task_id,data FROM results WHERE case_id=? ORDER BY task_id', (case,))]
        return data

    def search(self, query, *, project=None, limit=20):
        query = text(query, 'history query', 500)
        if not isinstance(limit, int) or not 1 <= limit <= 100:
            raise CoreError('Invalid history limit')
        needle = '%' + query.replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_') + '%'
        return [dict(r) for r in self.db.execute("SELECT DISTINCT i.id,i.project,i.objective,i.state,i.created FROM investigations i LEFT JOIN hypothesis_records h ON h.case_id=i.id LEFT JOIN source_records s ON s.case_id=i.id WHERE (? IS NULL OR i.project=?) AND (i.objective LIKE ? ESCAPE '\\' OR h.statement LIKE ? ESCAPE '\\' OR s.title LIKE ? ESCAPE '\\') ORDER BY i.created DESC LIMIT ?", (project, project, needle, needle, needle, limit))]

    def finalize(self, case, state, *, actor, reason):
        self._ready(case)
        actor, reason = text(actor, 'actor', 200), text(reason, 'state rationale')
        allowed = ('RESOLVIDO', 'EM INVESTIGACAO', 'AGUARDANDO RECURSOS', 'SEM SOLUCAO VIAVEL DEMONSTRADA')
        if state not in allowed:
            raise CoreError('Unknown investigation state')
        snapshot = self.snapshot(case)
        validated = False
        if state in ('RESOLVIDO', 'SEM SOLUCAO VIAVEL DEMONSTRADA'):
            if any(t['status'] != 'done' for t in self.core.tasks(case)):
                raise CoreError('Pending or failed tasks require disposition before finalization')
            if not snapshot['hypotheses'] or any(h['status'] in ('OPEN', 'CONFLICTING') for h in snapshot['hypotheses']):
                raise CoreError('Open or conflicting hypotheses require further investigation')
            accepted = []
            for hypothesis in snapshot['hypotheses']:
                accepted.extend(self._accepted(case, hypothesis))
            current_revisions = {h['id']: h['revision'] for h in snapshot['hypotheses']}
            plan_hypotheses = {e['id']: e['hypothesis_id'] for e in snapshot['experiments']}
            for run in snapshot['runs']:
                if run['hypothesis_revision'] == current_revisions[plan_hypotheses[run['experiment_id']]] and self._latest_review(run['id']) is None:
                    raise CoreError('Every current experiment run needs independent review or explicit rejection')
            reviewed_plans = {r['experiment_id'] for r, _ in accepted}
            if reviewed_plans != {e['id'] for e in snapshot['experiments']}:
                raise CoreError('Every registered experiment needs an independent review for the current hypothesis revision')
            for run, review in accepted:
                result, digest = verified_result(self.core, case, run['task_id'])
                if digest != run['evidence_digest'] or digest != review['evidence_digest']:
                    raise CoreError('Stale reviewed evidence')
                plan = self._row('experiments', case, run['experiment_id'])
                checks = evaluate_assertions(json.loads(plan['assertions']), result)
                if encoded(checks) != run['checks'] or outcome_for(checks) != run['outcome']:
                    raise CoreError('Experiment outcome no longer matches reproducible checks')
            if state == 'RESOLVIDO' and not any(run['outcome'] == 'supports' for run, _ in accepted):
                raise CoreError('No supported and reviewed solution criterion was demonstrated')
            if state == 'SEM SOLUCAO VIAVEL DEMONSTRADA' and any(run['outcome'] == 'supports' for run, _ in accepted):
                raise CoreError('Supported solution conditions contradict a no-viable-solution conclusion')
            if state == 'SEM SOLUCAO VIAVEL DEMONSTRADA' and len(reviewed_plans) < 2:
                raise CoreError('More than a first strategy is required for a no-viable-solution conclusion')
            validated = state == 'RESOLVIDO'
        digest = result_digest(snapshot)
        identifier = uuid4().hex
        with self.db:
            self._commit_guard(case)
            if digest != result_digest(self.snapshot(case)):
                raise CoreError('Investigation changed during verification; inspect the new work before finalizing')
            self.db.execute('UPDATE investigations SET state=? WHERE id=?', (state, case))
            self.db.execute('INSERT INTO verification_records VALUES(?,?,?,?,?,?,?,?)', (identifier, case, state, actor, reason, digest, int(validated), utc()))
            audit(self.db, case, 'investigation_state_verified', {'state': state, 'actor': actor, 'reason': reason, 'validated': validated, 'snapshot_digest': digest})
        return {'id': identifier, 'state': state, 'validated': validated, 'snapshot_digest': digest}
