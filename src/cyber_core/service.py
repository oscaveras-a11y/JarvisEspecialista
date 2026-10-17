"""Application service: permissions, persistent tasks and scientific records."""
import hashlib
import json
from pathlib import Path
import time
from uuid import uuid4
from cyber_core.errors import CoreError
from cyber_core.memory import audit, connect, encoded, utc, verify
from cyber_core.permissions import local_path, scoped_path, storage_root
from cyber_core.analysis_process import analyze_in_process


class Core:
    def __init__(self, home, *, max_bytes=64 * 1024 * 1024, timeout=60):
        if not 1 <= max_bytes <= 256 * 1024 * 1024 or not 0 < timeout <= 3600:
            raise CoreError('Invalid resource limits')
        self.home = storage_root(home)
        self.max_bytes, self.timeout = max_bytes, timeout
        self.db = connect(self.home / 'core.sqlite3')

    def close(self):
        self.db.close()

    def investigate(self, project, objective, scope, owner, reason, *, recovery=False, valid_hours=24):
        if not all(str(v).strip() for v in (project, objective, scope, owner, reason)):
            raise CoreError('Project, objective, scope, owner and authorization reason are required')
        if not 0 < valid_hours <= 24 * 365:
            raise CoreError('Invalid authorization lifetime')
        root = local_path(scope, directory=True)
        case = uuid4().hex
        with self.db:
            self.db.execute('INSERT INTO investigations(id,project,objective,scope,owner,reason,expires,created,recovery_allowed) VALUES(?,?,?,?,?,?,?,?,?)',
                            (case, project, objective, str(root), owner, reason, time.time() + valid_hours * 3600, utc(), int(recovery)))
            audit(self.db, case, 'authorization_registered', {'owner': owner, 'scope': str(root), 'reason': reason, 'recovery': recovery})
        return case

    def get(self, case):
        row = self.db.execute('SELECT * FROM investigations WHERE id=?', (case,)).fetchone()
        if row is None:
            raise CoreError('Unknown investigation')
        return dict(row)

    def authorize(self, case, path=None, *, recovery=False):
        row = self.get(case)
        if row['state'] == 'CANCELADO':
            raise CoreError('Investigation is cancelled; create a new investigation to continue')
        if row['revoked'] or row['expires'] <= time.time():
            raise CoreError('Authorization revoked or expired')
        if recovery and not row['recovery_allowed']:
            raise CoreError('Explicit recovery authorization required')
        return scoped_path(path, row['scope']) if path is not None else row

    def revoke(self, case):
        self.get(case)
        with self.db:
            self.db.execute('UPDATE investigations SET revoked=1 WHERE id=?', (case,))
            audit(self.db, case, 'authorization_revoked', {})

    def enqueue(self, case, path, *, tool='analyze-file', second_path=None):
        with self.db:
            return self._enqueue(case, path, tool=tool, second_path=second_path)

    def _enqueue(self, case, path, *, tool, second_path=None):
        # Serialize the authorization check with cancellation and insertion.
        if not self.db.in_transaction:
            self.db.execute('BEGIN IMMEDIATE')
        if tool not in ('analyze-file', 'assess-recovery', 'analyze-firmware', 'analyze-can'):
            raise CoreError('Tool is not allowlisted')
        source = self.authorize(case, path, recovery=tool == 'assess-recovery')
        secondary = None
        if second_path is not None:
            if tool not in ('analyze-firmware', 'analyze-can'):
                raise CoreError('This tool does not support paired inputs')
            secondary = self.authorize(case, second_path)
        task = uuid4().hex
        self.db.execute('INSERT INTO tasks(id,case_id,tool,path,created) VALUES(?,?,?,?,?)', (task, case, tool, str(source), utc()))
        if secondary is not None:
            self.db.execute('INSERT INTO task_parameters VALUES(?,?)', (task, encoded({'secondary': str(secondary)})))
        self.reopen(case, reason='New task queued')
        audit(self.db, case, 'task_queued', {'task': task, 'tool': tool, 'source': str(source)})
        return task

    def _claim(self, case, task_id=None):
        self.db.execute('BEGIN IMMEDIATE')
        try:
            row = self.authorize(case)
            if row['paused']:
                raise CoreError('Investigation is paused')
            now = time.time()
            exhausted = self.db.execute("SELECT id FROM tasks WHERE case_id=? AND status='running' AND lease_until<? AND attempts>=3", (case, now)).fetchall()
            for task in exhausted:
                self.db.execute("UPDATE tasks SET status='failed',error='Attempt budget exhausted' WHERE id=?", (task['id'],))
                audit(self.db, case, 'task_failed', {'task': task['id'], 'error': 'Attempt budget exhausted'})
            task = self.db.execute("SELECT * FROM tasks WHERE case_id=? AND (? IS NULL OR id=?) AND attempts<3 AND (status='pending' OR (status='running' AND lease_until<?)) ORDER BY created,id LIMIT 1", (case, task_id, task_id, now)).fetchone()
            if task is None:
                self.db.commit()
                return None
            task = dict(task)
            token = uuid4().hex
            self.db.execute("UPDATE tasks SET status='running',attempts=attempts+1,lease_until=?,token=? WHERE id=?", (now + self.timeout + 30, token, task['id']))
            audit(self.db, case, 'task_started', {'task': task['id'], 'attempt': task['attempts'] + 1})
            self.db.commit()
            task['token'] = token
            return task
        except BaseException:
            self.db.rollback()
            raise

    def run_one(self, case, task_id=None, *, time_budget=None):
        budget = self.timeout if time_budget is None else time_budget
        if not 0 < budget <= self.timeout:
            raise CoreError('Invalid task time budget')
        started = time.monotonic()
        task = self._claim(case, task_id)
        if task is None:
            return None
        output, secondary_output = None, None
        try:
            recovery_assessment = task['tool'] == 'assess-recovery'
            if task['tool'] not in ('analyze-file', 'assess-recovery', 'analyze-firmware', 'analyze-can'):
                raise CoreError('Tool is not allowlisted')
            source = self.authorize(case, task['path'], recovery=recovery_assessment)
            folder = storage_root(self.home / 'cases' / case / 'evidence')
            output = folder / (task['id'] + '-' + task['token'] + '.evidence')
            limit = self.db.execute('SELECT max_bytes FROM task_limits WHERE task_id=?', (task['id'],)).fetchone()
            byte_limit = min(self.max_bytes, limit['max_bytes']) if limit is not None else self.max_bytes
            parameters = self.db.execute('SELECT data FROM task_parameters WHERE task_id=?', (task['id'],)).fetchone()
            secondary_source = None
            if parameters:
                secondary_source = self.authorize(case, json.loads(parameters['data'])['secondary'])
                secondary_output = folder / (task['id'] + '-' + task['token'] + '-secondary.evidence')

            def check_claim():
                self.authorize(case, recovery=recovery_assessment)
                current = self.db.execute('SELECT status,token FROM tasks WHERE id=?', (task['id'],)).fetchone()
                return 'claim replaced' if current['status'] != 'running' or current['token'] != task['token'] else None

            def record_process(pid):
                with self.db:
                    self.db.execute('BEGIN IMMEDIATE')
                    if check_claim():
                        raise CoreError('Analysis claim no longer active')
                    audit(self.db, case, 'analysis_process_started', {'task': task['id'], 'pid': pid,
                          'containment': 'process-lifecycle', 'privilege_sandbox': False})

            remaining = budget - (time.monotonic() - started)
            if remaining <= 0:
                raise CoreError('Analysis time budget exhausted')
            configured = getattr(self, 'external_tools', {})
            external = {'external_tools': configured} if task['tool'] == 'analyze-firmware' and configured else {}
            result = analyze_in_process(source, output, byte_limit, remaining, tool=task['tool'],
                                        secondary_source=secondary_source, secondary_destination=secondary_output,
                                        secondary_max_bytes=self.max_bytes, should_stop=check_claim,
                                        on_started=record_process, **external)
            result.update(task_id=task['id'], tool=task['tool'])
            if time.monotonic() - started > budget:
                raise CoreError('Analysis resource limit exceeded')
            with self.db:
                # Read state and publish under the same writer lock as cancel().
                self.db.execute('BEGIN IMMEDIATE')
                self.authorize(case, source, recovery=recovery_assessment)
                if secondary_source is not None:
                    self.authorize(case, secondary_source)
                current = self.db.execute('SELECT status,token FROM tasks WHERE id=?', (task['id'],)).fetchone()
                if current['status'] != 'running' or current['token'] != task['token']:
                    raise CoreError('Task lease was replaced')
                self.db.execute('INSERT INTO results VALUES(?,?,?,?)', (task['id'], case, encoded(result), utc()))
                statement = 'Possible compression or encryption' if result['entropy'] > 7.5 else 'Possible structured or repetitive data'
                self.db.execute('INSERT INTO hypotheses VALUES(?,?,?,?,?,?,?)', (uuid4().hex, case, task['id'], statement, 'unconfirmed', 'OPEN', 'Validate with a format-specific parser and authorized metadata; entropy alone is insufficient'))
                self.db.execute("UPDATE tasks SET status='done',lease_until=0 WHERE id=?", (task['id'],))
                self.db.execute('INSERT INTO checkpoints(case_id,event,data,created) VALUES(?,?,?,?)', (case, 'analysis_committed', encoded({'task': task['id'], 'sha256': result['sha256']}), utc()))
                from cyber_core.verification.artifacts import result_digest
                audit(self.db, case, 'analysis_verified', {'task': task['id'], 'sha256': result['sha256'], 'size': result['size'], 'source': str(source), 'copy': str(output), 'result_digest': result_digest(result)})
            return result
        except BaseException as exc:
            # An interrupt can arrive after SQLite commits, before returning to the caller.
            # A done claim owns durable evidence; never clean it up as a partial result.
            current = self.db.execute('SELECT status,token FROM tasks WHERE id=?', (task['id'],)).fetchone()
            if current['status'] == 'done' and current['token'] == task['token']:
                if not isinstance(exc, Exception):
                    raise
                raise CoreError('Analysis committed; inspect stored result before retrying') from exc
            if output:
                output.unlink(missing_ok=True)
            if secondary_output:
                secondary_output.unlink(missing_ok=True)
            interrupted = not isinstance(exc, Exception)
            message = ('Interrupted before commit' if interrupted else
                       str(exc) if isinstance(exc, CoreError) else 'Local analysis failed; see error type')
            with self.db:
                self.db.execute('BEGIN IMMEDIATE')
                current = self.db.execute('SELECT status,token,attempts FROM tasks WHERE id=?', (task['id'],)).fetchone()
                owns_claim = current['status'] == 'running' and current['token'] == task['token']
                if owns_claim:
                    # PR #3 supplies a configured limit; the current base defaults to three.
                    attempt_limit = getattr(self, 'max_attempts', 3)
                    status = 'pending' if interrupted and current['attempts'] < attempt_limit else 'failed'
                    self.db.execute('UPDATE tasks SET status=?,error=?,lease_until=0,token=NULL WHERE id=?',
                                    (status, message, task['id']))
                    event = 'task_interrupted' if interrupted else 'task_failed'
                    audit(self.db, case, event, {'task': task['id'], 'error': message, 'type': type(exc).__name__})
                else:
                    audit(self.db, case, 'analysis_discarded', {'task': task['id'], 'reason': 'Claim no longer active'})
            if interrupted:
                raise
            raise CoreError(message) from exc

    def run_queue(self, case, **limits):
        from cyber_core.orchestrator.worker import run_queue
        return run_queue(self, case, **limits)

    def configure_external_tools(self, config):
        from cyber_core.reverse_engineering.external import _config
        parsed = _config(config)
        self.external_tools = {name: {key: str(value) for key, value in fields.items()}
                               for name, fields in parsed.items()}

    def cancel(self, case, *, reason):
        if not isinstance(reason, str) or not reason.strip() or len(reason) > 1024:
            raise CoreError('Provide a cancellation reason of 1 to 1024 characters')
        with self.db:
            self.db.execute('BEGIN IMMEDIATE')
            row = self.get(case)
            if row['state'] == 'CANCELADO':
                return {'id': case, 'state': 'CANCELADO', 'already_cancelled': True}
            self.db.execute("UPDATE investigations SET state='CANCELADO',paused=1 WHERE id=?", (case,))
            count = self.db.execute(
                "UPDATE tasks SET status='cancelled',lease_until=0,token=NULL,error='Investigation cancelled' "
                "WHERE case_id=? AND status IN ('pending','running')", (case,)).rowcount
            data = {'reason': reason.strip(), 'cancelled_tasks': count}
            self.db.execute('INSERT INTO checkpoints(case_id,event,data,created) VALUES(?,?,?,?)',
                            (case, 'cancelled', encoded(data), utc()))
            audit(self.db, case, 'investigation_cancelled', data)
        return {'id': case, 'state': 'CANCELADO', 'cancelled_tasks': count, 'already_cancelled': False}

    def pause(self, case):
        self.get(case)
        with self.db:
            self.db.execute('UPDATE investigations SET paused=1 WHERE id=?', (case,))
            self.db.execute('INSERT INTO checkpoints(case_id,event,data,created) VALUES(?,?,?,?)', (case, 'paused', '{}', utc()))
            audit(self.db, case, 'paused', {})

    def reopen(self, case, *, reason):
        row = self.get(case)
        if row['state'] in ('RESOLVIDO', 'SEM SOLUCAO VIAVEL DEMONSTRADA'):
            self.db.execute("UPDATE investigations SET state='EM INVESTIGACAO' WHERE id=?", (case,))
            audit(self.db, case, 'investigation_reopened', {'previous': row['state'], 'reason': reason})

    def resume(self, case):
        with self.db:
            self.db.execute('BEGIN IMMEDIATE')
            self.authorize(case)
            self.db.execute('UPDATE investigations SET paused=0 WHERE id=?', (case,))
            audit(self.db, case, 'resumed', {})

    def tasks(self, case):
        self.get(case)
        return [dict(r) for r in self.db.execute('SELECT * FROM tasks WHERE case_id=? ORDER BY created,id', (case,))]

    def results(self, case):
        self.get(case)
        return [json.loads(r[0]) for r in self.db.execute('SELECT data FROM results WHERE case_id=? ORDER BY created', (case,))]

    def hypotheses(self, case):
        self.get(case)
        return [dict(r) for r in self.db.execute('SELECT * FROM hypotheses WHERE case_id=?', (case,))]

    def checkpoints(self, case):
        self.get(case)
        return [dict(r) for r in self.db.execute('SELECT * FROM checkpoints WHERE case_id=? ORDER BY id', (case,))]

    def audit(self, case):
        self.get(case)
        return [dict(r) for r in self.db.execute('SELECT * FROM audit WHERE case_id=? ORDER BY id', (case,))]

    def verify_audit(self, case):
        self.get(case)
        return verify(self.db, case)

    def report(self, case):
        from cyber_core.reporting import write_report
        return write_report(self, case)

    def recover(self, case, source, key, **expectations):
        from cyber_core.cryptanalysis import recover
        return recover(self, case, source, key, **expectations)

    def assess_recovery(self, case, path, **limits):
        from cyber_core.recovery import assess_recovery
        return assess_recovery(self, case, path, **limits)
