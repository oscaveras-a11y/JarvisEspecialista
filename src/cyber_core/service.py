"""Application service: permissions, persistent tasks and scientific records."""
import hashlib
import json
from pathlib import Path
import sqlite3
import time
from uuid import uuid4
from cyber_core.errors import CoreError
from cyber_core.memory import audit, connect, encoded, utc, verify
from cyber_core.permissions import local_path, scoped_path, storage_root
from cyber_core.analysis_process import analyze_in_process


class Core:
    # A long sanity ceiling, not an operational deadline: a single authorized
    # task may run for hours or days, so the timeout only guards against absurd
    # or overflowing values, never cuts a legitimate long investigation short.
    MAX_TIMEOUT = 365 * 24 * 3600

    def __init__(self, home, *, max_bytes=64 * 1024 * 1024, timeout=60, max_attempts=3, agent_calls_per_case=5):
        if not 1 <= max_bytes <= 256 * 1024 * 1024 or not 0 < timeout <= self.MAX_TIMEOUT:
            raise CoreError('Invalid resource limits')
        if not 1 <= max_attempts <= 100 or not 0 <= agent_calls_per_case <= 100:
            raise CoreError('Invalid attempt or agent-call limits')
        self.home = storage_root(home)
        self.max_bytes, self.timeout = max_bytes, timeout
        self.max_attempts, self.agent_calls_per_case = max_attempts, agent_calls_per_case
        self.db = connect(self.home / 'core.sqlite3')

    def close(self):
        self.db.close()

    def backup(self, destination):
        # Durable backup of the whole local store (every case), via SQLite's own
        # backup API — safe against the live open connection, unlike a raw file
        # copy. Operational data, kept outside any single job and outside Git.
        target = Path(destination)
        name = target.name
        if not name or name in ('.', '..') or '/' in name or '\\' in name:
            raise CoreError('Invalid backup filename')
        parent = local_path(target.parent, directory=True)
        dest_path = parent / name
        if dest_path.exists() or dest_path.is_symlink():
            raise CoreError('Backup destination already exists')
        dest_conn = sqlite3.connect(str(dest_path), timeout=10)
        try:
            self.db.backup(dest_conn)
        except sqlite3.Error as exc:
            dest_conn.close()
            dest_path.unlink(missing_ok=True)
            raise CoreError('Backup failed') from exc
        dest_conn.close()
        return {'path': str(dest_path), 'size': dest_path.stat().st_size}

    @classmethod
    def restore(cls, home, source, **core_kwargs):
        # Restores a prior backup into a FRESH home directory, using SQLite's own
        # backup API (reads real database structures, not raw bytes, so a
        # truncated or foreign file is rejected rather than silently imported).
        # Refuses to overwrite an existing store. Returns a usable, open Core,
        # proving durable recovery outside the job/session that created the data.
        home_path = storage_root(home)
        destination = home_path / 'core.sqlite3'
        if destination.exists():
            raise CoreError('Restore target already has a store; back it up and remove it first')
        source_path = local_path(source)
        try:
            source_conn = sqlite3.connect(str(source_path), timeout=10)
            source_conn.execute('PRAGMA busy_timeout=10000')
        except sqlite3.Error as exc:
            raise CoreError('Backup source is not a readable SQLite database') from exc
        try:
            dest_conn = sqlite3.connect(str(destination), timeout=10)
            try:
                source_conn.backup(dest_conn)
            finally:
                dest_conn.close()
        except sqlite3.Error as exc:
            destination.unlink(missing_ok=True)
            raise CoreError('Restore failed; source may be corrupt or incompatible') from exc
        finally:
            source_conn.close()
        # Re-opening through the normal constructor validates the schema version
        # and applies any additive migrations, exactly as a fresh Core() would.
        return cls(home, **core_kwargs)

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
            from cyber_core.cryptanalysis.sessions import stop_case_sessions
            stop_case_sessions(self, case)
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
            exhausted = self.db.execute("SELECT id FROM tasks WHERE case_id=? AND status='running' AND lease_until<? AND attempts>=?", (case, now, self.max_attempts)).fetchall()
            for task in exhausted:
                self.db.execute("UPDATE tasks SET status='failed',error='Attempt budget exhausted' WHERE id=?", (task['id'],))
                audit(self.db, case, 'task_failed', {'task': task['id'], 'error': 'Attempt budget exhausted'})
            task = self.db.execute("SELECT * FROM tasks WHERE case_id=? AND (? IS NULL OR id=?) AND attempts<? AND (status='pending' OR (status='running' AND lease_until<?)) ORDER BY created,id LIMIT 1", (case, task_id, task_id, self.max_attempts, now)).fetchone()
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
                # Automatic entropy heuristic recorded as an analysis note, never a
                # scientific hypothesis; the scientific workflow owns hypothesis_records.
                self.db.execute('INSERT INTO analysis_notes VALUES(?,?,?,?,?,?)', (uuid4().hex, case, task['id'], statement, 'Validate with a format-specific parser and authorized metadata; entropy alone is insufficient', utc()))
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
                from cyber_core.cryptanalysis.sessions import stop_case_sessions
                stop_case_sessions(self, case)
                return {'id': case, 'state': 'CANCELADO', 'already_cancelled': True}
            self.db.execute("UPDATE investigations SET state='CANCELADO',paused=1 WHERE id=?", (case,))
            count = self.db.execute(
                "UPDATE tasks SET status='cancelled',lease_until=0,token=NULL,error='Investigation cancelled' "
                "WHERE case_id=? AND status IN ('pending','running')", (case,)).rowcount
            data = {'reason': reason.strip(), 'cancelled_tasks': count}
            self.db.execute('INSERT INTO checkpoints(case_id,event,data,created) VALUES(?,?,?,?)',
                            (case, 'cancelled', encoded(data), utc()))
            from cyber_core.cryptanalysis.sessions import stop_case_sessions
            stop_case_sessions(self, case)
            audit(self.db, case, 'investigation_cancelled', data)
        return {'id': case, 'state': 'CANCELADO', 'cancelled_tasks': count, 'already_cancelled': False}

    def pause(self, case):
        self.get(case)
        with self.db:
            self.db.execute('UPDATE investigations SET paused=1 WHERE id=?', (case,))
            self.db.execute('INSERT INTO checkpoints(case_id,event,data,created) VALUES(?,?,?,?)', (case, 'paused', '{}', utc()))
            from cyber_core.cryptanalysis.sessions import stop_case_sessions
            stop_case_sessions(self, case, state='paused')
            audit(self.db, case, 'paused', {})

    def reopen(self, case, *, reason):
        row = self.get(case)
        if row['state'] in ('RESOLVIDO', 'SEM SOLUCAO VIAVEL DEMONSTRADA', 'FALHA DE EXECUCAO'):
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

    def analysis_notes(self, case):
        self.get(case)
        return [dict(r) for r in self.db.execute('SELECT * FROM analysis_notes WHERE case_id=?', (case,))]

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

    def classify(self, case):
        row = self.authorize(case)
        self._ensure_not_paused(case, row)
        observed = None
        first = self.db.execute('SELECT data FROM results WHERE case_id=? ORDER BY created LIMIT 1', (case,)).fetchone()
        if first is not None:
            try:
                observed = json.loads(first['data']).get('format')
            except (ValueError, TypeError):
                observed = None
        from cyber_core.planning import classify_investigation
        result = classify_investigation(row['objective'], observed_format=observed)
        with self.db:
            self.authorize(case)
            self.db.execute('INSERT OR REPLACE INTO investigation_type(case_id,type,confidence,rationale,signals,created) VALUES(?,?,?,?,?,?)',
                            (case, result['type'], result['confidence'], result['rationale'], encoded(result['signals']), utc()))
            audit(self.db, case, 'investigation_classified', {'type': result['type'], 'confidence': result['confidence']})
        return result

    def plan(self, case):
        row = self.authorize(case)
        self._ensure_not_paused(case, row)
        stored = self.db.execute('SELECT type FROM investigation_type WHERE case_id=?', (case,)).fetchone()
        investigation_type = stored['type'] if stored is not None else self.classify(case)['type']
        from cyber_core.planning import build_plan
        steps = build_plan(investigation_type)
        plan_id = uuid4().hex
        with self.db:
            self.authorize(case)
            self.db.execute('INSERT INTO plans(id,case_id,investigation_type,author,created) VALUES(?,?,?,?,?)',
                            (plan_id, case, investigation_type, 'core', utc()))
            for ordinal, step in enumerate(steps):
                self.db.execute('INSERT INTO plan_steps(id,plan_id,case_id,ordinal,goal,candidate_tool,success_criterion,created) VALUES(?,?,?,?,?,?,?,?)',
                                (uuid4().hex, plan_id, case, ordinal, step['goal'], step['candidate_tool'], step['success_criterion'], utc()))
            self.reopen(case, reason='Execution plan created')
            audit(self.db, case, 'plan_created', {'plan': plan_id, 'type': investigation_type, 'steps': len(steps)})
        return {'plan': plan_id, 'type': investigation_type, 'steps': steps}

    def plans(self, case):
        self.get(case)
        out = []
        for row in self.db.execute('SELECT * FROM plans WHERE case_id=? ORDER BY created', (case,)):
            steps = [dict(s) for s in self.db.execute('SELECT * FROM plan_steps WHERE plan_id=? ORDER BY ordinal', (row['id'],))]
            out.append({**dict(row), 'steps': steps})
        return out

    @staticmethod
    def _decide_executor(tool):
        # Analysis/acquisition tools run locally in the CORE sandbox. Agents (Codex/
        # Claude) act on review via review_summary, never on raw evidence execution.
        return 'core', 'Local tool execution within the CORE; agents act only on review of derived metadata'

    def decompose(self, case, path, *, second_path=None, tool=None):
        row = self.authorize(case)
        self._ensure_not_paused(case, row)
        plan_row = self.db.execute('SELECT id,investigation_type FROM plans WHERE case_id=? ORDER BY created DESC LIMIT 1', (case,)).fetchone()
        if plan_row is None:
            created = self.plan(case)
            plan_id, investigation_type = created['plan'], created['type']
        else:
            plan_id, investigation_type = plan_row['id'], plan_row['investigation_type']
        from cyber_core.planning import select_tool
        chosen = tool or select_tool(investigation_type)['tool']
        with self.db:
            self.authorize(case)
            task = self._enqueue(case, path, tool=chosen, second_path=second_path)
            self.db.execute('INSERT INTO plan_tasks(task_id,plan_id,case_id,created) VALUES(?,?,?,?)', (task, plan_id, case, utc()))
            executor, reason = self._decide_executor(chosen)
            self.db.execute('INSERT OR REPLACE INTO task_assignments(task_id,case_id,executor,reason,created) VALUES(?,?,?,?,?)', (task, case, executor, reason, utc()))
            audit(self.db, case, 'plan_decomposed', {'plan': plan_id, 'task': task, 'tool': chosen, 'executor': executor})
        return {'plan': plan_id, 'type': investigation_type, 'tasks': [{'task': task, 'tool': chosen, 'executor': executor}]}

    def assign(self, case, task_id):
        case_row = self.authorize(case)
        self._ensure_not_paused(case, case_row)
        row = self.db.execute('SELECT id,tool FROM tasks WHERE id=? AND case_id=?', (task_id, case)).fetchone()
        if row is None:
            raise CoreError('Unknown task in this investigation')
        executor, reason = self._decide_executor(row['tool'])
        with self.db:
            self.authorize(case)
            self.db.execute('INSERT OR REPLACE INTO task_assignments(task_id,case_id,executor,reason,created) VALUES(?,?,?,?,?)', (task_id, case, executor, reason, utc()))
            audit(self.db, case, 'task_assigned', {'task': task_id, 'executor': executor})
        return {'task': task_id, 'executor': executor, 'reason': reason}

    def assignments(self, case):
        self.get(case)
        return [dict(r) for r in self.db.execute('SELECT * FROM task_assignments WHERE case_id=? ORDER BY created', (case,))]

    def set_authorization_basis(self, case, *, kind, authority, reference, examiner, scope_note):
        self.authorize(case)
        if kind not in ('owner_consent', 'legal_authority'):
            raise CoreError('Authorization basis kind must be owner_consent or legal_authority')
        values = {'authority': authority, 'reference': reference, 'examiner': examiner, 'scope_note': scope_note}
        for name, value in values.items():
            if not isinstance(value, str) or not value.strip():
                raise CoreError('Authorization basis requires a non-empty ' + name)
        with self.db:
            self.authorize(case)
            self.db.execute('INSERT OR REPLACE INTO authorization_basis(case_id,kind,authority,reference,examiner,scope_note,created) VALUES(?,?,?,?,?,?,?)',
                            (case, kind, authority.strip(), reference.strip(), examiner.strip(), scope_note.strip(), utc()))
            audit(self.db, case, 'authorization_basis_set', {'kind': kind, 'authority': authority.strip(), 'reference': reference.strip(), 'examiner': examiner.strip()})
        return {'case': case, 'kind': kind}

    def authorization_basis(self, case):
        self.get(case)
        row = self.db.execute('SELECT * FROM authorization_basis WHERE case_id=?', (case,)).fetchone()
        return dict(row) if row is not None else None

    def self_test_recovery(self, case, path, candidates, *, max_attempts=10000, max_seconds=30):
        row = self.authorize(case)
        self._ensure_not_paused(case, row)
        basis = self.db.execute('SELECT kind FROM authorization_basis WHERE case_id=?', (case,)).fetchone()
        if basis is None or basis['kind'] != 'owner_consent':
            raise CoreError('Self-test requires an owner_consent authorization basis on your own file')
        if not isinstance(candidates, (list, tuple)) or not 1 <= len(candidates) <= 100000:
            raise CoreError('Provide between 1 and 100000 candidate passphrases')
        if not 0 < max_attempts <= 100000 or not 0 < max_seconds <= 3600:
            raise CoreError('Invalid self-test limits')
        source = self.authorize(case, path)
        if source.stat().st_size > self.max_bytes:
            raise CoreError('Self-test file exceeds byte limit')
        envelope = source.read_bytes()
        from cyber_core.cryptanalysis.selftest import attempt
        result = attempt(envelope, candidates, max_attempts=max_attempts, deadline=time.monotonic() + max_seconds)
        result['recovery_demonstrated'] = result['recovered']
        # Audit records only the outcome, never the passphrase or the plaintext.
        with self.db:
            self.authorize(case)
            audit(self.db, case, 'self_test_recovery', {'recovered': result['recovered'], 'attempts': result['attempts'], 'status': result['status']})
        return result

    # recovery-session (cryptanalysis/sessions.py) requires candidate material
    # to already be a real file inside the case scope, capped at 8 MiB / one
    # candidate per line. This materializes a prefix of the bundled rockyou
    # wordlist as such a file, so the operator doesn't have to supply their
    # own list just to point recovery-session at a well-known one.
    MAX_WORDLIST_LINES = 100000

    def materialize_wordlist(self, case, output_path, *, source='rockyou', limit=100000):
        row = self.authorize(case)
        self._ensure_not_paused(case, row)
        if source != 'rockyou':
            raise CoreError('Unknown bundled wordlist source')
        if type(limit) is not int or not 1 <= limit <= self.MAX_WORDLIST_LINES:
            raise CoreError('Invalid wordlist line limit')
        target = Path(output_path)
        parent = local_path(target.parent, directory=True)
        if not parent.is_relative_to(local_path(row['scope'], directory=True)):
            raise CoreError('Wordlist must be materialized inside the authorized scope')
        name = target.name
        if not name or name in ('.', '..') or '/' in name or '\\' in name:
            raise CoreError('Invalid wordlist filename')
        destination = parent / name
        if destination.exists() or destination.is_symlink():
            raise CoreError('Wordlist path already exists')
        from cyber_core.cryptanalysis.wordlists import iter_builtin_wordlist
        written = 0
        with destination.open('xb') as handle:
            for candidate in iter_builtin_wordlist():
                if written >= limit:
                    break
                handle.write(candidate.encode('utf-8', errors='surrogateescape'))
                handle.write(b'\n')
                written += 1
        with self.db:
            self.authorize(case)
            audit(self.db, case, 'wordlist_materialized', {'source': source, 'lines': written, 'destination': str(destination)})
        return {'path': str(destination), 'source': source, 'lines': written}

    def materialize_generated_wordlist(self, case, output_path, words, *, limit=None):
        # "Layer 2" of the two-layer recovery design (docs/ai-assisted-
        # recovery-plan.md): rule-based expansion of operator-supplied hint
        # words (names, dates, references — not a password itself) into a
        # candidates file, same contract as materialize_wordlist. limit=None
        # (the default) means unbounded: generation keeps running, and the
        # file keeps growing, until interrupted from outside (Ctrl+C, the
        # consuming recovery-session being stopped, or the disk filling up).
        # The hint words are never audited: they can be identifying personal
        # details about the investigation subject, same handling as a secret.
        row = self.authorize(case)
        self._ensure_not_paused(case, row)
        target = Path(output_path)
        parent = local_path(target.parent, directory=True)
        if not parent.is_relative_to(local_path(row['scope'], directory=True)):
            raise CoreError('Wordlist must be materialized inside the authorized scope')
        name = target.name
        if not name or name in ('.', '..') or '/' in name or '\\' in name:
            raise CoreError('Invalid wordlist filename')
        destination = parent / name
        if destination.exists() or destination.is_symlink():
            raise CoreError('Wordlist path already exists')
        from cyber_core.cryptanalysis.wordlist_generator import generate_variations
        written = 0
        with destination.open('xb') as handle:
            for candidate in generate_variations(words, limit=limit):
                handle.write(candidate.encode('utf-8', errors='surrogateescape'))
                handle.write(b'\n')
                written += 1
        with self.db:
            self.authorize(case)
            audit(self.db, case, 'wordlist_materialized', {'source': 'generated', 'lines': written, 'destination': str(destination)})
        return {'path': str(destination), 'source': 'generated', 'lines': written}

    def materialize_bruteforce_wordlist(self, case, output_path, *, charset=None, min_length=1, max_length=None, limit=None):
        # True exhaustive enumeration, not hint-based — see
        # cryptanalysis.wordlist_generator.generate_bruteforce for why this
        # can only ever be exhaustive for short lengths (same contract/
        # authorization pattern as materialize_wordlist/materialize_generated_wordlist).
        # max_length=None and limit=None (the defaults) mean unbounded:
        # generation grows length without end until interrupted from
        # outside (Ctrl+C, the consuming recovery-session being stopped, or
        # the destination disk filling up).
        row = self.authorize(case)
        self._ensure_not_paused(case, row)
        target = Path(output_path)
        parent = local_path(target.parent, directory=True)
        if not parent.is_relative_to(local_path(row['scope'], directory=True)):
            raise CoreError('Wordlist must be materialized inside the authorized scope')
        name = target.name
        if not name or name in ('.', '..') or '/' in name or '\\' in name:
            raise CoreError('Invalid wordlist filename')
        destination = parent / name
        if destination.exists() or destination.is_symlink():
            raise CoreError('Wordlist path already exists')
        from cyber_core.cryptanalysis.wordlist_generator import generate_bruteforce
        written = 0
        with destination.open('xb') as handle:
            for candidate in generate_bruteforce(charset=charset, min_length=min_length, max_length=max_length, limit=limit):
                handle.write(candidate.encode('utf-8', errors='surrogateescape'))
                handle.write(b'\n')
                written += 1
        with self.db:
            self.authorize(case)
            audit(self.db, case, 'wordlist_materialized',
                  {'source': 'bruteforce', 'lines': written, 'destination': str(destination),
                   'min_length': min_length, 'max_length': max_length})
        return {'path': str(destination), 'source': 'bruteforce', 'lines': written}

    def make_lab_envelope(self, case, output_path, *, passphrase, content):
        # Create a CCPW1 lab target on the operator's OWN scope, to exercise the
        # recovery self-test end to end. Requires owner_consent; passphrase not logged.
        row = self.authorize(case)
        self._ensure_not_paused(case, row)
        basis = self.db.execute('SELECT kind FROM authorization_basis WHERE case_id=?', (case,)).fetchone()
        if basis is None or basis['kind'] != 'owner_consent':
            raise CoreError('Creating a lab envelope requires an owner_consent authorization basis')
        if not isinstance(passphrase, str) or not passphrase:
            raise CoreError('A passphrase is required to seal the lab envelope')
        if not isinstance(content, (bytes, bytearray)) or not 0 < len(content) <= self.max_bytes:
            raise CoreError('Lab content must be non-empty bytes within the byte limit')
        target = Path(output_path)
        parent = local_path(target.parent, directory=True)
        if not parent.is_relative_to(local_path(row['scope'], directory=True)):
            raise CoreError('Lab envelope must be inside the authorized scope')
        name = target.name
        if not name or name in ('.', '..') or '/' in name or '\\' in name:
            raise CoreError('Invalid lab envelope filename')
        destination = parent / name
        if destination.exists() or destination.is_symlink():
            raise CoreError('Lab envelope path already exists')
        from cyber_core.cryptanalysis.selftest import seal
        envelope = seal(passphrase, bytes(content))
        with destination.open('xb') as handle:
            handle.write(envelope)
            handle.flush()
        digest = hashlib.sha256(envelope).hexdigest()
        with self.db:
            self.authorize(case)
            audit(self.db, case, 'lab_envelope_created', {'path': str(destination), 'size': len(envelope), 'sha256': digest})
        return {'path': str(destination), 'size': len(envelope), 'format': 'CCPW1', 'sha256': digest}

    def recall_by_hash(self, sha256, *, limit=50):
        # Cross-investigation artifact recognition by SHA-256. Metadata only; never
        # exposes evidence content or stored copy paths. Reuses prior knowledge (item 5).
        if not isinstance(sha256, str) or len(sha256) != 64 or any(c not in '0123456789abcdefABCDEF' for c in sha256):
            raise CoreError('A 64-character hex SHA-256 is required')
        if not isinstance(limit, int) or not 1 <= limit <= 1000:
            raise CoreError('Invalid recall limit')
        needle = sha256.lower()
        matches = []
        # Scan the whole local store (no silent cap); only the number of matches is bounded.
        for row in self.db.execute('SELECT task_id,case_id,data,created FROM results ORDER BY created DESC'):
            try:
                data = json.loads(row['data'])
            except (ValueError, TypeError):
                continue
            if str(data.get('sha256', '')).lower() == needle:
                matches.append({'case_id': row['case_id'], 'task_id': row['task_id'],
                                'sha256': data.get('sha256'), 'format': data.get('format'),
                                'size': data.get('size'), 'created': row['created']})
                if len(matches) >= limit:
                    break
        return matches

    def _ensure_not_paused(self, case, row=None):
        # Matches the existing convention (cryptanalysis/intake.py, orchestrator/
        # __init__.py, CLI analyze-* handlers): new analytical work must not run
        # while an investigation is paused, even though authorize() itself allows
        # paused reads (status/logs/resume/revoke). Fix for a reviewed gap where
        # new side-analysis routes ignored pause.
        if (row if row is not None else self.get(case))['paused']:
            raise CoreError('Investigation is paused')

    def _persist_side_analysis(self, case, kind, path, result):
        # Persists the full (already-redacted-where-applicable) result so it is
        # reconstructable from normal case history, not only from audit-trail
        # counts. Fix for a reviewed gap (side analyses were audit-only).
        record_id = uuid4().hex
        with self.db:
            self.authorize(case)
            self.db.execute('INSERT INTO side_analyses(id,case_id,kind,path,data,created) VALUES(?,?,?,?,?,?)',
                            (record_id, case, kind, str(path), encoded(result), utc()))
        return record_id

    def side_analyses(self, case, *, kind=None):
        self.get(case)
        if kind is None:
            rows = self.db.execute('SELECT * FROM side_analyses WHERE case_id=? ORDER BY created', (case,))
        else:
            rows = self.db.execute('SELECT * FROM side_analyses WHERE case_id=? AND kind=? ORDER BY created', (case, kind))
        out = []
        for row in rows:
            entry = dict(row)
            entry['data'] = json.loads(entry['data'])
            out.append(entry)
        return out

    def extract_strings(self, case, path, *, min_length=4, max_strings=1000, max_sample=1048576):
        # Static string extraction (item 6) over a bounded prefix of an authorized file.
        # Strings go to the operator; persisted in side_analyses for later reconstruction.
        if not isinstance(max_sample, int) or not 1 <= max_sample <= 16 * 1024 * 1024:
            raise CoreError('Invalid string extraction sample limit')
        row = self.authorize(case)
        self._ensure_not_paused(case, row)
        source = self.authorize(case, path)
        if source.stat().st_size > self.max_bytes:
            raise CoreError('File exceeds byte limit')
        with source.open('rb') as handle:
            sample = handle.read(max_sample)
            truncated = bool(handle.read(1))
        from cyber_core.reverse_engineering.strings import extract_strings
        result = extract_strings(sample, min_length=min_length, max_strings=max_strings)
        result['sample_truncated'] = truncated
        self._persist_side_analysis(case, 'strings', source, result)
        with self.db:
            self.authorize(case)
            audit(self.db, case, 'strings_extracted', {'counts': result['counts'], 'min_length': min_length})
        return result

    def classify_source(self, url):
        # Offline source-authority heuristic (item 11); stateless, no web retrieval.
        from cyber_core.research import classify_source
        return classify_source(url)

    def sources(self, case):
        self.get(case)
        rows = self.db.execute('SELECT * FROM source_records WHERE case_id=? ORDER BY retrieved', (case,))
        out = []
        for row in rows:
            entry = dict(row)
            try:
                entry['authority'] = self.classify_source(entry['url'])['category']
            except CoreError:
                entry['authority'] = 'unknown'
            out.append(entry)
        return out

    @staticmethod
    def _capture_sample(source, maximum):
        # Read only up to the sample cap plus a one-byte peek, instead of reading
        # the whole file before slicing (fix for a reviewed gap where a large file
        # was read entirely and byte-level truncation was never reported), then
        # drop any trailing record the cut left incomplete: a byte-level cut
        # mid-record must never be counted as a complete message.
        with source.open('rb') as handle:
            raw = handle.read(maximum)
            truncated = bool(handle.read(1))
        partial = False
        if truncated and raw and not raw.endswith((b'\n', b'\r')):
            end = max(raw.rfind(b'\n'), raw.rfind(b'\r'))
            raw, partial = raw[:end + 1], True
        return raw.decode('utf-8', errors='replace'), truncated, partial

    def analyze_capture(self, case, path, *, second_path=None, max_sample=4194304):
        # Passive generic protocol-capture analysis (item 10). Static text capture;
        # never opens a bus/device/socket. Optional comparison with a second capture.
        if not isinstance(max_sample, int) or not 1 <= max_sample <= 16 * 1024 * 1024:
            raise CoreError('Invalid capture sample limit')
        row = self.authorize(case)
        self._ensure_not_paused(case, row)
        source = self.authorize(case, path)
        if source.stat().st_size > self.max_bytes:
            raise CoreError('File exceeds byte limit')
        text, clipped, partial = self._capture_sample(source, max_sample)
        from cyber_core.protocol import analyze_capture, compare_captures
        if second_path is not None:
            other = self.authorize(case, second_path)
            if other.stat().st_size > self.max_bytes:
                raise CoreError('Second file exceeds byte limit')
            other_text, other_clipped, other_partial = self._capture_sample(other, max_sample)
            result = compare_captures(text, other_text)
            # Each side keeps its OWN truncation/partial-record signal — a large
            # first file must not make the second file's untruncated result claim
            # truncation it never had (fix for a reviewed gap where both sides
            # shared a single byte_truncated flag).
            for sample, cut, tail in ((result['first'], clipped, partial),
                                      (result['second'], other_clipped, other_partial)):
                sample['truncated'] = sample['truncated'] or cut
                sample['sample_truncated'] = cut
                sample['partial_record_discarded'] = tail
            result['sample_truncated'] = clipped or other_clipped
            result['comparison_truncated'] = result['comparison_truncated'] or clipped or other_clipped
            event = {'messages': result['first']['messages'], 'second_messages': result['second']['messages']}
        else:
            result = analyze_capture(text)
            result['truncated'] = result['truncated'] or clipped
            result['sample_truncated'] = clipped
            result['partial_record_discarded'] = partial
            event = {'messages': result['messages'], 'unique_payloads': result['unique_payloads']}
        self._persist_side_analysis(case, 'capture', source, result)
        with self.db:
            self.authorize(case)
            audit(self.db, case, 'capture_analyzed', event)
        return result

    def inspect_disk_image(self, case, path, *, sector_size=512, max_bytes=16 * 1024 * 1024, max_partitions=256):
        # CORE wiring for forensics/disk.py (item 8), left as a separate step by
        # the module's own author: authorize, pause guard, bounded acquisition of
        # the WHOLE declared region up to max_bytes (the module needs the complete
        # image to validate GPT CRCs, so there is no byte-range "peek"; the byte
        # limit itself is the acquisition bound), persist for reconstruction.
        row = self.authorize(case)
        self._ensure_not_paused(case, row)
        source = self.authorize(case, path)
        if source.stat().st_size > min(self.max_bytes, max_bytes):
            raise CoreError('Disk image exceeds byte limit')
        data = source.read_bytes()
        from cyber_core.forensics.disk import inspect_disk_image
        try:
            result = inspect_disk_image(data, sector_size=sector_size, max_bytes=max_bytes, max_partitions=max_partitions)
        except ValueError as exc:
            raise CoreError('Disk image inventory failed: ' + str(exc)) from exc
        self._persist_side_analysis(case, 'disk_inventory', source, result)
        with self.db:
            self.authorize(case)
            audit(self.db, case, 'disk_image_inspected', {'format': result.get('format'), 'sha256': result.get('sha256')})
        return result

    def inspect_pcap(self, case, path, *, max_bytes=16 * 1024 * 1024, max_packets=256):
        # CORE wiring for protocols_pcap.py (item 10), same pattern as above.
        row = self.authorize(case)
        self._ensure_not_paused(case, row)
        source = self.authorize(case, path)
        if source.stat().st_size > min(self.max_bytes, max_bytes):
            raise CoreError('PCAP file exceeds byte limit')
        data = source.read_bytes()
        from cyber_core.protocols_pcap import inspect_pcap
        try:
            result = inspect_pcap(data, max_bytes=max_bytes, max_packets=max_packets)
        except ValueError as exc:
            raise CoreError('PCAP inventory failed: ' + str(exc)) from exc
        self._persist_side_analysis(case, 'pcap_inventory', source, result)
        with self.db:
            self.authorize(case)
            audit(self.db, case, 'pcap_inspected', {'packets': len(result.get('packets', [])), 'sha256': result.get('sha256')})
        return result

    def audit_crypto_implementation(self, case, path, *, max_sample=1048576):
        # Static audit of cryptographic implementation patterns (item 7: "auditar
        # a segurança de implementações criptográficas"). No execution, no key
        # derivation, no network. Findings are redacted; persisted so they are
        # reconstructable from case history, like the other side analyses.
        if not isinstance(max_sample, int) or not 1 <= max_sample <= 16 * 1024 * 1024:
            raise CoreError('Invalid audit sample limit')
        row = self.authorize(case)
        self._ensure_not_paused(case, row)
        source = self.authorize(case, path)
        if source.stat().st_size > self.max_bytes:
            raise CoreError('File exceeds byte limit')
        with source.open('rb') as handle:
            sample = handle.read(max_sample)
            truncated = bool(handle.read(1))
        from cyber_core.cryptanalysis.implementation_audit import audit_implementation
        result = audit_implementation(sample.decode('utf-8', errors='replace'))
        result['sample_truncated'] = truncated
        self._persist_side_analysis(case, 'crypto_audit', source, result)
        with self.db:
            self.authorize(case)
            audit(self.db, case, 'crypto_implementation_audited', {'summary': result['summary'], 'findings': len(result['findings'])})
        return result

    def configure_yara_rules(self, rules_path):
        # Trusted host configuration, never evidence-derived — same posture as
        # configure_external_tools for Ghidra/Binwalk (item 9).
        from cyber_core.vulnerability.yara_scan import configure_rules
        self.yara_rules_path = configure_rules(rules_path)

    def scan_with_yara(self, case, path, *, max_sample=1048576, timeout=10):
        # Static YARA signature scan (item 9) over a bounded prefix of an
        # authorized file. No active scan, no network. Matched byte content
        # never leaves yara_scan.scan_bytes; persisted so the finding is
        # reconstructable from case history, like the other side analyses.
        if not isinstance(max_sample, int) or not 1 <= max_sample <= 16 * 1024 * 1024:
            raise CoreError('Invalid YARA scan sample limit')
        rules_path = getattr(self, 'yara_rules_path', None)
        if rules_path is None:
            raise CoreError('Configure YARA rules first with configure_yara_rules')
        row = self.authorize(case)
        self._ensure_not_paused(case, row)
        source = self.authorize(case, path)
        if source.stat().st_size > self.max_bytes:
            raise CoreError('File exceeds byte limit')
        with source.open('rb') as handle:
            sample = handle.read(max_sample)
            truncated = bool(handle.read(1))
        from cyber_core.vulnerability.yara_scan import scan_bytes
        result = scan_bytes(sample, rules_path, timeout=timeout)
        result['sample_truncated'] = truncated
        self._persist_side_analysis(case, 'yara_scan', source, result)
        with self.db:
            self.authorize(case)
            audit(self.db, case, 'yara_scanned', {'matches': len(result.get('matches', [])), 'status': result['status']})
        return result

    def audit_config(self, case, path, *, max_sample=1048576):
        # Static, authorized configuration/exposure audit (item 9). No active scan,
        # no network. Findings are redacted; persisted so they are reconstructable
        # from case history (not only from audit-trail counts).
        if not isinstance(max_sample, int) or not 1 <= max_sample <= 16 * 1024 * 1024:
            raise CoreError('Invalid audit sample limit')
        row = self.authorize(case)
        self._ensure_not_paused(case, row)
        source = self.authorize(case, path)
        if source.stat().st_size > self.max_bytes:
            raise CoreError('File exceeds byte limit')
        with source.open('rb') as handle:
            sample = handle.read(max_sample)
            truncated = bool(handle.read(1))
        from cyber_core.vulnerability import audit_config
        result = audit_config(sample.decode('utf-8', errors='replace'))
        result['sample_truncated'] = truncated
        self._persist_side_analysis(case, 'config_audit', source, result)
        with self.db:
            self.authorize(case)
            audit(self.db, case, 'config_audited', {'summary': result['summary'], 'findings': len(result['findings'])})
        return result

    def custody_timeline(self, case):
        # Forensic timeline / chain-of-custody view (item 8), assembled from the
        # hash-linked audit trail. Read-only; surfaces only audited metadata.
        self.get(case)
        chain_valid = self.verify_audit(case)
        events = []
        for row in self.audit(case):
            try:
                data = json.loads(row['data'])
            except (ValueError, TypeError):
                data = {}
            entry = {'seq': row['id'], 'utc': row['created'], 'event': row['event'], 'digest': row['digest']}
            for key in ('sha256', 'result_digest', 'source', 'copy', 'task', 'owner', 'actor', 'reviewer', 'size'):
                if key in data:
                    entry[key] = data[key]
            events.append(entry)
        acquisitions = [{'task': e.get('task'), 'sha256': e.get('sha256'), 'size': e.get('size'), 'copy': e.get('copy'), 'utc': e['utc']}
                        for e in events if e['event'] == 'analysis_verified']
        return {'case': case, 'chain_valid': chain_valid, 'generated_utc': utc(),
                'events': events, 'acquisitions': acquisitions,
                'limitations': ['Cadeia encadeada por SHA-256: detecta edição, mas não é assinatura digital nem custódia imutável.',
                                'Para custódia forense formal, use retenção externa assinada e mídia protegida contra escrita.']}

    def differentiate_content(self, case, path, *, max_sample=65536):
        # Static differentiation (item 7): encoding vs compression vs encryption vs
        # structured, over a bounded prefix. Never asserts encryption from entropy alone.
        if not isinstance(max_sample, int) or not 1 <= max_sample <= 262144:
            raise CoreError('Invalid differentiation sample limit')
        row = self.authorize(case)
        self._ensure_not_paused(case, row)
        source = self.authorize(case, path)
        if source.stat().st_size > self.max_bytes:
            raise CoreError('File exceeds byte limit')
        with source.open('rb') as handle:
            sample = handle.read(max_sample)
            truncated = bool(handle.read(1))
        from cyber_core.cryptanalysis.differentiate import differentiate
        result = differentiate(sample, sample_truncated=truncated)
        self._persist_side_analysis(case, 'differentiate', source, result)
        with self.db:
            self.authorize(case)
            audit(self.db, case, 'content_differentiated', {'content_class': result['content_class'], 'label': result['label']})
        return result

    def recall_by_type(self, investigation_type, *, limit=20):
        # Prior investigations of a given type, to reuse approaches (item 5).
        if not isinstance(investigation_type, str) or not investigation_type.strip():
            raise CoreError('An investigation type is required')
        if not isinstance(limit, int) or not 1 <= limit <= 100:
            raise CoreError('Invalid recall limit')
        rows = self.db.execute('SELECT t.case_id,i.objective,i.state,t.type,t.confidence,t.created '
                               'FROM investigation_type t JOIN investigations i ON i.id=t.case_id '
                               'WHERE t.type=? ORDER BY t.created DESC LIMIT ?', (investigation_type.strip(), limit))
        return [dict(r) for r in rows]
