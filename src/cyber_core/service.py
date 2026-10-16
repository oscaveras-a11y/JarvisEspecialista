"""Application service: permissions, persistent tasks and scientific records."""
import hashlib
import json
from pathlib import Path
import time
from uuid import uuid4
from cyber_core.errors import CoreError
from cyber_core.memory import audit, connect, encoded, utc, verify
from cyber_core.permissions import local_path, scoped_path, storage_root
from cyber_core.reverse_engineering import analyze


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

    def enqueue(self, case, path, *, tool='analyze-file'):
        if tool != 'analyze-file':
            raise CoreError('Tool is not allowlisted')
        source = self.authorize(case, path)
        task = uuid4().hex
        with self.db:
            self.db.execute('INSERT INTO tasks(id,case_id,tool,path,created) VALUES(?,?,?,?,?)', (task, case, tool, str(source), utc()))
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

    def run_one(self, case, task_id=None):
        task = self._claim(case, task_id)
        if task is None:
            return None
        output = None
        try:
            source = self.authorize(case, task['path'])
            folder = storage_root(self.home / 'cases' / case / 'evidence')
            output = folder / (task['id'] + '-' + task['token'] + '.evidence')
            result = analyze(source, output, self.max_bytes, self.timeout)
            with self.db:
                self.authorize(case, source)
                current = self.db.execute('SELECT status,token FROM tasks WHERE id=?', (task['id'],)).fetchone()
                if current['status'] != 'running' or current['token'] != task['token']:
                    raise CoreError('Task lease was replaced')
                self.db.execute('INSERT INTO results VALUES(?,?,?,?)', (task['id'], case, encoded(result), utc()))
                statement = 'Possible compression or encryption' if result['entropy'] > 7.5 else 'Possible structured or repetitive data'
                self.db.execute('INSERT INTO hypotheses VALUES(?,?,?,?,?,?,?)', (uuid4().hex, case, task['id'], statement, 'unconfirmed', 'OPEN', 'Validate with a format-specific parser and authorized metadata; entropy alone is insufficient'))
                self.db.execute("UPDATE tasks SET status='done',lease_until=0 WHERE id=?", (task['id'],))
                self.db.execute('INSERT INTO checkpoints(case_id,event,data,created) VALUES(?,?,?,?)', (case, 'analysis_committed', encoded({'task': task['id'], 'sha256': result['sha256']}), utc()))
                audit(self.db, case, 'analysis_verified', {'task': task['id'], 'sha256': result['sha256'], 'size': result['size'], 'source': str(source), 'copy': str(output)})
            return result
        except Exception as exc:
            if output:
                output.unlink(missing_ok=True)
            message = str(exc) if isinstance(exc, CoreError) else 'Local analysis failed; see error type'
            with self.db:
                self.db.execute("UPDATE tasks SET status='failed',error=?,lease_until=0 WHERE id=? AND token=?", (message, task['id'], task['token']))
                audit(self.db, case, 'task_failed', {'task': task['id'], 'error': message, 'type': type(exc).__name__})
            raise CoreError(message) from exc

    def pause(self, case):
        self.get(case)
        with self.db:
            self.db.execute('UPDATE investigations SET paused=1 WHERE id=?', (case,))
            self.db.execute('INSERT INTO checkpoints(case_id,event,data,created) VALUES(?,?,?,?)', (case, 'paused', '{}', utc()))
            audit(self.db, case, 'paused', {})

    def resume(self, case):
        self.authorize(case)
        with self.db:
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
