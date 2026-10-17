"""Private additive broker schema; never changes the CORE PRAGMA user_version."""
import json
import time
from uuid import uuid4

from cyber_core.errors import CoreError
from cyber_core.memory import audit, encoded, utc
from cyber_core.verification.artifacts import result_digest

SCHEMA = '''
CREATE TABLE IF NOT EXISTS agent_broker_meta(
 id INTEGER PRIMARY KEY CHECK(id=1), version INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS agent_jobs(
 id TEXT PRIMARY KEY, case_id TEXT NOT NULL REFERENCES investigations(id),
 agent TEXT NOT NULL, purpose TEXT NOT NULL,
 status TEXT NOT NULL DEFAULT 'pending', summary TEXT NOT NULL,
 snapshot_digest TEXT NOT NULL, summary_digest TEXT NOT NULL,
 depends_on TEXT REFERENCES agent_jobs(id), dependency_digest TEXT NOT NULL DEFAULT '',
 dedup_key TEXT NOT NULL UNIQUE,
 attempts INTEGER NOT NULL DEFAULT 0, sent INTEGER NOT NULL DEFAULT 0,
 lease_until REAL NOT NULL DEFAULT 0, token TEXT, response TEXT,
 response_digest TEXT, error TEXT, created TEXT NOT NULL, updated TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS agent_job_queue ON agent_jobs(case_id,status,lease_until);
'''

class Store:
    def __init__(self, core):
        self.core, self.db = core, core.db
        if self.db.in_transaction:
            raise CoreError('Initialize the agent broker outside an open transaction')
        self.db.executescript(SCHEMA)
        version = self.db.execute('SELECT version FROM agent_broker_meta WHERE id=1').fetchone()
        if version and version[0] != 1:
            raise CoreError('Unsupported agent broker database version')
        with self.db:
            self.db.execute('INSERT OR IGNORE INTO agent_broker_meta(id,version) VALUES(1,1)')

    def begin(self):
        if not self.db.in_transaction:
            self.db.execute('BEGIN IMMEDIATE')

    def row(self, case, job):
        record = self.db.execute('SELECT * FROM agent_jobs WHERE case_id=? AND id=?', (case, job)).fetchone()
        if record is None:
            raise CoreError('Unknown agent job in this investigation')
        return dict(record)

    @staticmethod
    def public(row):
        output = {key: value for key, value in row.items() if key not in ('token', 'dedup_key')}
        for key in ('summary', 'response'):
            output[key] = json.loads(output[key]) if output.get(key) is not None else None
        return output

    def event(self, case, event, payload):
        self.db.execute('INSERT INTO checkpoints(case_id,event,data,created) VALUES(?,?,?,?)',
                        (case, event, encoded(payload), utc()))
        audit(self.db, case, event, payload)

    def insert(self, case, agent, summary, snapshot, *, depends_on=None, dependency_digest=''):
        dedup = result_digest([case, agent, snapshot, depends_on, dependency_digest])
        old = self.db.execute('SELECT id FROM agent_jobs WHERE dedup_key=?', (dedup,)).fetchone()
        if old:
            return old[0]
        job, stamp = uuid4().hex, utc()
        digest = result_digest(summary)
        purpose = 'cross_review' if depends_on else 'primary_review'
        self.db.execute('''INSERT INTO agent_jobs
            (id,case_id,agent,purpose,summary,snapshot_digest,summary_digest,
             depends_on,dependency_digest,dedup_key,created,updated)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?)''',
            (job, case, agent, purpose, encoded(summary), snapshot, digest,
             depends_on, dependency_digest, dedup, stamp, stamp))
        self.event(case, 'agent_job_enqueued',
                   {'job': job, 'agent': agent, 'purpose': purpose, 'snapshot_digest': snapshot,
                    'summary_digest': digest, 'depends_on': depends_on, 'dependency_digest': dependency_digest})
        return job

    def recover(self, case):
        now = time.time()
        expired = self.db.execute("SELECT * FROM agent_jobs WHERE case_id=? AND status='running' AND lease_until<=?",
                                  (case, now)).fetchall()
        for row in expired:
            state = 'uncertain' if row['sent'] else 'pending'
            self.db.execute('UPDATE agent_jobs SET status=?,token=NULL,lease_until=0,error=?,updated=? WHERE id=?',
                            (state, 'interrupted_after_send' if row['sent'] else None, utc(), row['id']))
            self.event(case, 'agent_job_recovered', {'job': row['id'], 'status': state})

    def claim(self, case, *, job=None, lease_seconds=150):
        self.recover(case)
        if job:
            row = self.row(case, job)
            if row['status'] != 'pending':
                return None
        else:
            record = self.db.execute("SELECT * FROM agent_jobs WHERE case_id=? AND status='pending' ORDER BY rowid LIMIT 1",
                                     (case,)).fetchone()
            if record is None:
                return None
            row = dict(record)
        token = uuid4().hex
        self.db.execute("UPDATE agent_jobs SET status='running',token=?,sent=0,lease_until=?,updated=? WHERE id=?",
                        (token, time.time() + lease_seconds, utc(), row['id']))
        self.event(case, 'agent_job_claimed', {'job': row['id'], 'attempt': row['attempts'] + 1})
        return self.row(case, row['id'])

    def owned(self, case, job, token):
        row = self.row(case, job)
        if row['status'] != 'running' or row['token'] != token or row['lease_until'] <= time.time():
            raise CoreError('Agent job claim lost or expired')
        return row

    def finish(self, case, job, token, status, *, response=None, error=None):
        self.owned(case, job, token)
        digest = result_digest(response) if response is not None else None
        self.db.execute('''UPDATE agent_jobs SET status=?,response=?,response_digest=?,error=?,
                        token=NULL,lease_until=0,updated=? WHERE id=?''',
                        (status, encoded(response) if response is not None else None, digest, error, utc(), job))
        self.event(case, 'agent_job_completed' if status == 'done' else 'agent_job_stopped',
                   {'job': job, 'status': status, 'response_digest': digest, 'error': error})
        return self.public(self.row(case, job))
