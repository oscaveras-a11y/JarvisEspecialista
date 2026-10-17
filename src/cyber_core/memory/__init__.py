"""Versioned SQLite schema and hash-linked audit events."""
import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from cyber_core.errors import CoreError


def utc():
    return datetime.now(timezone.utc).isoformat()


def encoded(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(',', ':'))


SCHEMA = '''
CREATE TABLE IF NOT EXISTS investigations(
 id TEXT PRIMARY KEY, project TEXT NOT NULL, objective TEXT NOT NULL,
 scope TEXT NOT NULL, owner TEXT NOT NULL, reason TEXT NOT NULL,
 expires REAL NOT NULL, revoked INTEGER NOT NULL DEFAULT 0,
 state TEXT NOT NULL DEFAULT 'EM INVESTIGACAO', paused INTEGER NOT NULL DEFAULT 0,
 created TEXT NOT NULL, recovery_allowed INTEGER NOT NULL DEFAULT 0,
 recovery_attempts INTEGER NOT NULL DEFAULT 0, agent_calls INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS tasks(
 id TEXT PRIMARY KEY, case_id TEXT NOT NULL REFERENCES investigations(id),
 tool TEXT NOT NULL, path TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending',
 attempts INTEGER NOT NULL DEFAULT 0, lease_until REAL NOT NULL DEFAULT 0,
 token TEXT, error TEXT, created TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS results(
 task_id TEXT PRIMARY KEY REFERENCES tasks(id), case_id TEXT NOT NULL REFERENCES investigations(id),
 data TEXT NOT NULL, created TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS task_parameters(
 task_id TEXT PRIMARY KEY REFERENCES tasks(id), data TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS task_limits(
 task_id TEXT PRIMARY KEY REFERENCES tasks(id), max_bytes INTEGER NOT NULL CHECK(max_bytes>=0));
CREATE TABLE IF NOT EXISTS checkpoints(
 id INTEGER PRIMARY KEY, case_id TEXT NOT NULL REFERENCES investigations(id),
 event TEXT NOT NULL, data TEXT NOT NULL, created TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS audit(
 id INTEGER PRIMARY KEY, case_id TEXT NOT NULL REFERENCES investigations(id),
 event TEXT NOT NULL, data TEXT NOT NULL, created TEXT NOT NULL,
 previous TEXT NOT NULL, digest TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS task_queue ON tasks(case_id,status,lease_until);
CREATE TABLE IF NOT EXISTS hypothesis_records(
 id TEXT PRIMARY KEY, case_id TEXT NOT NULL REFERENCES investigations(id), statement TEXT NOT NULL,
 author TEXT NOT NULL, plausibility REAL NOT NULL CHECK(plausibility>=0 AND plausibility<=1),
 status TEXT NOT NULL DEFAULT 'OPEN', revision INTEGER NOT NULL DEFAULT 1, created TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS hypothesis_history(
 id INTEGER PRIMARY KEY, hypothesis_id TEXT NOT NULL REFERENCES hypothesis_records(id),
 revision INTEGER NOT NULL, data TEXT NOT NULL, reason TEXT NOT NULL, author TEXT NOT NULL, created TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS experiments(
 id TEXT PRIMARY KEY, case_id TEXT NOT NULL REFERENCES investigations(id),
 hypothesis_id TEXT NOT NULL REFERENCES hypothesis_records(id), name TEXT NOT NULL, criterion TEXT NOT NULL,
 assertions TEXT NOT NULL, tool TEXT NOT NULL, author TEXT NOT NULL, max_runs INTEGER NOT NULL,
 plan_hash TEXT NOT NULL, created TEXT NOT NULL, UNIQUE(case_id,plan_hash));
CREATE TABLE IF NOT EXISTS experiment_runs(
 id TEXT PRIMARY KEY, case_id TEXT NOT NULL REFERENCES investigations(id), experiment_id TEXT NOT NULL REFERENCES experiments(id),
 task_id TEXT NOT NULL REFERENCES tasks(id), hypothesis_revision INTEGER NOT NULL, operator TEXT NOT NULL,
 outcome TEXT NOT NULL, checks TEXT NOT NULL, evidence_digest TEXT NOT NULL, observation_fingerprint TEXT NOT NULL,
 created TEXT NOT NULL, UNIQUE(experiment_id,observation_fingerprint));
CREATE TABLE IF NOT EXISTS peer_reviews(
 id TEXT PRIMARY KEY, case_id TEXT NOT NULL REFERENCES investigations(id), run_id TEXT NOT NULL REFERENCES experiment_runs(id),
 reviewer TEXT NOT NULL, decision TEXT NOT NULL, reason TEXT NOT NULL, evidence_digest TEXT NOT NULL, created TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS source_records(
 id TEXT PRIMARY KEY, case_id TEXT NOT NULL REFERENCES investigations(id), title TEXT NOT NULL, url TEXT NOT NULL,
 version TEXT NOT NULL, provenance TEXT NOT NULL, author TEXT NOT NULL, retrieved TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS verification_records(
 id TEXT PRIMARY KEY, case_id TEXT NOT NULL REFERENCES investigations(id), state TEXT NOT NULL,
 actor TEXT NOT NULL, reason TEXT NOT NULL, snapshot_digest TEXT NOT NULL, validated INTEGER NOT NULL, created TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS analysis_notes(
 id TEXT PRIMARY KEY, case_id TEXT NOT NULL REFERENCES investigations(id),
 task_id TEXT NOT NULL REFERENCES tasks(id), statement TEXT NOT NULL,
 basis TEXT NOT NULL, created TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS investigation_type(
 case_id TEXT PRIMARY KEY REFERENCES investigations(id),
 type TEXT NOT NULL, confidence REAL NOT NULL, rationale TEXT NOT NULL,
 signals TEXT NOT NULL, created TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS plans(
 id TEXT PRIMARY KEY, case_id TEXT NOT NULL REFERENCES investigations(id),
 investigation_type TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'OPEN',
 author TEXT NOT NULL, created TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS plan_steps(
 id TEXT PRIMARY KEY, plan_id TEXT NOT NULL REFERENCES plans(id),
 case_id TEXT NOT NULL REFERENCES investigations(id), ordinal INTEGER NOT NULL,
 goal TEXT NOT NULL, candidate_tool TEXT NOT NULL, success_criterion TEXT NOT NULL,
 status TEXT NOT NULL DEFAULT 'pending', created TEXT NOT NULL,
 UNIQUE(plan_id, ordinal));
CREATE TABLE IF NOT EXISTS plan_tasks(
 task_id TEXT PRIMARY KEY REFERENCES tasks(id), plan_id TEXT NOT NULL REFERENCES plans(id),
 case_id TEXT NOT NULL REFERENCES investigations(id), created TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS task_assignments(
 task_id TEXT PRIMARY KEY REFERENCES tasks(id), case_id TEXT NOT NULL REFERENCES investigations(id),
 executor TEXT NOT NULL, reason TEXT NOT NULL, created TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS authorization_basis(
 case_id TEXT PRIMARY KEY REFERENCES investigations(id),
 kind TEXT NOT NULL, authority TEXT NOT NULL, reference TEXT NOT NULL,
 examiner TEXT NOT NULL, scope_note TEXT NOT NULL, created TEXT NOT NULL);
'''


def connect(path):
    db = sqlite3.connect(path, timeout=10)
    db.row_factory = sqlite3.Row
    db.execute('PRAGMA foreign_keys=ON')
    db.execute('PRAGMA busy_timeout=10000')
    version = db.execute('PRAGMA user_version').fetchone()[0]
    if version not in (0, 1, 2, 3, 4, 5, 6, 7):
        db.close()
        raise CoreError('Unsupported database version')
    db.executescript(SCHEMA)
    # Additive schemas retain earlier investigations, audit chains and evidence.
    # Schema 4 unifies "hypothesis" on the scientific records; automatic entropy
    # heuristics move to analysis_notes. A legacy hypotheses table from an older
    # database is left untouched and simply no longer written to or reported.
    # Schema 5 adds CORE planning: investigation_type, plans and plan_steps.
    # Schema 6 adds decomposition/distribution: plan_tasks and task_assignments.
    # Schema 7 adds authorization_basis (owner consent / legal authority).
    db.execute('PRAGMA user_version=7')
    db.commit()
    return db


def audit(db, case, event, data):
    # A deferred context manager does not acquire a SQLite writer lock until DML.
    # Serialize BEFORE reading the chain predecessor, including append-only callers.
    if not db.in_transaction:
        db.execute('BEGIN IMMEDIATE')
    previous = db.execute('SELECT digest FROM audit WHERE case_id=? ORDER BY id DESC LIMIT 1', (case,)).fetchone()
    previous = previous[0] if previous else '0' * 64
    stamp, payload = utc(), encoded(data)
    digest = hashlib.sha256(encoded([case, event, payload, stamp, previous]).encode()).hexdigest()
    db.execute('INSERT INTO audit(case_id,event,data,created,previous,digest) VALUES(?,?,?,?,?,?)',
               (case, event, payload, stamp, previous, digest))


def verify(db, case):
    previous = '0' * 64
    for row in db.execute('SELECT * FROM audit WHERE case_id=? ORDER BY id', (case,)):
        digest = hashlib.sha256(encoded([case, row['event'], row['data'], row['created'], previous]).encode()).hexdigest()
        if row['previous'] != previous or row['digest'] != digest:
            return False
        previous = digest
    return True
