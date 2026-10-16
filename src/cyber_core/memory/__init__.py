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
CREATE TABLE IF NOT EXISTS task_limits(
 task_id TEXT PRIMARY KEY REFERENCES tasks(id), max_bytes INTEGER NOT NULL CHECK(max_bytes>=0));
CREATE TABLE IF NOT EXISTS hypotheses(
 id TEXT PRIMARY KEY, case_id TEXT NOT NULL REFERENCES investigations(id),
 task_id TEXT NOT NULL REFERENCES tasks(id), statement TEXT NOT NULL,
 plausibility TEXT NOT NULL, status TEXT NOT NULL, experiment TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS checkpoints(
 id INTEGER PRIMARY KEY, case_id TEXT NOT NULL REFERENCES investigations(id),
 event TEXT NOT NULL, data TEXT NOT NULL, created TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS audit(
 id INTEGER PRIMARY KEY, case_id TEXT NOT NULL REFERENCES investigations(id),
 event TEXT NOT NULL, data TEXT NOT NULL, created TEXT NOT NULL,
 previous TEXT NOT NULL, digest TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS task_queue ON tasks(case_id,status,lease_until);
'''


def connect(path):
    db = sqlite3.connect(path, timeout=10)
    db.row_factory = sqlite3.Row
    db.execute('PRAGMA foreign_keys=ON')
    db.execute('PRAGMA busy_timeout=10000')
    version = db.execute('PRAGMA user_version').fetchone()[0]
    if version not in (0, 1, 2):
        db.close()
        raise CoreError('Unsupported database version')
    db.executescript(SCHEMA)
    # Schema 2 adds optional persisted task byte caps; all schema-1 records remain valid.
    db.execute('PRAGMA user_version=2')
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
