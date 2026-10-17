"""Additive item-4 storage; the global memory schema remains owned by item 5."""
from cyber_core.errors import CoreError

DDL = (
    """CREATE TABLE IF NOT EXISTS reasoning_meta(
        singleton INTEGER PRIMARY KEY CHECK(singleton=1), version INTEGER NOT NULL)""",
    """CREATE TABLE IF NOT EXISTS reasoning_strategies(
        id TEXT PRIMARY KEY, case_id TEXT NOT NULL REFERENCES investigations(id),
        experiment_id TEXT NOT NULL UNIQUE REFERENCES experiments(id),
        cost REAL NOT NULL, risk REAL NOT NULL, evidence TEXT NOT NULL, sources TEXT NOT NULL,
        alternative_to TEXT REFERENCES reasoning_strategies(id),
        rationale TEXT NOT NULL, actor TEXT NOT NULL, created TEXT NOT NULL)""",
    """CREATE TABLE IF NOT EXISTS reasoning_blockers(
        id TEXT PRIMARY KEY, case_id TEXT NOT NULL REFERENCES investigations(id),
        strategy_id TEXT NOT NULL REFERENCES reasoning_strategies(id),
        kind TEXT NOT NULL, detail TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'OPEN',
        actor TEXT NOT NULL, resolution TEXT, resolved_by TEXT, created TEXT NOT NULL)""",
    """CREATE TABLE IF NOT EXISTS reasoning_notes(
        id TEXT PRIMARY KEY, case_id TEXT NOT NULL REFERENCES investigations(id),
        kind TEXT NOT NULL CHECK(kind IN ('INFERENCE','UNKNOWN')),
        statement TEXT NOT NULL, actor TEXT NOT NULL, created TEXT NOT NULL)""",
    """CREATE TABLE IF NOT EXISTS reasoning_cycles(
        id TEXT PRIMARY KEY, case_id TEXT NOT NULL REFERENCES investigations(id),
        strategy_id TEXT NOT NULL REFERENCES reasoning_strategies(id),
        hypothesis_revision INTEGER NOT NULL, input_fingerprint TEXT NOT NULL,
        task_id TEXT NOT NULL UNIQUE REFERENCES tasks(id), run_id TEXT REFERENCES experiment_runs(id),
        status TEXT NOT NULL, outcome TEXT, error TEXT, created TEXT NOT NULL, updated TEXT NOT NULL,
        UNIQUE(strategy_id,hypothesis_revision,input_fingerprint))""",
)


def exists(db):
    return db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='reasoning_meta'").fetchone() is not None


def ensure(db):
    if exists(db):
        row = db.execute('SELECT version FROM reasoning_meta WHERE singleton=1').fetchone()
        if row is None or row[0] != 1:
            raise CoreError('Unsupported reasoning contract version')
        return
    if db.in_transaction:
        raise CoreError('Initialize reasoning outside an active transaction')
    with db:
        db.execute('BEGIN IMMEDIATE')
        for statement in DDL:
            db.execute(statement)
        db.execute('INSERT OR IGNORE INTO reasoning_meta VALUES(1,1)')
