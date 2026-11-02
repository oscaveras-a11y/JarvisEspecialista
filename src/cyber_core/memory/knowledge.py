"""Offline secure-programming knowledge index, isolated from operational case data."""
import json
import os
import re
import sqlite3
from importlib.resources import files
from pathlib import Path

_MAX_QUERY = 256
_MAX_LIMIT = 10

def default_database_path():
    if os.name == 'nt':
        root = Path(os.environ.get('LOCALAPPDATA') or Path.home()) / 'CyberCore'
    else:
        root = Path(os.environ.get('XDG_DATA_HOME') or (Path.home() / '.local' / 'share')) / 'cyber-core'
    return root / 'knowledge.sqlite3'

def _database_path(path=None):
    return Path(path).expanduser() if path else default_database_path()

def _catalog():
    resource = files('cyber_core.memory').joinpath('guides', 'catalog.json')
    entries = json.loads(resource.read_text(encoding='utf-8'))
    for item in entries:
        name = item['path']
        if not name.endswith('.md') or '/' in name or '\\\\' in name or name in ('.', '..'):
            raise ValueError('Invalid packaged guide path')
    return entries

def _connect(path):
    path.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(path)
    try:
        db.execute('CREATE VIRTUAL TABLE IF NOT EXISTS guide_search USING fts5(id UNINDEXED, topic UNINDEXED, title, body, sources, tokenize=\'unicode61 remove_diacritics 2\')')
        db.execute('PRAGMA user_version = 1')
        db.commit()
        return db
    except Exception:
        db.close()
        raise

def build_index(path=None):
    target = _database_path(path)
    catalog = _catalog()
    rows = []
    for entry in catalog:
        body = files('cyber_core.memory').joinpath('guides', entry['path']).read_text(encoding='utf-8')
        rows.append((entry['id'], entry['topic'], entry['title'], body, ' '.join(entry['sources'])))
    db = _connect(target)
    try:
        with db:
            db.execute('DELETE FROM guide_search')
            db.executemany('INSERT INTO guide_search(id,topic,title,body,sources) VALUES(?,?,?,?,?)', rows)
        return {'indexed': len(rows), 'database': str(target), 'topics': [r[1] for r in rows]}
    finally:
        db.close()

def search_index(query, path=None, limit=5):
    if not isinstance(query, str) or not query.strip() or len(query) > _MAX_QUERY:
        raise ValueError('Query must contain 1 to 256 characters')
    if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= _MAX_LIMIT:
        raise ValueError('Limit must be between 1 and 10')
    terms = re.findall(r'[^\\W_]+', query, flags=re.UNICODE)
    if not terms:
        raise ValueError('Query must include at least one searchable word')
    expression = ' AND '.join('"' + term.replace('"', '""') + '"' for term in terms)
    target = _database_path(path)
    if not target.is_file():
        raise FileNotFoundError('Knowledge index not found; run cyber knowledge index first')
    db = sqlite3.connect(target)
    db.row_factory = sqlite3.Row
    try:
        rows = db.execute('SELECT id, topic, title, snippet(guide_search,3,\'[\',\']\',\' … \',24) AS excerpt, sources FROM guide_search WHERE guide_search MATCH ? ORDER BY rank LIMIT ?', (expression, limit)).fetchall()
        return {'query': query, 'results': [dict(row) for row in rows], 'count': len(rows), 'database': str(target)}
    finally:
        db.close()
