"""Initial deterministic scheduler and explicitly approved cloud summary review."""
from cyber_core.agents.runner import CodexAdapter
from cyber_core.errors import CoreError
from cyber_core.memory import audit, encoded
from cyber_core.permissions import storage_root


def review_summary(core, case, *, allow_cloud=False):
    if not allow_cloud:
        raise CoreError('Cloud summary transfer requires explicit approval')
    row = core.authorize(case)
    if row['paused']:
        raise CoreError('Investigation is paused')
    # Only allowlisted derived fields: no file paths, filenames, objective, contents or authorization text.
    summary = {'observations': [{k: r[k] for k in ('size', 'entropy', 'format', 'copy_verified')} for r in core.results(case)],
               'question': 'Which additional static validation would distinguish a format signature from a valid file?'}
    folder = storage_root(core.home / 'agent-workspaces' / case)
    core.db.execute('BEGIN IMMEDIATE')
    try:
        core.authorize(case)
        if core.get(case)['agent_calls'] >= core.agent_calls_per_case:
            raise CoreError('Agent call budget exhausted')
        core.db.execute('UPDATE investigations SET agent_calls=agent_calls+1 WHERE id=?', (case,))
        audit(core.db, case, 'cloud_summary_authorized', {'fields': ['size', 'entropy', 'format', 'copy_verified']})
        core.db.commit()
    except BaseException:
        core.db.rollback()
        raise
    try:
        result = CodexAdapter(timeout=min(core.timeout, 120)).review(summary, folder)
    except CoreError as exc:
        with core.db:
            audit(core.db, case, 'agent_failed', {'error': str(exc)})
        raise
    with core.db:
        core.db.execute('BEGIN IMMEDIATE')
        core.authorize(case)
        audit(core.db, case, 'agent_review_proposed', result)
    return result
