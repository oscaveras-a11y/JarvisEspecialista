"""Bounded sequential workers over durable claims; no background service installation."""
import math
import time
from uuid import uuid4

from cyber_core.errors import CoreError
from cyber_core.memory import audit, encoded, utc


def _number(value, name, minimum, maximum):
    if type(value) not in (int, float) or not math.isfinite(value) or not minimum <= value <= maximum:
        raise CoreError('Invalid worker ' + name)
    return value


def _checkpoint(core, case, event, payload):
    with core.db:
        core.db.execute('BEGIN IMMEDIATE')
        core.db.execute('INSERT INTO checkpoints(case_id,event,data,created) VALUES(?,?,?,?)',
                        (case, event, encoded(payload), utc()))
        audit(core.db, case, event, payload)


def _counts(core, case):
    return {row['status']: row['count'] for row in core.db.execute(
        'SELECT status,COUNT(*) AS count FROM tasks WHERE case_id=? GROUP BY status', (case,))}


def run_queue(core, case, *, max_tasks=100, max_seconds=300, poll_interval=.2, idle_timeout=0):
    """Drain a case, or poll briefly for new work, under explicit per-invocation budgets."""
    if type(max_tasks) is not int or not 1 <= max_tasks <= 100000:
        raise CoreError('Invalid worker task limit')
    _number(max_seconds, 'time limit', .001, 86400)
    _number(poll_interval, 'poll interval', .01, 60)
    _number(idle_timeout, 'idle timeout', 0, 3600)
    core.get(case)
    started = time.monotonic()
    run_id = uuid4().hex
    summary = {'run_id': run_id, 'case': case, 'status': 'running',
               'completed': 0, 'failed': 0, 'attempted': 0}
    _checkpoint(core, case, 'worker_started',
                {**summary, 'max_tasks': max_tasks, 'max_seconds': max_seconds,
                 'poll_interval': poll_interval, 'idle_timeout': idle_timeout})
    idle_since = None
    try:
        while True:
            row = core.get(case)
            if row['state'] == 'CANCELADO':
                summary['status'] = 'cancelled'
                break
            try:
                core.authorize(case)
            except CoreError as exc:
                summary.update(status='blocked', blocked_error=str(exc))
                break
            if row['paused']:
                summary['status'] = 'paused'
                break
            if summary['attempted'] >= max_tasks:
                summary['status'] = 'task_limit'
                break
            remaining = max_seconds - (time.monotonic() - started)
            if remaining <= 0:
                summary['status'] = 'time_limit'
                break
            before = _counts(core, case)
            try:
                result = core.run_one(case, time_budget=min(core.timeout, remaining))
            except CoreError as exc:
                row = core.get(case)
                if row['state'] == 'CANCELADO':
                    summary['status'] = 'cancelled'
                    break
                try:
                    core.authorize(case)
                except CoreError as blocked:
                    summary.update(status='blocked', blocked_error=str(blocked))
                    break
                if row['paused']:
                    summary['status'] = 'paused'
                    break
                summary['failed'] += 1
                summary['attempted'] += 1
                idle_since = None
                _checkpoint(core, case, 'worker_progress', dict(summary))
                continue
            if result is not None:
                summary['completed'] += 1
                summary['attempted'] += 1
                idle_since = None
                _checkpoint(core, case, 'worker_progress', {**summary, 'task': result['task_id']})
                continue
            counts = _counts(core, case)
            # Expired leases at the attempt ceiling are disposed by _claim().
            newly_failed = max(0, counts.get('failed', 0) - before.get('failed', 0))
            if newly_failed:
                summary['failed'] += newly_failed
                _checkpoint(core, case, 'worker_progress', dict(summary))
            now = time.monotonic()
            if idle_since is None:
                idle_since = now
            if now - idle_since >= idle_timeout:
                summary['status'] = ('awaiting_lease' if counts.get('running', 0) else
                                     'drained_with_errors' if counts.get('failed', 0) else 'drained')
                break
            remaining = max_seconds - (now - started)
            if remaining <= 0:
                summary['status'] = 'time_limit'
                break
            time.sleep(min(poll_interval, remaining, idle_timeout - (now - idle_since)))
        return summary
    except KeyboardInterrupt:
        summary['status'] = 'interrupted'
        raise
    except BaseException:
        summary['status'] = 'execution_error'
        raise
    finally:
        summary['elapsed_seconds'] = max(0, time.monotonic() - started)
        summary['queue_counts'] = _counts(core, case)
        _checkpoint(core, case, 'worker_stopped', dict(summary))
