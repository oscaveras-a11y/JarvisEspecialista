"""Authorized, bounded batch intake. No automatic secret search or file execution."""
import os
from pathlib import Path
import stat
import time
from cyber_core.errors import CoreError
from cyber_core.memory import audit
from cyber_core.permissions import local_path


def collect(core, case, value, *, max_files, recursive, max_total_bytes):
    if not 1 <= max_files <= 1000 or not 1 <= max_total_bytes <= 1024 * 1024 * 1024:
        raise CoreError('Invalid batch limits')
    row = core.authorize(case, recovery=True)
    if row['paused']:
        raise CoreError('Investigation is paused')
    root = local_path(row['scope'], directory=True)
    raw = Path(value)
    # Determine the requested type without resolving links; local_path rejects them.
    requested = local_path(value, directory=raw.is_dir())
    if not requested.is_relative_to(root):
        raise CoreError('Batch is outside the authorized scope')
    if requested.is_relative_to(core.home) or core.home.is_relative_to(requested):
        raise CoreError('Batch input must not overlap operational storage')
    files, skipped, scanned, total = [], 0, 0, 0
    started = time.monotonic()

    def add(path, size):
        nonlocal total
        if size > core.max_bytes:
            raise CoreError('Batch contains a file exceeding the per-file byte limit')
        total += size
        if len(files) >= max_files or total > max_total_bytes:
            raise CoreError('Batch file or total byte limit exceeded; no new tasks were queued')
        files.append((path, size))

    if requested.is_file():
        add(requested, requested.stat().st_size)
    else:
        pending = [requested]
        while pending:
            directory = local_path(pending.pop(), directory=True)
            with os.scandir(directory) as entries:
                for entry in entries:
                    scanned += 1
                    if scanned > 20000 or time.monotonic() - started > core.timeout:
                        raise CoreError('Batch enumeration resource limit exceeded; no new tasks were queued')
                    info = entry.stat(follow_symlinks=False)
                    if stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400:
                        skipped += 1
                    elif stat.S_ISREG(info.st_mode):
                        add(Path(entry.path), info.st_size)
                    elif stat.S_ISDIR(info.st_mode) and recursive:
                        if len(pending) >= 1000:
                            raise CoreError('Batch directory limit exceeded; no new tasks were queued')
                        pending.append(Path(entry.path))
                    elif not stat.S_ISDIR(info.st_mode):
                        skipped += 1
    return files, skipped, total


def assess_recovery(core, case, path, *, max_files=100, recursive=False, queue_only=False, max_total_bytes=268435456):
    files, skipped, total = collect(core, case, path, max_files=max_files, recursive=recursive, max_total_bytes=max_total_bytes)
    tasks = []
    # Atomic queue intake: reject a changed scope/path without leaving a half-queued batch.
    with core.db:
        for file, size in files:
            task = core._enqueue(case, file, tool='assess-recovery')
            core.db.execute('INSERT INTO task_limits(task_id,max_bytes) VALUES(?,?)', (task, size))
            tasks.append(task)
        audit(core.db, case, 'recovery_batch_queued', {'count': len(tasks), 'skipped': skipped, 'declared_bytes': total,
                                                   'max_files': max_files, 'max_total_bytes': max_total_bytes, 'recursive': recursive})
    output = {'tasks': tasks, 'results': [], 'failures': [], 'pending_tasks': [], 'skipped': skipped,
              'status': 'queued' if queue_only else 'completed', 'recovery_demonstrated': False}
    if queue_only:
        return output
    started, processed_bytes = time.monotonic(), 0
    for index, task in enumerate(tasks):
        remaining = core.timeout - (time.monotonic() - started)
        if remaining <= 0 or processed_bytes >= max_total_bytes:
            output['pending_tasks'] = tasks[index:]
            output['status'] = 'awaiting_resume_resource_limit'
            break
        try:
            result = core.run_one(case, task_id=task, time_budget=remaining)
            if result is None:
                output['pending_tasks'].append(task)
            else:
                output['results'].append(result)
                processed_bytes += result['size']
        except CoreError as exc:
            durable = core.db.execute('SELECT status FROM tasks WHERE id=?', (task,)).fetchone()
            if durable['status'] in ('pending', 'running'):
                # Pause/revocation/expiry may reject a claim without failing its durable task.
                remaining_ids = set(tasks[index:])
                output['pending_tasks'] = [row['id'] for row in core.tasks(case)
                                           if row['id'] in remaining_ids and row['status'] in ('pending', 'running')]
                output['status'] = 'awaiting_resume_or_authorization'
                output['blocked_error'] = str(exc)
                break
            output['failures'].append({'task': task, 'error': str(exc)})
    if output['failures'] or output['pending_tasks']:
        if output['status'] == 'completed':
            output['status'] = 'partial'
    with core.db:
        audit(core.db, case, 'recovery_batch_checkpoint', {'completed': len(output['results']),
                                                       'failed': len(output['failures']), 'pending': len(output['pending_tasks']),
                                                       'status': output['status']})
    return output
