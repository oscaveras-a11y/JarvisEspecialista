import hashlib
import json
from pathlib import Path
import time
from cyber_core.errors import CoreError
from cyber_core.memory import encoded
from cyber_core.permissions import local_path


def verify_copy(core, case, artifact):
    copy = local_path(artifact['copy'])
    folder = (core.home / 'cases' / case / 'evidence').resolve()
    if not copy.is_relative_to(folder):
        raise CoreError('Evidence copy is outside its investigation')
    expected_size = artifact['size']
    if not isinstance(expected_size, int) or isinstance(expected_size, bool) or not 0 <= expected_size <= core.max_bytes:
        raise CoreError('Invalid evidence byte limit')
    checksum, size, started = hashlib.sha256(), 0, time.monotonic()
    with copy.open('rb') as handle:
        while block := handle.read(65536):
            size += len(block)
            if size > expected_size or time.monotonic() - started > core.timeout:
                raise CoreError('Evidence verification resource limit exceeded')
            checksum.update(block)
    if size != expected_size or checksum.hexdigest() != artifact['sha256']:
        raise CoreError('Evidence integrity mismatch')


def result_digest(result):
    return hashlib.sha256(encoded(result).encode('utf-8')).hexdigest()


def verified_result(core, case, task):
    if not core.verify_audit(case):
        raise CoreError('Audit chain integrity failed')
    row = core.db.execute("SELECT r.data,t.status FROM results r JOIN tasks t ON t.id=r.task_id WHERE r.case_id=? AND t.case_id=? AND r.task_id=?", (case, case, task)).fetchone()
    if row is None or row['status'] != 'done':
        raise CoreError('Experiment requires a completed result from this investigation')
    try:
        result = json.loads(row['data'])
        digest = result_digest(result)
        acquired = False
        for event in core.db.execute("SELECT data FROM audit WHERE case_id=? AND event='analysis_verified' ORDER BY id DESC", (case,)):
            record = json.loads(event['data'])
            if record.get('task') == task:
                acquired = record.get('sha256') == result.get('sha256') and record.get('result_digest') == digest
                break
        if not acquired:
            raise CoreError('Result differs from audited acquisition or is legacy; reacquire it before verification')
        verify_copy(core, case, result)
        if 'secondary' in result:
            verify_copy(core, case, result['secondary'])
    except (KeyError, TypeError, ValueError, OSError) as exc:
        raise CoreError('Invalid or inaccessible evidence record') from exc
    return result, digest


def observation_fingerprint(result, revision):
    def semantic(value):
        if isinstance(value, dict):
            return {key: semantic(item) for key, item in value.items() if key not in ('copy', 'task_id')}
        if isinstance(value, list):
            return [semantic(item) for item in value]
        return value
    stable = semantic(result)
    return result_digest({'observation': stable, 'hypothesis_revision': revision})
