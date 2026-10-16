"""Authorized AES-256-GCM recovery of the CCAES1 synthetic envelope only."""
import hashlib
import os
import time
from uuid import uuid4
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cyber_core.errors import CoreError
from cyber_core.memory import audit
from cyber_core.permissions import storage_root
from cyber_core.reverse_engineering import identify

MAGIC = b'CCAES1'


def recover(core, case, source, key, *, expected_sha256=None, expected_format=None):
    # Never serialize key bytes, key fingerprints or plaintext into audit records.
    core.get(case)
    started = time.monotonic()
    material_id = uuid4().hex
    output = None
    try:
        path = core.authorize(case, source, recovery=True)
        if core.get(case)['paused']:
            raise CoreError('Investigation is paused')
        if not isinstance(key, bytes) or len(key) != 32:
            raise CoreError('AES-256 requires a supplied 32-byte key')
        if expected_sha256 is not None:
            if len(expected_sha256) != 64 or any(c not in '0123456789abcdefABCDEF' for c in expected_sha256):
                raise CoreError('Expected SHA-256 must have 64 hex characters')
        core.db.execute('BEGIN IMMEDIATE')
        try:
            row = core.authorize(case, path, recovery=True)
            budget = core.get(case)['recovery_attempts']
            if budget >= 3:
                raise CoreError('Recovery attempt budget exhausted')
            core.db.execute('UPDATE investigations SET recovery_attempts=recovery_attempts+1 WHERE id=?', (case,))
            audit(core.db, case, 'recovery_attempt', {'material_id': material_id, 'source': str(path), 'attempt': budget + 1})
            core.db.commit()
        except BaseException:
            core.db.rollback()
            raise
        with path.open('rb') as handle:
            before = os.fstat(handle.fileno())
            # AESGCM is an in-memory primitive. A 64 MiB maximum bounds copies well below 8 GiB.
            limit = min(core.max_bytes, 64 * 1024 * 1024)
            if before.st_size > limit:
                raise CoreError('Recovery byte limit exceeded')
            envelope = handle.read(limit + 1)
            after = os.fstat(handle.fileno())
        if len(envelope) > limit or (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
            raise CoreError('Recovery input changed or exceeds limits')
        if len(envelope) < len(MAGIC) + 12 + 16 or not envelope.startswith(MAGIC):
            raise CoreError('Unsupported or truncated CCAES1 envelope')
        if time.monotonic() - started > core.timeout:
            raise CoreError('Recovery time limit exceeded')
        try:
            plain = AESGCM(key).decrypt(envelope[6:18], envelope[18:], MAGIC)
        except InvalidTag as exc:
            raise CoreError('Key or authentication tag is invalid') from exc
        digest = hashlib.sha256(plain).hexdigest()
        observed = identify(plain[:32])
        if expected_sha256 is not None and digest != expected_sha256.lower():
            raise CoreError('Recovered SHA-256 does not match expectation')
        if expected_format is not None and observed != expected_format:
            raise CoreError('Recovered format does not match expectation')
        if time.monotonic() - started > core.timeout:
            raise CoreError('Recovery time limit exceeded')
        core.authorize(case, path, recovery=True)
        folder = storage_root(core.home / 'cases' / case / 'recovered')
        output = folder / (uuid4().hex + '.recovered')
        with output.open('xb') as handle:
            handle.write(plain)
            handle.flush()
            os.fsync(handle.fileno())
        # Re-read published bytes before claiming integrity, and clean up on any failure.
        check = hashlib.sha256()
        with output.open('rb') as handle:
            while block := handle.read(65536):
                check.update(block)
        if check.hexdigest() != digest or time.monotonic() - started > core.timeout:
            raise CoreError('Recovered output integrity or time limit failure')
        result = {'authenticated': True, 'sha256': digest, 'size': len(plain), 'format': observed,
                  'output': str(output), 'source_sha256': hashlib.sha256(envelope).hexdigest(),
                  'material_id': material_id, 'algorithm': 'AES-256-GCM',
                  'validation': 'GCM authentication and output SHA-256; supplied expectations checked when present'}
        with core.db:
            core.authorize(case, path, recovery=True)
            audit(core.db, case, 'recovery_verified', result)
        return result
    except Exception as exc:
        if output:
            output.unlink(missing_ok=True)
        message = str(exc) if isinstance(exc, CoreError) else 'Recovery failed'
        with core.db:
            audit(core.db, case, 'recovery_rejected', {'material_id': material_id, 'error': message, 'type': type(exc).__name__})
        raise CoreError(message) from exc
