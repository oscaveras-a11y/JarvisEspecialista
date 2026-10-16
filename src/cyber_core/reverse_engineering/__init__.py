"""Bounded static analysis; signatures are observations, not full parsers."""
from collections import Counter
import hashlib
import math
import os
import time
from cyber_core.errors import CoreError


def identify(header):
    for magic, name in ((b'\x7fELF', 'ELF signature'), (b'MZ', 'DOS/PE signature'),
                        (b'PK\x03\x04', 'ZIP signature'), (b'%PDF-', 'PDF signature'),
                        (b'\x89PNG\r\n\x1a\n', 'PNG signature'), (b'CCAES1', 'CYBER CORE AES-GCM envelope')):
        if header.startswith(magic):
            return name
    return 'Unknown binary'


def analyze(path, destination, max_bytes, timeout):
    start = time.monotonic()
    counts, digest, size, header = Counter(), hashlib.sha256(), 0, b''
    try:
        with open(path, 'rb') as source, open(destination, 'xb') as target:
            before = os.fstat(source.fileno())
            if before.st_size > max_bytes:
                raise CoreError('File exceeds byte limit')
            while block := source.read(65536):
                size += len(block)
                if size > max_bytes or time.monotonic() - start > timeout:
                    raise CoreError('Analysis resource limit exceeded')
                if not header:
                    header = block[:32]
                digest.update(block)
                counts.update(block)
                target.write(block)
            after = os.fstat(source.fileno())
            if (before.st_size, before.st_mtime_ns, before.st_ino) != (after.st_size, after.st_mtime_ns, after.st_ino):
                raise CoreError('Evidence changed during acquisition')
            target.flush()
            os.fsync(target.fileno())
        copied = hashlib.sha256()
        with open(destination, 'rb') as verified:
            while block := verified.read(65536):
                if time.monotonic() - start > timeout:
                    raise CoreError('Verification time limit exceeded')
                copied.update(block)
        if copied.hexdigest() != digest.hexdigest():
            raise CoreError('Evidence copy integrity mismatch')
    except BaseException:
        destination.unlink(missing_ok=True)
        raise
    entropy = -sum((n / size) * math.log2(n / size) for n in counts.values()) if size else 0.0
    return {'sha256': digest.hexdigest(), 'size': size, 'format': identify(header),
            'entropy': entropy, 'copy': str(destination), 'copy_verified': True,
            'limitations': 'Signature only; high entropy does not prove encryption. No code was executed.'}
