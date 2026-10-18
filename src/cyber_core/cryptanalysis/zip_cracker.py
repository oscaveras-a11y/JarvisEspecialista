"""Authorized password recovery for traditional PKZIP-encrypted archives.

Tries supplied candidate passphrases against a real ZIP file the operator is
authorized to test. Unlike selftest.attempt() (which proves the CORE's own
recovery pipeline on a synthetic envelope and never returns the passphrase),
this is a genuine recovery tool: its whole purpose is handing back a lost
password, so a match IS returned to the caller. It is never written into the
audit trail (see service.py), matching the project's "never log secrets"
rule.

Scope and limits, stated plainly:
- Only the classic PKZIP ("ZipCrypto") stream cipher that Python's zipfile
  module itself supports. WinZip/7-Zip AES-encrypted members (compression
  method 99) raise NotImplementedError and are reported as unsupported, not
  silently skipped or misreported as "wrong password".
- Only one member (the smallest, for speed) is used to test each candidate;
  finding its password recovers the whole archive, since ZipCrypto encrypts
  all members under file-specific streams derived from a common key check.
- No extraction occurs on disk; tested bytes stay in memory and are
  discarded, matching the whole-project rule of never executing analyzed
  input.
"""
import time
import zipfile

from cyber_core.errors import CoreError

MAX_ZIP_BYTES = 64 * 1024 * 1024


def attempt_zip_password(path, candidates, *, max_attempts, deadline):
    """Try candidate passwords against a real ZIP file within bounds.

    Returns a dict with recovered/attempts/status and, on success, the
    password and the matched member's name/size — the caller decides what
    to do with it (never persisted into the audit trail).
    """
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise CoreError('ZIP file is not accessible') from exc
    if size > MAX_ZIP_BYTES:
        raise CoreError('ZIP file exceeds the recovery byte limit')
    try:
        archive = zipfile.ZipFile(path)
    except zipfile.BadZipFile as exc:
        raise CoreError('Not a valid ZIP archive') from exc
    try:
        members = [info for info in archive.infolist() if not info.is_dir()]
        encrypted = [info for info in members if info.flag_bits & 0x1]
        if not encrypted:
            raise CoreError('No ZIP member declares password protection')
        target = min(encrypted, key=lambda info: info.file_size)
        if target.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
            raise CoreError('Unsupported ZIP compression method for recovery')
        tried = 0
        for candidate in candidates:
            if tried >= max_attempts:
                return {'recovered': False, 'attempts': tried, 'status': 'attempt_budget_exhausted'}
            if time.monotonic() > deadline:
                return {'recovered': False, 'attempts': tried, 'status': 'time_budget_exhausted'}
            if not isinstance(candidate, str) or not candidate or len(candidate) > 1024:
                continue
            tried += 1
            try:
                archive.read(target, pwd=candidate.encode('utf-8', errors='surrogateescape'))
            except RuntimeError:
                continue
            except NotImplementedError:
                return {'recovered': False, 'attempts': tried, 'status': 'unsupported_encryption_method'}
            return {'recovered': True, 'attempts': tried, 'status': 'recovered',
                    'password': candidate, 'member': target.filename, 'member_size': target.file_size}
        return {'recovered': False, 'attempts': tried, 'status': 'candidates_exhausted'}
    finally:
        archive.close()
