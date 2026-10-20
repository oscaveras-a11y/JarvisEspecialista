"""Authorized password recovery for AES-256-encrypted 7z archives.

Tries supplied candidate passwords against a real 7z file the operator is
authorized to test, using py7zr (a maintained pure-Python 7z implementation)
rather than reimplementing the format — same rationale as pdf_cracker.py
choosing pikepdf over a bespoke PDF security handler.

Unlike pikepdf.PasswordError for PDFs, py7zr has no single clean exception
for "wrong password": whether content only or both content and filenames
are encrypted (a per-archive choice made when it was created) changes where
and how a wrong key surfaces. With content-only encryption, a wrong key
decompresses to garbage that raises lzma.LZMAError, EOFError, or py7zr's
own CrcError once checked (confirmed empirically across thousands of real
candidate passwords from the bundled wordlist). With encrypted filenames
too, the header itself is AES-decrypted and re-parsed as structured 7z
metadata before any content is touched; feeding it the wrong key makes
that parse walk into effectively random bytes, which this library
surfaces as whatever exception its decoder happens to hit first
(overwhelmingly TypeError in practice). None of these are a dedicated
password error. All of them are therefore treated as
"wrong candidate" here — the same reasoning zip_cracker.py already applies
to ZipCrypto's own 1/256 false-positive header check: a parse failure
caused by feeding a decryption step the wrong key is still just "wrong",
whatever exception type the underlying library happened to raise for it.

No extraction occurs on disk; testzip() decompresses each member in memory
only to verify its CRC, matching the whole-project rule of never writing
analyzed input to disk during a credential check.

Throughput is slow by the format's own design: 7z derives its AES key via
many rounds of SHA-256 (deliberately expensive, the same anti-brute-force
rationale as bcrypt), and py7zr re-parses the archive header on every
attempt since its API has no way to re-key an already-open file. Measured
here at roughly 8 candidates/second against a tiny single-file archive —
testing the full bundled rockyou wordlist (14.3M entries) would take on
the order of weeks, far past any time budget this tool offers. Treat 7z
recovery as viable only for a short, targeted candidate list, not the
bundled wordlist.
"""
import lzma
import struct
import time

import py7zr
import py7zr.exceptions

from cyber_core.errors import CoreError

MAX_7Z_BYTES = 64 * 1024 * 1024

# Deliberately broad: see the module docstring for why a password-recovery
# loop treats any of these, raised while opening or testing with a candidate
# key, as "that candidate was wrong" rather than letting it propagate.
_WRONG_PASSWORD_ERRORS = (
    lzma.LZMAError,
    py7zr.exceptions.Bad7zFile,
    py7zr.exceptions.CrcError,
    TypeError,
    ValueError,
    struct.error,
    IndexError,
    KeyError,
    UnicodeDecodeError,
    EOFError,
    OverflowError,
)


def attempt_7z_password(path, candidates, *, max_attempts, deadline):
    """Try candidate passwords against a real 7z archive within bounds.

    Returns a dict with recovered/attempts/status and, on success, the
    password — never persisted into the audit trail by the caller.
    """
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise CoreError('7z file is not accessible') from exc
    if size > MAX_7Z_BYTES:
        raise CoreError('7z file exceeds the recovery byte limit')
    try:
        with py7zr.SevenZipFile(path) as probe:
            protected = probe.needs_password()
    except py7zr.exceptions.PasswordRequired:
        protected = True
    except _WRONG_PASSWORD_ERRORS as exc:
        raise CoreError('Not a valid 7z file') from exc
    if not protected:
        raise CoreError('7z archive does not declare password protection')
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
            with py7zr.SevenZipFile(path, password=candidate) as archive:
                if archive.testzip() is not None:
                    continue
        except _WRONG_PASSWORD_ERRORS:
            continue
        return {'recovered': True, 'attempts': tried, 'status': 'recovered', 'password': candidate}
    return {'recovered': False, 'attempts': tried, 'status': 'candidates_exhausted'}
