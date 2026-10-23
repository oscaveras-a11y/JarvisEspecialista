"""Authorized password recovery for standard-encrypted PDF files.

Tries supplied candidate passwords against a real PDF the operator is
authorized to test, using pikepdf (a maintained binding to the qpdf C
library) rather than a bespoke reimplementation of the PDF standard
security handler — the format's object/xref syntax and the RC4/AES-128/
AES-256 revisions (2 through 6) are involved enough that using the
correct, well-tested parser is safer than risking a subtly wrong one.

A match against either the PDF's user or owner password counts as
recovery (either reopens the file); pikepdf does not distinguish which
one matched. No page content is modified, re-saved, or decrypted to disk.
"""
import time

import pikepdf

from cyber_core.errors import CoreError

MAX_PDF_BYTES = 64 * 1024 * 1024


def attempt_pdf_password(path, candidates, *, max_attempts, deadline):
    """Try candidate passwords against a real PDF within bounds.

    Returns a dict with recovered/attempts/status and, on success, the
    password — never persisted into the audit trail by the caller.
    """
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise CoreError('PDF file is not accessible') from exc
    if size > MAX_PDF_BYTES:
        raise CoreError('PDF file exceeds the recovery byte limit')
    try:
        with pikepdf.open(path):
            pass
    except pikepdf.PasswordError:
        pass
    except pikepdf.PdfError as exc:
        raise CoreError('Not a valid PDF file') from exc
    else:
        raise CoreError('PDF does not declare password protection')
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
            with pikepdf.open(path, password=candidate):
                pass
        except pikepdf.PasswordError:
            continue
        return {'recovered': True, 'attempts': tried, 'status': 'recovered', 'password': candidate}
    return {'recovered': False, 'attempts': tried, 'status': 'candidates_exhausted'}
