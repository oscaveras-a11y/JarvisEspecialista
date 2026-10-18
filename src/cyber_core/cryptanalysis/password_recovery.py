"""Format-detecting dispatcher for authorized real password recovery.

Recognizes a file by its byte signature (the same signatures used for
static triage in assessment.py) and routes to a format-specific recovery
implementation. Formats with no implementation yet are reported honestly
as unsupported — never silently skipped, never misreported as a wrong
password.
"""
from cyber_core.errors import CoreError

SAMPLE_BYTES = 64

# Formats this dispatcher can actually attempt passwords against.
_HANDLERS = ('zip', 'pdf')

_UNSUPPORTED_NOTES = {
    'rar5': 'RAR5 encryption is not yet supported by this recovery tool.',
    'rar4': 'RAR4 encryption is not yet supported by this recovery tool.',
    '7z': '7-Zip AES-256 encryption is not yet supported by this recovery tool.',
    'ole-cfb': 'Encrypted legacy Office documents (.doc/.xls/.ppt) are not yet supported by this recovery tool.',
    'luks': 'LUKS volume recovery is not yet supported by this recovery tool.',
    'openssl-salted': 'OpenSSL "Salted__" envelopes declare no cipher/KDF in the header; not yet supported.',
    'ccaes1': "This is the CORE's own synthetic AES envelope: it needs the exact 32-byte key "
              '(`cyber recover-aes`), not a guessed password.',
}


def detect_format(path):
    with open(path, 'rb') as handle:
        prefix = handle.read(SAMPLE_BYTES)
    from cyber_core.cryptanalysis.assessment import SIGNATURES
    for magic, identifier, _family in SIGNATURES:
        if prefix.startswith(magic):
            return identifier
    return 'unknown'


def attempt_password(path, candidates, *, max_attempts, deadline):
    # A plain list/tuple is bounded here (a sane upper bound for something a
    # caller typed or uploaded by hand); a generator — e.g. the bundled
    # wordlist, which has no fixed length worth materializing — is bounded
    # by max_attempts/deadline instead, enforced below by each cracker.
    if isinstance(candidates, (list, tuple)):
        if not 1 <= len(candidates) <= 100000:
            raise CoreError('Provide between 1 and 100000 candidate passwords')
    elif candidates is None or not hasattr(candidates, '__iter__'):
        raise CoreError('Provide candidate passwords as a list or an iterable')
    identifier = detect_format(path)
    if identifier == 'zip':
        from cyber_core.cryptanalysis.zip_cracker import attempt_zip_password
        result = attempt_zip_password(path, candidates, max_attempts=max_attempts, deadline=deadline)
    elif identifier == 'pdf':
        from cyber_core.cryptanalysis.pdf_cracker import attempt_pdf_password
        result = attempt_pdf_password(path, candidates, max_attempts=max_attempts, deadline=deadline)
    else:
        note = _UNSUPPORTED_NOTES.get(identifier, 'No password-recovery implementation exists yet for this format.')
        return {'recovered': False, 'attempts': 0, 'status': 'unsupported_format', 'format_id': identifier, 'note': note}
    result['format_id'] = identifier
    return result
