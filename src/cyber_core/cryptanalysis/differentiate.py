"""Static differentiation: encoding vs compression vs encryption vs structured.

Implements part of item 7 ("diferenciar criptografia, compressão, ofuscação e
codificação"). Pure and honest: a signature is an observation, not a validated
format, and high entropy alone is never asserted as encryption (compression is
high-entropy too). Inspects a bounded prefix only.
"""
import base64
import math
from collections import Counter
from cyber_core.errors import CoreError

# Leading signatures grouped by what they indicate.
SIGNATURES = (
    (b'\x1f\x8b\x08', 'compression', 'gzip'),
    (b'\xfd7zXZ\x00', 'compression', 'xz'),
    (b'BZh', 'compression', 'bzip2'),
    (b'PK\x03\x04', 'archive', 'zip'),
    (b'7z\xbc\xaf\x27\x1c', 'archive', '7z'),
    (b'Rar!\x1a\x07', 'archive', 'rar'),
    (b'CCAES1', 'encrypted', 'cyber-core-aes-gcm'),
    (b'CCPW1', 'encrypted', 'cyber-core-passphrase'),
    (b'LUKS\xba\xbe', 'encrypted', 'luks'),
    (b'Salted__', 'encrypted', 'openssl-salted'),
    (b'-----BEGIN PGP MESSAGE', 'encrypted', 'pgp-message'),
    (b'age-encryption.org', 'encrypted', 'age'),
)
_HEX = set(b'0123456789abcdefABCDEF')
_B64 = set(b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=')
_LIMITS = ['Prefixo limitado; o reconhecimento não valida o formato completo.',
           'Alta entropia não prova criptografia: compressão também produz alta entropia.']


def _entropy(data):
    if not data:
        return 0.0
    counts, n = Counter(data), len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def differentiate(sample, *, sample_truncated=False):
    if not isinstance(sample, (bytes, bytearray)):
        raise CoreError('Sample must be bytes')
    sample = bytes(sample)
    report = {'content_class': 'unknown', 'label': 'unclassified',
              'entropy': round(_entropy(sample), 6), 'sample_bytes': len(sample),
              'sample_truncated': bool(sample_truncated), 'evidence': [], 'limitations': list(_LIMITS)}
    for magic, kind, name in SIGNATURES:
        if sample.startswith(magic):
            report.update(content_class=kind, label=name)
            report['evidence'].append('signature:' + name)
            return report
    stripped = bytes(b for b in sample if b not in b' \t\r\n')
    if len(stripped) >= 16 and len(stripped) % 2 == 0 and all(b in _HEX for b in stripped):
        report.update(content_class='encoding', label='hex')
        report['evidence'].append('charset:hexadecimal')
        return report
    if len(stripped) >= 16 and all(b in _B64 for b in stripped):
        try:
            base64.b64decode(stripped + b'=' * (-len(stripped) % 4))
            report.update(content_class='encoding', label='base64')
            report['evidence'].append('charset:base64')
            return report
        except Exception:
            pass
    if sample and sum(1 for b in sample if 9 <= b <= 13 or 32 <= b <= 126) / len(sample) > 0.95:
        report.update(content_class='text', label='printable-text')
        report['evidence'].append('mostly-printable')
        return report
    if report['entropy'] > 7.9:
        report.update(content_class='high-entropy', label='encrypted-or-compressed-indistinguishable')
        report['evidence'].append('entropy>7.9 without a recognized structure')
        return report
    report.update(content_class='structured', label='binary-structured')
    report['evidence'].append('low/medium entropy without a known signature')
    return report
