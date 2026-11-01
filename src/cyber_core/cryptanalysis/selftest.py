"""Authorized self-test of password recovery on the operator's OWN lab file.

Honest and bounded: a weak passphrase present in the candidate list is recovered;
a strong or absent one yields recovery_demonstrated=False. The passphrase and the
recovered plaintext are never returned in logs/audit — only a SHA-256 and size.

Lab envelope format CCPW1 (synthetic, for self-testing only):
    magic(5) 'CCPW1' + salt(16) + nonce(12) + AES-256-GCM ciphertext(>=16)
Key = scrypt(passphrase, salt). This is a controlled demonstration of recovery
feasibility, not a tool against third-party material.
"""
import hashlib
import os
import time
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cyber_core.errors import CoreError

MAGIC = b'CCPW1'
_SCRYPT = {'n': 2 ** 14, 'r': 8, 'p': 1}
_MIN = len(MAGIC) + 16 + 12 + 16


def _key(passphrase, salt):
    return hashlib.scrypt(passphrase.encode('utf-8'), salt=salt, dklen=32, **_SCRYPT)


def seal(passphrase, plaintext):
    """Create a CCPW1 envelope. Used to generate a lab target you own."""
    if not isinstance(passphrase, str) or not passphrase:
        raise CoreError('A passphrase is required to seal the lab envelope')
    if not isinstance(plaintext, (bytes, bytearray)):
        raise CoreError('Plaintext must be bytes')
    salt, nonce = os.urandom(16), os.urandom(12)
    ciphertext = AESGCM(_key(passphrase, salt)).encrypt(nonce, bytes(plaintext), MAGIC)
    return MAGIC + salt + nonce + ciphertext


def attempt(envelope, candidates, *, max_attempts, deadline):
    """Try candidate passphrases against a CCPW1 envelope within bounds.

    Returns a dict with recovered/attempts/status and, on success, only a
    SHA-256 and size of the plaintext — never the passphrase or the plaintext.
    """
    if not isinstance(envelope, (bytes, bytearray)) or len(envelope) < _MIN or not bytes(envelope).startswith(MAGIC):
        raise CoreError('Unsupported or truncated CCPW1 envelope')
    salt, nonce, ciphertext = envelope[5:21], envelope[21:33], envelope[33:]
    tried = 0
    for candidate in candidates:
        if tried >= max_attempts:
            return {'recovered': False, 'attempts': tried, 'status': 'attempt_budget_exhausted'}
        if time.monotonic() > deadline:
            return {'recovered': False, 'attempts': tried, 'status': 'time_budget_exhausted'}
        tried += 1
        try:
            plain = AESGCM(_key(candidate, salt)).decrypt(nonce, ciphertext, MAGIC)
        except InvalidTag:
            continue
        return {'recovered': True, 'attempts': tried, 'status': 'recovered',
                'plaintext_sha256': hashlib.sha256(plain).hexdigest(), 'plaintext_size': len(plain)}
    return {'recovered': False, 'attempts': tried, 'status': 'candidates_exhausted'}
