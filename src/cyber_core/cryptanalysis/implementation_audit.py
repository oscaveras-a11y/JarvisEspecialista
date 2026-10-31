"""Static audit of cryptographic implementation patterns in authorized source
or configuration text. Part of item 7 ("auditar a segurança de implementações
criptográficas"). No execution, no network, no key derivation — pattern
matching only. A match is an indication to verify by a human reviewer, never
proof of a vulnerability, and never a claim that the code was exploited.
"""
import re
from cyber_core.errors import CoreError

# (kind, compiled pattern, severity, group-index-of-secret-value-to-redact; 0/-1
# follow the same convention as vulnerability/__init__.py).
RULES = (
    ('broken_cipher', re.compile(r'(?i)\b(DES|3DES|TripleDES|RC2|RC4|Blowfish)\b(?!\w)'), 'high', 0),
    ('ecb_mode', re.compile(r'(?i)\bMODE[_.]?ECB\b'), 'high', 0),
    ('static_iv_or_nonce', re.compile(r'(?i)\b(iv|nonce|salt)\s*[:=]\s*["\']?(0x0+|0{8,}|["\']?\\x00{4,})'), 'high', 2),
    ('hardcoded_key_literal', re.compile(r'(?i)\b(key|secret[_-]?key|encryption[_-]?key)\s*[:=]\s*["\']([0-9a-fA-F]{16,}|[^"\'\s]{16,})["\']'), 'high', 2),
    ('weak_random_for_crypto', re.compile(r'(?i)\brandom\.(random|randint|choice|randrange)\s*\('), 'medium', 0),
    ('weak_hash_for_integrity', re.compile(r'(?i)\b(md5|sha1)\s*\([^)]*\)\s*(?:#.*(?:hmac|signature|integrity|checksum|password))'), 'medium', 0),
    ('short_key_length', re.compile(r'(?i)\b(?:key_size|keysize|bits)\s*[:=]\s*(?:40|56|64)\b'), 'medium', 0),
    ('insufficient_kdf_iterations', re.compile(r'(?i)\bPBKDF2\b[^\n]{0,80}\biterations\s*[:=]\s*(?:1|10|100|1000|2000|4096|10000)\b'), 'medium', 0),
    ('custom_crypto_warning', re.compile(r'(?i)\bdef\s+(encrypt|decrypt|xor_encrypt|rot13|custom_cipher)\b'), 'low', 0),
)
_LIMITS = ['Correspondência por padrão estático sobre texto; não executa nem analisa comportamento em tempo real.',
           'Indício a verificar por um revisor humano, nunca prova de vulnerabilidade exploravel.',
           'Não deriva, recupera nem testa chaves; valores aparentes de segredo são redigidos.']


def _redact_line(line):
    redacted = line
    for _, pattern, _, group in RULES:
        if not group:
            continue
        real_group = 0 if group == -1 else group
        for match in pattern.finditer(redacted):
            value = match.group(real_group)
            if not value:
                continue
            masked = value[:2] + '***' if len(value) > 2 else '***'
            redacted = redacted.replace(value, masked)
    return redacted


def audit_implementation(text, *, max_findings=1000):
    if not isinstance(text, str):
        raise CoreError('Source text must be a string')
    if not isinstance(max_findings, int) or not 1 <= max_findings <= 100000:
        raise CoreError('Invalid finding limit')
    findings, severities = [], {'high': 0, 'medium': 0, 'low': 0}
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw[:4096]
        excerpt = _redact_line(line).strip()[:160]
        for kind, pattern, severity, group in RULES:
            if not pattern.search(line):
                continue
            findings.append({'line': number, 'kind': kind, 'severity': severity, 'excerpt': excerpt})
            severities[severity] += 1
            if len(findings) >= max_findings:
                return {'findings': findings, 'summary': severities, 'truncated': True, 'limitations': list(_LIMITS)}
    return {'findings': findings, 'summary': severities, 'truncated': False, 'limitations': list(_LIMITS)}
