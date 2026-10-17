"""Bounded static string extraction. Read-only; never executes the input.

Part of item 6 (reverse engineering): recover printable ASCII and UTF-16LE runs
from a bounded prefix of a verified copy. Pure function over bytes; the caller
bounds how much is read. Extracted strings are evidence-derived content, so the
service returns them to the operator but records only counts in the audit trail.
"""
from cyber_core.errors import CoreError

_PRINTABLE = set(range(0x20, 0x7F)) | {0x09}


def extract_strings(data, *, min_length=4, max_strings=1000):
    if not isinstance(data, (bytes, bytearray)):
        raise CoreError('Sample must be bytes')
    if not isinstance(min_length, int) or not 1 <= min_length <= 256:
        raise CoreError('min_length must be between 1 and 256')
    if not isinstance(max_strings, int) or not 1 <= max_strings <= 100000:
        raise CoreError('max_strings must be between 1 and 100000')
    data = bytes(data)
    ascii_strings, truncated = _ascii_runs(data, min_length, max_strings)
    utf16_strings, utf16_truncated = _utf16le_runs(data, min_length, max_strings)
    return {'ascii': ascii_strings, 'utf16le': utf16_strings,
            'counts': {'ascii': len(ascii_strings), 'utf16le': len(utf16_strings)},
            'truncated': truncated or utf16_truncated, 'min_length': min_length,
            'limitations': ['Prefixo limitado; strings não provam funcionalidade nem intenção.',
                            'Nenhum código foi executado; apenas bytes legíveis foram recuperados.']}


def _ascii_runs(data, min_length, max_strings):
    out, run = [], bytearray()
    for byte in data:
        if byte in _PRINTABLE:
            run.append(byte)
            continue
        if len(run) >= min_length:
            out.append(run.decode('ascii'))
            if len(out) >= max_strings:
                return out, True
        run = bytearray()
    if len(run) >= min_length and len(out) < max_strings:
        out.append(run.decode('ascii'))
    return out, False


def _utf16le_runs(data, min_length, max_strings):
    out, run = [], bytearray()
    # A printable char followed by a 0x00 high byte marks a UTF-16LE code unit.
    for index in range(0, len(data) - 1, 2):
        low, high = data[index], data[index + 1]
        if high == 0 and low in _PRINTABLE:
            run.append(low)
            continue
        if len(run) >= min_length:
            out.append(run.decode('ascii'))
            if len(out) >= max_strings:
                return out, True
        run = bytearray()
    if len(run) >= min_length and len(out) < max_strings:
        out.append(run.decode('ascii'))
    return out, False
