"""Passive, generic framed-capture analysis. No bus access, no transmission.

Part of item 10 (protocol analysis), complementing the CAN-specific module with a
protocol-agnostic view over a TEXT capture: one message per non-empty line as hex
bytes (separators space/colon/comma/dash allowed), with an optional leading
id/channel token ending in '#' or '|'. Purely static: imports a capture and
reports patterns; it never opens a bus, device, or socket.
"""
import re
from cyber_core.errors import CoreError

_HEX = set('0123456789abcdefABCDEF')
_SEP = re.compile(r'[\s:,\-]')
_MAX_DISTINCT = 10000


def analyze_capture(text, *, max_messages=200000):
    if not isinstance(text, str):
        raise CoreError('Capture must be text')
    if not isinstance(max_messages, int) or not 1 <= max_messages <= 1000000:
        raise CoreError('Invalid message limit')
    messages, skipped = 0, 0
    lengths, ids, payloads = {}, {}, set()
    truncated = False
    # _MAX_DISTINCT bounds how many distinct ids/payloads get tallied; previously
    # hitting that cap was silent (an already-known id kept counting, but a NEW id
    # or payload past the cap was just dropped with no signal). Fix: keep counting
    # already-known ids past the cap (no data loss for what we DO track), and
    # report explicitly when a new distinct id/payload had to be dropped.
    ids_truncated, payloads_truncated = False, False
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        if messages >= max_messages:
            truncated = True
            break
        ident = None
        for sep in ('#', '|'):
            if sep in line:
                ident, line = line.split(sep, 1)
                ident = ident.strip()
                break
        hexstr = _SEP.sub('', line)
        if not hexstr or len(hexstr) % 2 or any(c not in _HEX for c in hexstr):
            skipped += 1
            continue
        payload = bytes.fromhex(hexstr)
        messages += 1
        lengths[len(payload)] = lengths.get(len(payload), 0) + 1
        if ident is not None:
            if ident in ids or len(ids) < _MAX_DISTINCT:
                ids[ident] = ids.get(ident, 0) + 1
            else:
                ids_truncated = True
        normalized = hexstr.lower()
        if normalized in payloads or len(payloads) < _MAX_DISTINCT:
            payloads.add(normalized)
        else:
            payloads_truncated = True
    return {'messages': messages, 'skipped': skipped, 'unique_payloads': len(payloads),
            'length_histogram': dict(sorted(lengths.items())), 'id_histogram': ids,
            'truncated': truncated, 'ids_truncated': ids_truncated, 'payloads_truncated': payloads_truncated,
            'limitations': ['Análise passiva de captura textual; nenhum barramento/rede foi acessado.',
                            'Reconhece enquadramento e padrões, não valida semântica do protocolo.']}


def compare_captures(first_text, second_text, *, max_messages=200000):
    first = analyze_capture(first_text, max_messages=max_messages)
    second = analyze_capture(second_text, max_messages=max_messages)
    a, a_truncated = _payload_set(first_text, max_messages)
    b, b_truncated = _payload_set(second_text, max_messages)
    only_in_first, only_in_second = sorted(a - b), sorted(b - a)
    # The comparison itself can be incomplete for reasons beyond either side's own
    # 'truncated'/'payloads_truncated': the distinct-payload sets used HERE for the
    # set difference have their own _MAX_DISTINCT cap, and the diff lists below are
    # independently capped at 1000 entries each.
    comparison_truncated = (first['truncated'] or second['truncated'] or
                            first['payloads_truncated'] or second['payloads_truncated'] or
                            a_truncated or b_truncated or
                            len(only_in_first) > 1000 or len(only_in_second) > 1000)
    return {'first': first, 'second': second,
            'only_in_first': only_in_first[:1000], 'only_in_second': only_in_second[:1000],
            'common_unique_payloads': len(a & b), 'comparison_truncated': comparison_truncated,
            'limitations': first['limitations']}


def _payload_set(text, max_messages):
    out, count, dropped = set(), 0, False
    for raw in text.splitlines():
        line = raw.strip()
        if not line or count >= max_messages:
            continue
        for sep in ('#', '|'):
            if sep in line:
                _, line = line.split(sep, 1)
                break
        hexstr = _SEP.sub('', line)
        if hexstr and len(hexstr) % 2 == 0 and all(c in _HEX for c in hexstr):
            count += 1
            normalized = hexstr.lower()
            if normalized in out or len(out) < _MAX_DISTINCT:
                out.add(normalized)
            else:
                dropped = True
    return out, dropped
