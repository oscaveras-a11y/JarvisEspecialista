"""Bounded offline correlation of declared firmware observations; no device access."""
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
import math
import platform
import re
import time

VERSION = 'firmware-timeline-1'
KINDS = {'measurement', 'update', 'access', 'boot', 'log_gap'}
REQUIRED = {'id', 'device', 'component', 'source', 'time', 'kind'}
OPTIONAL = {'sha256', 'sequence', 'uncertainty_ms', 'actor'}
HEX = re.compile(r'[0-9a-fA-F]{64}\Z')


def _integer(value, low, high):
    if type(value) is not int or not low <= value <= high:
        raise ValueError('Invalid integer or resource limit')
    return value


def _pairs(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError('Duplicate JSON key')
        value[key] = item
    return value


def _constant(value):
    raise ValueError('Nonfinite JSON value')


def _event(raw, line):
    try:
        e = json.loads(raw, object_pairs_hook=_pairs, parse_constant=_constant)
        if not isinstance(e, dict) or not REQUIRED <= e.keys() or e.keys() - REQUIRED - OPTIONAL:
            raise ValueError('Invalid event schema')
        for key in REQUIRED | ({'actor'} if 'actor' in e else set()):
            if not isinstance(e[key], str) or not 1 <= len(e[key]) <= 128:
                raise ValueError('Invalid event text')
            if any(ord(c) < 32 or 0xD800 <= ord(c) <= 0xDFFF for c in e[key]):
                raise ValueError('Invalid event text')
        if e['kind'] not in KINDS:
            raise ValueError('Unsupported event kind')
        if e['kind'] == 'measurement' and 'sha256' not in e:
            raise ValueError('Measurement requires declared SHA-256')
        if 'sha256' in e:
            if not isinstance(e['sha256'], str) or not HEX.fullmatch(e['sha256']):
                raise ValueError('Invalid declared SHA-256')
            e['sha256'] = e['sha256'].lower()
        uncertainty = _integer(e.get('uncertainty_ms', 0), 0, 86400000)
        if 'sequence' in e:
            _integer(e['sequence'], 0, 2**63-1)
        stamp = datetime.fromisoformat(e['time'])
        if stamp.tzinfo is None or stamp.utcoffset() is None:
            raise ValueError('Timezone-aware timestamp required')
        stamp = stamp.astimezone(timezone.utc)
        delta = stamp - datetime(1970, 1, 1, tzinfo=timezone.utc)
        micros = (delta.days * 86400 + delta.seconds) * 1000000 + delta.microseconds
        e['_time'] = micros
        e['_low'] = micros - uncertainty * 1000
        e['_high'] = micros + uncertainty * 1000
        e['time_utc'] = stamp.isoformat()
        e['line'] = line
        e['line_sha256'] = hashlib.sha256(raw).hexdigest()
        e['uncertainty_ms'] = uncertainty
        return e
    except (TypeError, OverflowError, RecursionError, UnicodeError, KeyError) as exc:
        raise ValueError('Invalid event encoding or fields') from exc


def analyze(stream, *, max_bytes=16777216, max_line_bytes=16384,
            max_events=10000, max_findings=128, max_seconds=30, check=None):
    """Read binary JSONL. Hashes/times/source identities remain unverified declarations."""
    _integer(max_bytes, 1, 16777216)
    _integer(max_line_bytes, 1, 65536)
    _integer(max_events, 1, 10000)
    _integer(max_findings, 1, 128)
    if type(max_seconds) not in (int, float) or not math.isfinite(max_seconds) or not 0 < max_seconds <= 300:
        raise ValueError('Invalid time budget')
    deadline = time.monotonic() + max_seconds
    def gate():
        if check is not None:
            check()
        if time.monotonic() >= deadline:
            raise ValueError('Timeline time budget exceeded')
    events = []
    identifiers = set()
    consumed = 0
    digest = hashlib.sha256()
    flags = set()
    previous_time = {}
    previous_sequence = {}
    counts = Counter()
    while True:
        gate()
        raw = stream.readline(min(max_line_bytes, max_bytes-consumed) + 1)
        if not raw:
            break
        consumed += len(raw)
        if len(raw) > max_line_bytes or consumed > max_bytes or len(events) >= max_events:
            raise ValueError('Timeline input resource limit exceeded')
        digest.update(raw)
        e = _event(raw, len(events)+1)
        if e['id'] in identifiers:
            raise ValueError('Duplicate event ID')
        identifiers.add(e['id'])
        key = (e['source'], e['device'], e['component'])
        if key in previous_time and e['_time'] < previous_time[key]:
            flags.add('input_time_reversal')
        previous_time[key] = e['_time']
        if 'sequence' in e:
            if key in previous_sequence:
                old = previous_sequence[key]
                if e['sequence'] <= old:
                    flags.add('sequence_reversal')
                elif e['sequence'] != old+1:
                    flags.add('sequence_gap')
            previous_sequence[key] = e['sequence']
        if e['kind'] == 'log_gap':
            flags.add('declared_log_gap')
        counts[e['kind']] += 1
        events.append(e)
    if not events:
        raise ValueError('Empty timeline')
    gate()
    events.sort(key=lambda e: (e['_time'], e['line']))
    gate()
    patterns = []
    total_patterns = 0
    runs = {}
    # Only measurement events count as firmware observations. Ambiguous observations
    # break a run instead of being silently skipped to obtain an ordered pattern.
    for e in events:
        gate()
        if e['kind'] != 'measurement':
            continue
        key = (e['device'], e['component'])
        history = runs.setdefault(key, [])
        if history and history[-1]['_high'] >= e['_low']:
            flags.add('ambiguous_clock_order')
            history.clear()
        if history and history[-1]['sha256'] == e['sha256']:
            history[-1] = e
            continue
        history.append(e)
        if len(history) > 3:
            del history[0]
        if len(history) == 3 and history[0]['sha256'] == history[2]['sha256']:
            total_patterns += 1
            if len(patterns) < max_findings:
                patterns.append({
                    'classification': 'recorded_change_and_return',
                    'device': e['device'], 'component': e['component'],
                    'events': [v['id'] for v in history],
                    'lines': [v['line'] for v in history],
                    'line_sha256': [v['line_sha256'] for v in history],
                    'sources': [v['source'] for v in history],
                    'declared_sha256': [v['sha256'] for v in history],
                    'times_utc': [v['time_utc'] for v in history],
                    'meaning': 'A/B/A fingerprints in supplied records; not proof of installed firmware or fraud'
                })
    gate()
    preview = [{k: v for k, v in e.items() if not k.startswith('_')}
               for e in events[:max_findings]]
    return {
        'analyzer_version': VERSION,
        'parameters': dict(max_bytes=max_bytes, max_line_bytes=max_line_bytes,
                           max_events=max_events, max_findings=max_findings, max_seconds=max_seconds),
        'input_sha256': digest.hexdigest(), 'input_bytes': consumed,
        'events_read': len(events), 'event_counts': dict(counts),
        'timeline': preview, 'timeline_omitted': max(0, len(events)-len(preview)),
        'patterns': patterns, 'patterns_omitted': total_patterns-len(patterns),
        'quality_flags': sorted(flags), 'authenticity': 'not_verified',
        'conclusion': 'insufficient_to_determine_fraud',
        'findings': ['Parsed records and fingerprint patterns refer only to the supplied evidence'],
        'hypotheses': ['A recorded change may represent an update, temporary replacement, measurement error or altered records']
                      if total_patterns else [],
        'pending': [
            'Authenticate sources and measurement procedure independently',
            'Validate clock uncertainty and coverage; absent events do not prove absence of changes',
            'Establish whether fingerprints describe installed/running firmware, files or another measurement domain',
            'Corroborate with independent logs and authorized device-specific evidence',
            'Determine authorization, cause and impact separately; no attribution or fraud verdict'
        ]
    }


def run_timeline(core, case, path, **budgets):
    """Use existing verified acquisition and audited operation persistence."""
    from cyber_core.errors import CoreError
    from cyber_core.operations import _acquire, save_operation
    # Validate all options before acquiring or running another CORE operation.
    import io
    probe = b'{"id":"p","device":"p","component":"p","source":"p","time":"2000-01-01T00:00:00Z","kind":"boot"}\n'
    try:
        analyze(io.BytesIO(probe), **budgets)
    except (ValueError, TypeError):
        raise CoreError('Invalid firmware timeline parameters') from None
    maximum = budgets.get('max_bytes', 16777216)
    raw, evidence = _acquire(core, case, path, maximum)
    def check():
        row = core.authorize(case)
        core.authorize(case, path)
        if row['paused']:
            raise CoreError('Investigation is paused')
    try:
        result = analyze(io.BytesIO(raw), check=check, **budgets)
    except ValueError:
        raise CoreError('Invalid firmware timeline evidence or resource budget exceeded') from None
    check()
    if result['input_sha256'] != evidence['sha256']:
        raise CoreError('Timeline copy integrity failed')
    return save_operation(core, case, 'firmware_timeline',
                          {'evidence': evidence, 'analysis': result,
                           'runtime': {'python': platform.python_version(),
                                       'analyzer': VERSION}})
