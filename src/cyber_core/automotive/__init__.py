"""Bounded, read-only analysis of classic CAN compact candump logs."""
from collections import Counter
from pathlib import Path
import os
import re
import stat

from cyber_core.errors import CoreError

_LINE = re.compile(r'\(([0-9]{1,16})\.([0-9]{6})\) ([A-Za-z0-9_.:-]{1,64}) ([0-9A-Fa-f]{3}|[0-9A-Fa-f]{8})#([0-9A-Fa-f]*)')


def analyze_can(path, *, max_bytes=16777216, max_frames=100000):
    """Analyze classic data frames; unsupported records fail the entire import."""
    for limit in (max_bytes, max_frames):
        if type(limit) is not int or limit <= 0:
            raise CoreError('CAN limits must be positive integers.')
    try:
        with Path(path).open('rb') as source:
            if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
                raise CoreError('CAN input must be a regular file.')
            raw = source.read(max_bytes + 1)
    except (OSError, ValueError, TypeError):
        raise CoreError('Cannot read CAN log.') from None
    if len(raw) > max_bytes:
        raise CoreError('CAN byte limit exceeded.')
    try:
        content = raw.decode('ascii')
    except UnicodeError:
        raise CoreError('CAN log must contain ASCII compact records.') from None
    streams = {}
    count = 0
    for line_number, line in enumerate(content.split('\n'), 1):
        if line.endswith('\r'):
            line = line[:-1]
        if not line.strip():
            continue
        if count >= max_frames:
            raise CoreError('CAN frame limit exceeded.')
        match = _LINE.fullmatch(line)
        if not match:
            raise CoreError(f'Unsupported or malformed CAN record at line {line_number}; only classic data frames are supported.')
        seconds, micros, channel, identifier, data = match.groups()
        number = int(identifier, 16)
        extended = len(identifier) == 8
        if number > (0x1FFFFFFF if extended else 0x7FF):
            raise CoreError(f'Invalid CAN identifier or unsupported error frame at line {line_number}.')
        if len(data) % 2 or len(data) > 16:
            raise CoreError(f'Invalid classic CAN payload at line {line_number}.')
        identifier = identifier.upper()
        data = data.upper()
        timestamp = int(seconds) * 1000000 + int(micros)
        key = (channel, identifier)
        if key not in streams:
            streams[key] = dict(channel=channel, id=identifier,
                                id_format='extended' if extended else 'standard',
                                count=0, payload_counts=Counter(), payload_length_counts=Counter(),
                                sample_payloads=[], timestamp_regressions=0, duplicate_timestamps=0,
                                _first=timestamp, _last=timestamp, _deltas=[])
        stream = streams[key]
        if stream['count']:
            delta = timestamp - stream['_last']
            stream['timestamp_regressions'] += int(delta < 0)
            stream['duplicate_timestamps'] += int(delta == 0)
            stream['_deltas'].append(delta)
        stream['_last'] = timestamp
        stream['count'] += 1
        stream['payload_counts'][data] += 1
        stream['payload_length_counts'][str(len(data) // 2)] += 1
        if data not in stream['sample_payloads'] and len(stream['sample_payloads']) < 8:
            stream['sample_payloads'].append(data)
        count += 1
    if not count:
        raise CoreError('CAN log contains no frames.')
    output = []
    for key in sorted(streams):
        stream = streams[key]
        deltas = stream.pop('_deltas')
        first, last = stream.pop('_first'), stream.pop('_last')
        valid = not stream['timestamp_regressions']
        stream['timestamp_status'] = 'regression' if not valid else ('nondecreasing' if deltas else 'single_frame')
        stream['interarrival_seconds'] = None
        stream['rate_hz'] = None
        stream['duration_seconds'] = (last - first) / 1000000 if valid else None
        if valid and deltas:
            stream['interarrival_seconds'] = dict(mean=sum(deltas) / len(deltas) / 1000000,
                                                  min=min(deltas) / 1000000,
                                                  max=max(deltas) / 1000000,
                                                  jitter=(max(deltas) - min(deltas)) / 1000000)
            if last > first:
                stream['rate_hz'] = (stream['count'] - 1) * 1000000 / (last - first)
        stream['payload_counts'] = dict(sorted(stream['payload_counts'].items()))
        stream['payload_length_counts'] = dict(sorted(stream['payload_length_counts'].items()))
        stream['dlc_counts'] = dict(stream['payload_length_counts'])
        output.append(stream)
    return dict(format='candump_compact_classic', frame_count=count, byte_count=len(raw),
                stream_count=len(output), streams=output)


def compare_can(first, second, *, max_bytes=16777216, max_frames=100000):
    """Compare observations, without inferring faults, compatibility, or causation."""
    a = analyze_can(first, max_bytes=max_bytes, max_frames=max_frames)
    b = analyze_can(second, max_bytes=max_bytes, max_frames=max_frames)
    left = {(s['channel'], s['id']): s for s in a['streams']}
    right = {(s['channel'], s['id']): s for s in b['streams']}
    common = []
    for key in sorted(left.keys() & right.keys()):
        x, y = left[key], right[key]
        distribution_changed = any(x['payload_counts'].get(p, 0) * y['count'] !=
                                   y['payload_counts'].get(p, 0) * x['count']
                                   for p in x['payload_counts'].keys() | y['payload_counts'].keys())
        common.append(dict(channel=key[0], id=key[1], id_format=x['id_format'],
                           first=x, second=y, count_delta=y['count'] - x['count'],
                           rate_delta_hz=None if x['rate_hz'] is None or y['rate_hz'] is None else y['rate_hz'] - x['rate_hz'],
                           payload_distribution_changed=distribution_changed))
    return dict(first=a, second=b, common=common,
                only_first=[left[k] for k in sorted(left.keys() - right.keys())],
                only_second=[right[k] for k in sorted(right.keys() - left.keys())],
                interpretation='Observed log differences only; no causal diagnosis.')
