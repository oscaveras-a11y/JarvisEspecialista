"""CAN FD candump parser (offline, compact `ID##<flags><data>` records)."""
import re
from cyber_core.errors import CoreError

LEN = {0, 1, 2, 3, 4, 5, 6, 7, 8, 12, 16, 20, 24, 32, 48, 64}
RE = re.compile(r'^\((\d{1,16}\.\d{6})\) ([A-Za-z0-9_.:-]{1,64}) ([0-9A-F]{3}|[0-9A-F]{8})##([0-9A-F])((?:[0-9A-F]{2}){0,64})$')


def analyze_canfd(text, *, max_frames=100000):
    frames, streams = 0, {}
    for number, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        match = RE.match(line.strip())
        if not match:
            raise CoreError('Invalid CAN FD record at line %d' % number)
        ts, chan, ident, flags, data = match.groups()
        size = len(data) // 2
        if size not in LEN:
            raise CoreError('Invalid CAN FD length %d at line %d' % (size, number))
        if int(flags, 16) > 7:
            raise CoreError('Invalid CAN FD flags at line %d' % number)
        frames += 1
        if frames > max_frames:
            raise CoreError('Too many frames')
        s = streams.setdefault((chan, ident), {'channel': chan, 'id': ident, 'count': 0, 'brs': 0, 'esi': 0, 'max_len': 0})
        f = int(flags, 16)
        s['count'] += 1; s['brs'] += bool(f & 1); s['esi'] += bool(f & 2); s['max_len'] = max(s['max_len'], size)
    return {'frames': frames, 'streams': list(streams.values()),
            'limitation': 'Análise offline; CRC não verificado (não presente no candump).'}
