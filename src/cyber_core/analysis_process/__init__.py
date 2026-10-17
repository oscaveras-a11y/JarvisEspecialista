"""Analysis in a monitored process; no privilege or network sandbox is implied."""
import math
from pathlib import Path

from cyber_core.errors import CoreError
from cyber_core.analysis_process.supervisor import run_monitored


def _validate(result, destination, maximum):
    digest = result.get('sha256')
    if (not isinstance(digest, str) or len(digest) != 64 or
            any(c not in '0123456789abcdef' for c in digest) or
            type(result.get('size')) is not int or not 0 <= result['size'] <= maximum or
            type(result.get('entropy')) not in (int, float) or
            not math.isfinite(result['entropy']) or not 0 <= result['entropy'] <= 8 or
            result.get('copy_verified') is not True or result.get('copy') != str(destination) or
            not isinstance(result.get('format'), str)):
        raise CoreError('Invalid analysis child metadata')


def analyze_in_process(source, destination, max_bytes, timeout, *, tool='analyze-file',
                       secondary_source=None, secondary_destination=None, secondary_max_bytes=None,
                       should_stop=None, on_started=None, options=None):
    request = {'source': str(source), 'destination': str(destination),
               'max_bytes': max_bytes, 'timeout': timeout, 'tool': tool,
               'secondary_source': str(secondary_source) if secondary_source is not None else None,
               'secondary_destination': str(secondary_destination) if secondary_destination is not None else None,
               'secondary_max_bytes': secondary_max_bytes, 'options': options or {}}
    result = run_monitored(request, cwd=Path(destination).parent, timeout=timeout,
                           should_stop=should_stop, on_started=on_started)
    _validate(result, destination, max_bytes)
    if secondary_source is not None:
        if not isinstance(result.get('secondary'), dict):
            raise CoreError('Missing secondary analysis metadata')
        _validate(result['secondary'], secondary_destination, secondary_max_bytes)
    return result
