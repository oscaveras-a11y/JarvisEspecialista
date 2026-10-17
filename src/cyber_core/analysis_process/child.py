"""Fixed analysis child. Never imports or executes the analyzed input."""
import json
from pathlib import Path
import sys
import time

# -I ignores PYTHONPATH/cwd. Insert only our own trusted package installation/source root.
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from cyber_core.analysis_process.network_guard import block_network
# Item 14 "politica de acesso a rede": block before any analysis code runs,
# since this child parses untrusted evidence bytes.
block_network()
from cyber_core.errors import CoreError
from cyber_core.analysis_process.limits import MAX_TIMEOUT_SECONDS
from cyber_core.reverse_engineering import analyze


def execute(request):
    if not isinstance(request, dict) or request.get('tool') not in (
            'analyze-file', 'assess-recovery', 'analyze-firmware', 'analyze-can'):
        raise CoreError('Analysis operation is not allowlisted')
    source, output = Path(request['source']), Path(request['destination'])
    maximum, timeout = request['max_bytes'], request['timeout']
    if type(maximum) is not int or not 0 <= maximum <= 268435456:
        raise CoreError('Invalid analysis byte limit')
    if type(timeout) not in (int, float) or not 0 < timeout <= MAX_TIMEOUT_SECONDS:
        raise CoreError('Invalid analysis time limit')
    if not source.is_absolute() or not output.is_absolute():
        raise CoreError('Analysis requires absolute paths')
    started = time.monotonic()
    result = analyze(source, output, maximum, timeout)
    secondary = None
    if request.get('secondary_source') is not None:
        if request['tool'] not in ('analyze-firmware', 'analyze-can'):
            raise CoreError('Paired analysis is not supported')
        secondary = Path(request['secondary_destination'])
        second_limit = request['secondary_max_bytes']
        if type(second_limit) is not int or not 1 <= second_limit <= 268435456:
            raise CoreError('Invalid secondary byte limit')
        remaining = timeout - (time.monotonic() - started)
        if remaining <= 0:
            raise CoreError('Analysis time budget exhausted')
        result['secondary'] = analyze(Path(request['secondary_source']), secondary, second_limit, remaining)
    tool = request['tool']
    if tool == 'assess-recovery':
        from cyber_core.cryptanalysis.assessment import assess
        result['recovery_assessment'] = assess(output, entropy=result['entropy'])
    elif tool == 'analyze-firmware':
        from cyber_core.firmware import analyze_firmware, compare_firmware
        result['firmware'] = analyze_firmware(output, max_bytes=maximum)
        if secondary:
            result['firmware_comparison'] = compare_firmware(output, secondary, max_bytes=request['secondary_max_bytes'])
    elif tool == 'analyze-can':
        from cyber_core.automotive import analyze_can, compare_can
        result['can'] = analyze_can(output, max_bytes=min(maximum, 16777216))
        if secondary:
            result['can_comparison'] = compare_can(output, secondary, max_bytes=min(request['secondary_max_bytes'], 16777216))
    if tool == 'analyze-firmware' and request.get('external_tools'):
        from cyber_core.reverse_engineering.external import analyze_external
        remaining = timeout - (time.monotonic() - started)
        if remaining <= 0:
            raise CoreError('Analysis time budget exhausted before external tools')
        result['firmware']['external_analysis'] = analyze_external(
            output, {'format': result['firmware']['format']},
            request['external_tools'], min(remaining, 3600))
    return result


def main():
    try:
        data = sys.stdin.buffer.read(65537)
        if len(data) > 65536:
            raise CoreError('Analysis request limit exceeded')
        result = execute(json.loads(data.decode('utf-8')))
        message = {'ok': True, 'result': result}
    except Exception as exc:
        message = {'ok': False, 'error': str(exc) if isinstance(exc, CoreError) else 'Analysis child failed'}
    sys.stdout.write(json.dumps(message, ensure_ascii=True, allow_nan=False) + '\n')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
