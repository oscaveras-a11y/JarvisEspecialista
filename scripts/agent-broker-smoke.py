"""Manually opt-in real-provider probe using fixed synthetic evidence only.

No live call is made by default. CI credentials must be supplied explicitly;
this script never creates credentials, probes credential files, or prints them.
"""
import argparse
import json
import os
from pathlib import Path
import sys
import tempfile

def emit(status, *, attempted=False, live=False, **data):
    print(json.dumps({'status': status, 'live_call_attempted': attempted,
                      'live_integration': live, **data}, ensure_ascii=True))

def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--live', action='store_true')
    parser.add_argument('--agents', choices=('codex', 'claude', 'both'), default='both')
    args = parser.parse_args(argv)
    if not args.live:
        emit('not_requested')
        return 0
    selected = ['codex', 'claude'] if args.agents == 'both' else [args.agents]
    # Presence only. Never enumerate, inspect, print or persist credential values.
    ready = {'codex': any(bool(os.environ.get(key)) for key in
                         ('CODEX_API_KEY', 'OPENAI_API_KEY', 'CODEX_ACCESS_TOKEN')),
             'claude': any(bool(os.environ.get(key)) for key in
                          ('ANTHROPIC_API_KEY', 'CLAUDE_CODE_OAUTH_TOKEN'))}
    missing = [agent for agent in selected if not ready[agent]]
    if missing:
        emit('awaiting_resources', missing=missing)
        return 2
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
    from cyber_core.errors import CoreError
    from cyber_core.service import Core
    from cyber_core.orchestrator.broker import Broker
    with tempfile.TemporaryDirectory(prefix='cyber-agent-broker-smoke-') as temporary:
        root = Path(temporary)
        scope = root / 'synthetic'
        scope.mkdir()
        source = scope / 'sample.bin'
        source.write_bytes(b'\x7fELF' + bytes(range(256)) * 4)
        core = None
        try:
            core = Core(root / 'state', timeout=120)
            case = core.investigate('synthetic', 'Static synthetic format validation',
                                    scope, 'declared synthetic owner', 'manual synthetic smoke')
            task = core.enqueue(case, source)
            core.run_one(case, task_id=task)
            broker = Broker(core)
            summaries, primary = [], None
            for agent in selected:
                job = broker.enqueue(case, agent=agent, allow_cloud=True, depends_on=primary)
                result = broker.run_one(case, job)
                summaries.append({'agent': agent, 'status': result['status'],
                                  'usage': (result['response'] or {}).get('usage', {}),
                                  'error': result['error']})
                if result['status'] != 'done':
                    emit(result['status'], attempted=core.get(case)['agent_calls'] > 0,
                         agents=summaries, cross_review=False)
                    return 2
                primary = job if args.agents == 'both' and agent == 'codex' else None
            emit('completed', attempted=True, live=True, agents=summaries,
                 cross_review=args.agents == 'both', independent_validation=False)
            return 0
        except (CoreError, OSError, ValueError):
            attempted = bool(core and 'case' in locals() and core.get(case)['agent_calls'])
            emit('execution_failed', attempted=attempted)
            return 2
        finally:
            if core is not None:
                core.close()

if __name__ == '__main__':
    raise SystemExit(main())
