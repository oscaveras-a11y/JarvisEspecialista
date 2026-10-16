"""Command-line interface; JSON success output and clear operational errors."""
import argparse
import json
import os
import sqlite3
from pathlib import Path
import sys
from cyber_core.agents import doctor
from cyber_core.errors import CoreError
from cyber_core.permissions import local_path
from cyber_core.service import Core


def parser():
    p = argparse.ArgumentParser(prog='cyber', description='CYBER CORE: authorized local investigations')
    default = Path(os.environ.get('LOCALAPPDATA', Path.home())) / 'CyberCore'
    p.add_argument('--home', default=os.environ.get('CYBER_HOME', str(default)), help='Protected storage outside the repository')
    p.add_argument('--max-bytes', type=int, default=int(os.environ.get('CYBER_MAX_BYTES', 67108864)))
    p.add_argument('--timeout', type=float, default=float(os.environ.get('CYBER_TIMEOUT', 60)))
    sub = p.add_subparsers(dest='command', required=True)
    sub.add_parser('init', help='Initialize local SQLite storage')
    sub.add_parser('doctor', help='Diagnose runtime and optional CLIs')
    sub.add_parser('agents', help='List available agents')
    inv = sub.add_parser('investigate', help='Register investigation and declared authorization')
    for name in ('project', 'objective', 'scope', 'owner', 'authorization'):
        inv.add_argument('--' + name, required=True)
    inv.add_argument('--allow-recovery', action='store_true', help='Explicitly authorize recovery investigation within scope; no key required for assessment')
    inv.add_argument('--valid-hours', type=float, default=24)
    status = sub.add_parser('status', help='List cases or display one case')
    status.add_argument('case', nargs='?')
    for name in ('report', 'pause', 'resume', 'revoke', 'run'):
        cmd = sub.add_parser(name, help={'report': 'Generate technical report', 'pause': 'Pause at operation boundary', 'resume': 'Resume persistent investigation', 'revoke': 'Revoke operation permission', 'run': 'Run one persistent pending task'}[name])
        cmd.add_argument('case')
    analyze = sub.add_parser('analyze-file', help='Acquire verified copy and analyze statically')
    analyze.add_argument('case')
    analyze.add_argument('path')
    analyze.add_argument('--queue-only', action='store_true')
    aes = sub.add_parser('recover-aes', help='Recover a CCAES1 AES-256-GCM envelope with supplied key')
    aes.add_argument('case')
    aes.add_argument('path')
    aes.add_argument('--key-file', required=True, help='Local protected file containing exactly 32 raw bytes; never logged')
    aes.add_argument('--expected-sha256')
    aes.add_argument('--expected-format')
    assess = sub.add_parser('assess-recovery', help='Assess recovery options for a file or bounded batch without supplying keys')
    assess.add_argument('case')
    assess.add_argument('path')
    assess.add_argument('--max-files', type=int, default=100)
    assess.add_argument('--max-total-bytes', type=int, default=268435456)
    assess.add_argument('--recursive', action='store_true')
    assess.add_argument('--queue-only', action='store_true')
    review = sub.add_parser('review', help='Ask Codex to review derived metadata; cloud approval required')
    review.add_argument('case')
    review.add_argument('--allow-cloud-summary', action='store_true')
    return p


def main(argv=None):
    core = None
    try:
        args = parser().parse_args(argv)
        if args.command in ('doctor', 'agents'):
            result = doctor()
            if args.command == 'agents':
                result = result['agents']
        else:
            core = Core(args.home, max_bytes=args.max_bytes, timeout=args.timeout)
            cmd = args.command
            if cmd == 'init':
                result = {'initialized': True, 'home': str(core.home), 'schema': 2}
            elif cmd == 'investigate':
                result = {'id': core.investigate(args.project, args.objective, args.scope, args.owner, args.authorization, recovery=args.allow_recovery, valid_hours=args.valid_hours)}
            elif cmd == 'status':
                result = {'investigation': core.get(args.case), 'tasks': core.tasks(args.case), 'checkpoints': core.checkpoints(args.case)} if args.case else [dict(r) for r in core.db.execute('SELECT id,project,state,paused,created FROM investigations ORDER BY created')]
            elif cmd == 'analyze-file':
                if core.get(args.case)['paused']:
                    raise CoreError('Investigation is paused')
                task = core.enqueue(args.case, args.path)
                result = {'task': task} if args.queue_only else core.run_one(args.case, task_id=task)
            elif cmd == 'run':
                result = core.run_one(args.case)
            elif cmd == 'assess-recovery':
                result = core.assess_recovery(args.case, args.path, max_files=args.max_files, recursive=args.recursive,
                                             queue_only=args.queue_only, max_total_bytes=args.max_total_bytes)
            elif cmd == 'report':
                result = {'path': str(core.report(args.case))}
            elif cmd in ('pause', 'resume', 'revoke'):
                getattr(core, cmd)(args.case)
                result = {'id': args.case, 'operation': cmd}
            elif cmd == 'recover-aes':
                key_path = local_path(args.key_file)
                with key_path.open('rb') as handle:
                    key = handle.read(33)
                result = core.recover(args.case, args.path, key, expected_sha256=args.expected_sha256, expected_format=args.expected_format)
                del key
            elif cmd == 'review':
                from cyber_core.orchestrator import review_summary
                result = review_summary(core, args.case, allow_cloud=args.allow_cloud_summary)
        print(json.dumps(result, ensure_ascii=True, indent=2))
        return 0
    except (CoreError, OSError, ValueError, sqlite3.Error) as exc:
        # OS errors can contain sensitive paths. Never print arbitrary exception data.
        message = str(exc) if isinstance(exc, CoreError) else 'Invalid configuration or inaccessible local resource'
        print('cyber: ' + message, file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print('cyber: interrupted; persistent tasks can be resumed after lease expiry', file=sys.stderr)
        return 130
    finally:
        if core is not None:
            core.close()
