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
    from cyber_core.config import load_defaults
    defaults = load_defaults()
    default = Path(os.environ.get('LOCALAPPDATA', Path.home())) / 'CyberCore'
    p.add_argument('--ghidra-home', help='Trusted absolute Ghidra 12.1.4 path on the runner')
    p.add_argument('--java-home', help='Trusted absolute JDK path; required with --ghidra-home')
    p.add_argument('--binwalk-executable', help='Trusted absolute Binwalk 3.1.0 executable path on the runner')
    p.add_argument('--yara-rules', help='Trusted absolute path to a .yar/.yara rule file or directory of rules')
    p.add_argument('--home', default=os.environ.get('CYBER_HOME', str(default)), help='Protected storage outside the repository')
    p.add_argument('--max-bytes', type=int, default=int(os.environ.get('CYBER_MAX_BYTES', defaults['max_bytes'])))
    p.add_argument('--timeout', type=float, default=float(os.environ.get('CYBER_TIMEOUT', defaults['timeout_seconds'])),
                   help='Per-task time budget in seconds; a single task may run for hours or days')
    p.add_argument('--max-attempts', type=int, default=int(os.environ.get('CYBER_MAX_ATTEMPTS', defaults['max_attempts'])))
    p.add_argument('--agent-calls-per-case', type=int, default=int(os.environ.get('CYBER_AGENT_CALLS', defaults['agent_calls_per_case'])))
    sub = p.add_subparsers(dest='command', required=True)
    sub.add_parser('init', help='Initialize local SQLite storage')
    sub.add_parser('doctor', help='Diagnose runtime and optional CLIs')
    sub.add_parser('agents', help='List available agents')
    sub.add_parser('crypto-demo', help='Synthetic round-trip of RSA-OAEP, ECDH+AES-GCM and ChaCha20-Poly1305 with freshly generated keys')
    backup = sub.add_parser('backup', help='Durable backup of the whole local store (every case), outside any single job')
    backup.add_argument('dest', help='Destination file path; must not already exist')
    restore = sub.add_parser('restore', help='Restore a prior backup into a fresh --home, proving durable recovery')
    restore.add_argument('source', help='Local backup file to restore from')
    inv = sub.add_parser('investigate', help='Register investigation and declared authorization')
    for name in ('project', 'objective', 'scope', 'owner', 'authorization'):
        inv.add_argument('--' + name, required=True)
    inv.add_argument('--allow-recovery', action='store_true', help='Explicitly authorize recovery investigation within scope; no key required for assessment')
    inv.add_argument('--valid-hours', type=float, default=24)
    status = sub.add_parser('status', help='List cases or display one case')
    status.add_argument('case', nargs='?')
    logs = sub.add_parser('logs', help='View the raw hash-linked audit log for a case')
    logs.add_argument('case')
    for name in ('report', 'pause', 'resume', 'revoke', 'run'):
        cmd = sub.add_parser(name, help={'report': 'Generate technical report', 'pause': 'Pause at operation boundary', 'resume': 'Resume persistent investigation', 'revoke': 'Revoke operation permission', 'run': 'Run one persistent pending task'}[name])
        cmd.add_argument('case')
    worker = sub.add_parser('worker', help='Run bounded persistent queue worker (beta)')
    worker.add_argument('case')
    worker.add_argument('--max-tasks', type=int, default=100)
    worker.add_argument('--max-seconds', type=float, default=300)
    worker.add_argument('--poll-interval', type=float, default=.2)
    worker.add_argument('--idle-timeout', type=float, default=0)
    cancel = sub.add_parser('cancel', help='Permanently stop a case, preserving committed evidence')
    cancel.add_argument('case')
    cancel.add_argument('--reason', required=True)
    for name in ('classify', 'plan', 'plans', 'assignments'):
        cmd = sub.add_parser(name, help={'classify': 'Classify the investigation type from its objective',
                                         'plan': 'Create an ordered execution plan for the case',
                                         'plans': 'List execution plans and steps for the case',
                                         'assignments': 'List task execution assignments (broker decisions)'}[name])
        cmd.add_argument('case')
    decompose = sub.add_parser('decompose', help='Materialize plan tasks for an authorized file and assign an executor')
    decompose.add_argument('case')
    decompose.add_argument('path')
    decompose.add_argument('--compare-to', help='Second authorized input for paired firmware/CAN comparison')
    basis = sub.add_parser('authorize-basis', help='Record the authorization basis (owner consent or legal authority)')
    basis.add_argument('case')
    basis.add_argument('--kind', choices=('owner_consent', 'legal_authority'), required=True)
    for name in ('authority', 'reference', 'examiner', 'scope-note'):
        basis.add_argument('--' + name, required=True)
    lab = sub.add_parser('make-lab-envelope', help='Create a CCPW1 lab file on your own scope to exercise the recovery self-test')
    lab.add_argument('case')
    lab.add_argument('path', help='Output path inside the authorized scope; must not already exist')
    lab.add_argument('--passphrase-file', required=True, help='Local file whose first line is the passphrase; never logged')
    lab.add_argument('--content', default='cyber-core lab self-test content', help='Synthetic plaintext to seal into the lab file')
    selftest = sub.add_parser('self-test-recovery', help='Authorized recovery self-test on your own CCPW1 lab file (create it with make-lab-envelope)')
    selftest.add_argument('case')
    selftest.add_argument('path')
    selftest.add_argument('--wordlist', required=True, help='Local file with one candidate passphrase per line')
    selftest.add_argument('--max-candidates', type=int, default=10000, help='Maximum candidate passphrases to try')
    selftest.add_argument('--max-seconds', type=float, default=30)
    materialize = sub.add_parser('materialize-wordlist',
                                 help='Write a prefix of a bundled real-world wordlist as a file inside the case '
                                      'scope, ready to pass as --candidates to recovery-session start')
    materialize.add_argument('case')
    materialize.add_argument('path', help='Output path inside the authorized scope; must not already exist')
    materialize.add_argument('--source', choices=('rockyou',), default='rockyou',
                             help='Bundled wordlist to draw from (rockyou: 14,344,391 real breached passwords)')
    materialize.add_argument('--limit', type=int, default=100000,
                             help='How many candidate lines to write (recovery-session caps candidates at 100000)')
    generate = sub.add_parser('generate-wordlist',
                              help='Expand hint words (names, dates, references) into a rule-based candidates '
                                   'file, ready to pass as --candidates to recovery-session start. No AI, no '
                                   'network: fixed local rules (case, leetspeak, digits, years, separators).')
    generate.add_argument('case')
    generate.add_argument('path', help='Output path inside the authorized scope; must not already exist')
    generate.add_argument('--word', dest='words', action='append', required=True,
                          help='A hint word; repeat --word for each one (1-50 words, not the password itself)')
    generate.add_argument('--limit', type=int, default=100000,
                          help='Maximum candidate lines to write (recovery-session caps candidates at 100000)')
    analyze = sub.add_parser('analyze-file', help='Acquire verified copy and analyze statically')
    analyze.add_argument('case')
    analyze.add_argument('path')
    analyze.add_argument('--queue-only', action='store_true')
    for name in ('analyze-firmware', 'analyze-can'):
        specialist = sub.add_parser(name, help='Analyze authorized offline ' + name.removeprefix('analyze-') + ' evidence')
        specialist.add_argument('case'); specialist.add_argument('path')
        specialist.add_argument('--compare-to', help='Second authorized input to compare without modification')
        specialist.add_argument('--queue-only', action='store_true')
    from cyber_core.cli.operations import configure as configure_operations
    configure_operations(sub)
    aes = sub.add_parser('recover-aes', help='Recover a CCAES1 AES-256-GCM envelope with supplied key')
    aes.add_argument('case')
    aes.add_argument('path')
    aes.add_argument('--key-file', required=True, help='Local protected file containing exactly 32 raw bytes; never logged')
    aes.add_argument('--expected-sha256')
    aes.add_argument('--expected-format')
    custody = sub.add_parser('custody', help='Forensic timeline / chain-of-custody view from the audit trail')
    custody.add_argument('case')
    auditcfg = sub.add_parser('audit-config', help='Static authorized audit of a config file for exposed secrets / insecure settings')
    auditcfg.add_argument('case')
    auditcfg.add_argument('path')
    auditcrypto = sub.add_parser('audit-crypto', help='Static audit of cryptographic implementation patterns (ECB, static IV, hardcoded keys, weak RNG/hash)')
    auditcrypto.add_argument('case')
    auditcrypto.add_argument('path')
    yarascan = sub.add_parser('scan-yara', help='Static YARA signature scan over an authorized sample (no execution/network); requires --yara-rules')
    yarascan.add_argument('case')
    yarascan.add_argument('path')
    yarascan.add_argument('--max-sample', type=int, default=1048576)
    yarascan.add_argument('--yara-timeout', type=float, default=10)
    capture = sub.add_parser('analyze-capture', help='Passively analyze a generic hex protocol capture (no bus/network access)')
    capture.add_argument('case')
    capture.add_argument('path')
    capture.add_argument('--compare-to', help='Second authorized capture to compare')
    disk = sub.add_parser('inspect-disk', help='Bounded, read-only MBR/GPT inventory of a raw disk image (no mount/write/recovery)')
    disk.add_argument('case')
    disk.add_argument('path')
    disk.add_argument('--sector-size', type=int, default=512, choices=(512, 4096))
    disk.add_argument('--max-bytes', type=int, default=16 * 1024 * 1024)
    disk.add_argument('--max-partitions', type=int, default=256)
    pcap = sub.add_parser('inspect-pcap', help='Bounded, read-only classic PCAP inventory (no live capture/network access)')
    pcap.add_argument('case')
    pcap.add_argument('path')
    pcap.add_argument('--max-bytes', type=int, default=16 * 1024 * 1024)
    pcap.add_argument('--max-packets', type=int, default=256)
    strings = sub.add_parser('strings', help='Extract bounded ASCII/UTF-16LE strings from an authorized file (static)')
    strings.add_argument('case')
    strings.add_argument('path')
    strings.add_argument('--min-length', type=int, default=4)
    strings.add_argument('--max-strings', type=int, default=1000)
    differ = sub.add_parser('differentiate', help='Statically differentiate encoding vs compression vs encryption vs structured')
    differ.add_argument('case')
    differ.add_argument('path')
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
    classify_src = sub.add_parser('classify-source', help='Classify a source URL authority (official/academic/community) offline')
    classify_src.add_argument('--url', required=True)
    sources = sub.add_parser('sources', help='List registered technical sources for a case with authority heuristic')
    sources.add_argument('case')
    side = sub.add_parser('side-analyses', help='List persisted side analyses (strings/differentiate/audit-config/capture) for a case')
    side.add_argument('case')
    side.add_argument('--kind', help='Filter by kind: strings, differentiate, config_audit, crypto_audit, capture, disk_inventory, pcap_inventory, yara_scan')
    recall = sub.add_parser('recall', help='Recall prior knowledge by evidence SHA-256 or by investigation type')
    recall.add_argument('--sha256', help='Find prior investigations that analyzed this exact evidence hash')
    recall.add_argument('--type', dest='recall_type', help='List prior investigations of this type')
    recall.add_argument('--limit', type=int, default=20)
    from cyber_core.cli.science import configure
    configure(sub)
    return p


def external_configuration(args):
    if bool(args.ghidra_home) != bool(args.java_home):
        raise CoreError('--ghidra-home and --java-home must be provided together')
    config = {}
    if args.ghidra_home:
        config['ghidra'] = {'home': args.ghidra_home, 'java_home': args.java_home}
    if args.binwalk_executable:
        config['binwalk'] = {'executable': args.binwalk_executable}
    return config



def _main(argv=None):
    core = None
    try:
        args = parser().parse_args(argv)
        if args.command in ('doctor', 'agents', 'crypto-demo'):
            if args.command == 'crypto-demo':
                from cyber_core.cryptanalysis.algorithms import demonstrate_all
                result = demonstrate_all()
            else:
                result = doctor()
                if args.command == 'agents':
                    result = result['agents']
        elif args.command == 'restore':
            # Must not construct Core(args.home, ...) first: that would already
            # create/open an empty store at the destination before we can check
            # whether one exists there.
            restored = Core.restore(args.home, args.source, max_bytes=args.max_bytes, timeout=args.timeout,
                                    max_attempts=args.max_attempts, agent_calls_per_case=args.agent_calls_per_case)
            try:
                result = {'restored': True, 'home': str(restored.home)}
            finally:
                restored.close()
        else:
            core = Core(args.home, max_bytes=args.max_bytes, timeout=args.timeout,
                        max_attempts=args.max_attempts, agent_calls_per_case=args.agent_calls_per_case)
            cmd = args.command
            if cmd in ('hypothesis', 'experiment', 'research', 'verify', 'history'):
                from cyber_core.cli.science import execute
                result = execute(core, args)
            elif cmd in ('keys', 'inventory-disk', 'inventory-pcap', 'agent-jobs', 'recovery-session'):
                from cyber_core.cli.operations import execute
                result = execute(core, args)
            elif cmd == 'init':
                result = {'initialized': True, 'home': str(core.home), 'schema': 8}
            elif cmd == 'backup':
                result = core.backup(args.dest)
            elif cmd == 'investigate':
                result = {'id': core.investigate(args.project, args.objective, args.scope, args.owner, args.authorization, recovery=args.allow_recovery, valid_hours=args.valid_hours)}
            elif cmd == 'status':
                result = {'investigation': core.get(args.case), 'tasks': core.tasks(args.case), 'checkpoints': core.checkpoints(args.case)} if args.case else [dict(r) for r in core.db.execute('SELECT id,project,state,paused,created FROM investigations ORDER BY created')]
            elif cmd == 'logs':
                result = {'audit': core.audit(args.case), 'chain_valid': core.verify_audit(args.case)}
            elif cmd in ('analyze-file', 'analyze-firmware', 'analyze-can'):
                if core.get(args.case)['paused']:
                    raise CoreError('Investigation is paused')
                core.configure_external_tools(external_configuration(args))
                task = core.enqueue(args.case, args.path, tool=cmd, second_path=getattr(args, 'compare_to', None))
                result = {'task': task} if args.queue_only else core.run_one(args.case, task_id=task)
            elif cmd == 'worker':
                core.configure_external_tools(external_configuration(args))
                result = core.run_queue(args.case, max_tasks=args.max_tasks, max_seconds=args.max_seconds,
                                        poll_interval=args.poll_interval, idle_timeout=args.idle_timeout)
            elif cmd == 'cancel':
                result = core.cancel(args.case, reason=args.reason)
            elif cmd in ('classify', 'plan', 'plans', 'assignments'):
                result = getattr(core, cmd)(args.case)
            elif cmd == 'decompose':
                result = core.decompose(args.case, args.path, second_path=args.compare_to)
            elif cmd == 'authorize-basis':
                result = core.set_authorization_basis(args.case, kind=args.kind, authority=args.authority,
                                                      reference=args.reference, examiner=args.examiner, scope_note=args.scope_note)
            elif cmd == 'make-lab-envelope':
                passphrase_file = local_path(args.passphrase_file)
                lines = passphrase_file.read_text(encoding='utf-8', errors='replace').splitlines()
                passphrase = lines[0] if lines else ''
                result = core.make_lab_envelope(args.case, args.path, passphrase=passphrase, content=args.content.encode('utf-8'))
                del passphrase
            elif cmd == 'self-test-recovery':
                wordlist = local_path(args.wordlist)
                candidates = [line for line in wordlist.read_text(encoding='utf-8', errors='replace').splitlines() if line]
                result = core.self_test_recovery(args.case, args.path, candidates, max_attempts=args.max_candidates, max_seconds=args.max_seconds)
            elif cmd == 'materialize-wordlist':
                result = core.materialize_wordlist(args.case, args.path, source=args.source, limit=args.limit)
            elif cmd == 'generate-wordlist':
                result = core.materialize_generated_wordlist(args.case, args.path, args.words, limit=args.limit)
            elif cmd == 'run':
                result = core.run_one(args.case)
            elif cmd == 'custody':
                result = core.custody_timeline(args.case)
            elif cmd == 'audit-config':
                result = core.audit_config(args.case, args.path)
            elif cmd == 'audit-crypto':
                result = core.audit_crypto_implementation(args.case, args.path)
            elif cmd == 'scan-yara':
                if args.yara_rules:
                    core.configure_yara_rules(args.yara_rules)
                result = core.scan_with_yara(args.case, args.path, max_sample=args.max_sample, timeout=args.yara_timeout)
            elif cmd == 'analyze-capture':
                result = core.analyze_capture(args.case, args.path, second_path=args.compare_to)
            elif cmd == 'inspect-disk':
                result = core.inspect_disk_image(args.case, args.path, sector_size=args.sector_size,
                                                 max_bytes=args.max_bytes, max_partitions=args.max_partitions)
            elif cmd == 'inspect-pcap':
                result = core.inspect_pcap(args.case, args.path, max_bytes=args.max_bytes, max_packets=args.max_packets)
            elif cmd == 'strings':
                result = core.extract_strings(args.case, args.path, min_length=args.min_length, max_strings=args.max_strings)
            elif cmd == 'differentiate':
                result = core.differentiate_content(args.case, args.path)
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
            elif cmd == 'classify-source':
                result = core.classify_source(args.url)
            elif cmd == 'sources':
                result = core.sources(args.case)
            elif cmd == 'side-analyses':
                result = core.side_analyses(args.case, kind=args.kind)
            elif cmd == 'recall':
                if args.sha256:
                    result = {'matches': core.recall_by_hash(args.sha256, limit=max(1, min(args.limit, 1000)))}
                elif args.recall_type:
                    result = {'cases': core.recall_by_type(args.recall_type, limit=args.limit)}
                else:
                    raise CoreError('Provide --sha256 or --type to recall')
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


def main(argv=None):
    # Standalone metadata inspection does not create an operational database.
    args = parser().parse_args(argv)
    if args.command != "keys" or args.keys_action != "inspect":
        return _main(argv)
    try:
        from cyber_core.recovery import inspect_key
        result = inspect_key(args.path,max_bytes=args.key_max_bytes,timeout=args.timeout)
        print(json.dumps(result,ensure_ascii=True,indent=2))
        return 0
    except (CoreError,OSError,ValueError) as exc:
        message = str(exc) if isinstance(exc,CoreError) else "Invalid configuration or inaccessible local resource"
        print("cyber: "+message,file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130
