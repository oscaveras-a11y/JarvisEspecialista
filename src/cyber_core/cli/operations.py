"""Argument wiring for durable recovery, key metadata, inventories and agent jobs."""
def configure(sub):
    campaign=sub.add_parser('pentest',help='Create and run durable automatic assessment campaigns')
    actions=campaign.add_subparsers(dest='pentest_action',required=True)
    for action in ('create','run','show'):
        command=actions.add_parser(action)
        command.add_argument('case')
        command.add_argument('manifest' if action=='create' else 'campaign')
        if action=='run':
            command.add_argument('--max-stages',type=int,default=16)
            command.add_argument('--max-seconds',type=float,default=300)
    api=sub.add_parser('api-inventory',help='Inventory supplied OpenAPI JSON without network requests')
    api.add_argument('case')
    api.add_argument('path')
    api.add_argument('--grant',required=True)
    api.add_argument('--max-bytes',dest='api_max_bytes',type=int,default=1048576)
    api.add_argument('--max-operations',type=int,default=64)
    api.add_argument('--output-bytes',type=int,default=131072)
    api.add_argument('--seconds',type=float,default=30)
    passive=sub.add_parser('web-passive',help='Collect authorized HTTPS and scan offline with networkless ZAP')
    passive.add_argument('case')
    passive.add_argument('manifest')
    passive.add_argument('--ca-file')
    passive.add_argument('--body-bytes',type=int,default=65536)
    passive.add_argument('--seconds',type=float,default=120)
    web=sub.add_parser('web-probe',help='Observe explicitly authorized HTTPS endpoints without writes')
    web.add_argument('case')
    web.add_argument('manifest')
    web.add_argument('--ca-file',help='Optional scoped public CA certificate; TLS verification remains mandatory')
    web.add_argument('--body-bytes',type=int,default=65536)
    web.add_argument('--seconds',type=float,default=30)
    web.add_argument('--inventory',action='store_true',help='Inventory bounded static HTML without submitting forms')
    timeline=sub.add_parser('firmware-timeline',help='Correlate offline firmware records without a fraud verdict')
    timeline.add_argument('case')
    timeline.add_argument('path')
    timeline.add_argument('--max-input-bytes',type=int,default=16777216)
    timeline.add_argument('--max-events',type=int,default=10000)
    timeline.add_argument('--max-findings',type=int,default=128)
    timeline.add_argument('--max-line-bytes',type=int,default=16384)
    timeline.add_argument('--max-seconds',type=float,default=30)
    lab=sub.add_parser('web-lab',help='Run scoped synthetic HTTP laboratory')
    lab.add_argument('case')
    lab.add_argument('manifest')
    symbols = sub.add_parser("symbols", help="Read COFF symbols and optionally demangle C++ without execution")
    symbols.add_argument("case")
    symbols.add_argument("path")
    symbols.add_argument("--llvm-bin")
    symbols.add_argument("--max-symbols", type=int, default=128)
    symbols.add_argument("--max-records", type=int, default=100000)
    symbols.add_argument("--max-name-bytes", type=int, default=512)
    symbols.add_argument("--output-bytes", type=int, default=1048576)
    functions = sub.add_parser("functions", help="Select static Ghidra functions and inspect references")
    functions.add_argument("case")
    functions.add_argument("path")
    functions.add_argument("--name", action="append", default=[])
    functions.add_argument("--address", action="append", type=lambda v:int(v,0), default=[])
    functions.add_argument("--range", dest="entry_ranges", action="append", nargs=2, type=lambda v:int(v,0), default=[])
    functions.add_argument("--max-functions", type=int, default=8)
    functions.add_argument("--max-references", type=int, default=64)
    functions.add_argument("--decompile-seconds", type=int, default=5)
    functions.add_argument("--analysis-seconds", type=int, default=30)
    functions.add_argument("--pseudocode-chars", type=int, default=4096)
    functions.add_argument("--output-bytes", type=int, default=1048576)
    installer = sub.add_parser("installer", help="List or extract selected NSIS files without running the installer")
    installer.add_argument("case")
    installer.add_argument("path")
    installer.add_argument("--seven-zip", required=True)
    installer.add_argument("--extract", action="store_true")
    installer.add_argument("--max-extracted-bytes", type=int, default=1073741824)
    installer.add_argument("--memory-bytes", type=int, default=536870912)
    sub.add_parser("recovery-formats", help="Show supported recovery formats and available dependencies")
    external = sub.add_parser("external-analyze", help="Static external identification of verified evidence")
    external.add_argument("case")
    external.add_argument("path")
    external.add_argument("--tool", choices=("die", "unblob"), required=True)
    sub.add_parser("external-tools", help="Show configured external tool availability")
    keys = sub.add_parser("keys",help="Inspect key metadata or inventory an authorized directory")
    actions = keys.add_subparsers(dest="keys_action",required=True)
    inspect = actions.add_parser("inspect")
    inspect.add_argument("path")
    inspect.add_argument("--max-bytes",dest="key_max_bytes",type=int,default=1048576)
    scan = actions.add_parser("scan")
    scan.add_argument("case")
    scan.add_argument("path")
    scan.add_argument("--recursive",action="store_true")
    scan.add_argument("--max-files",type=int,default=100)
    scan.add_argument("--max-total-bytes",type=int,default=16777216)
    for name in ("inventory-disk","inventory-pcap"):
        parser = sub.add_parser(name,help="Read-only inventory of a verified evidence copy")
        parser.add_argument("case")
        parser.add_argument("path")
        parser.add_argument("--max-bytes",dest="inventory_max_bytes",type=int,default=16777216)
        if name == "inventory-disk":
            parser.add_argument("--max-partitions",type=int,default=256)
            parser.add_argument("--sector-size",type=int,choices=(512,4096),default=512)
        else:
            parser.add_argument("--max-packets",type=int,default=256)
    agent = sub.add_parser("agent-jobs",help="Persistent Codex/Claude metadata reviews")
    commands = agent.add_subparsers(dest="agent_action",required=True)
    for action in ("enqueue","run","list","retry"):
        parser = commands.add_parser(action)
        parser.add_argument("case")
        if action in ("run","retry"):
            parser.add_argument("job")
        if action in ("enqueue","retry"):
            parser.add_argument("--allow-cloud-summary",action="store_true")
        if action == "enqueue":
            parser.add_argument("--agent",choices=("codex","claude"),default="codex")
            parser.add_argument("--depends-on")
        if action == "retry":
            parser.add_argument("--reason",required=True)
            parser.add_argument("--acknowledge-uncertain",action="store_true")
    recovery = sub.add_parser("recovery-session",help="Checkpointed trials of owner-supplied candidates")
    commands = recovery.add_subparsers(dest="recovery_action",required=True)
    for action in ("start","work","show","list","pause","resume","cancel","extend"):
        parser = commands.add_parser(action)
        parser.add_argument("case")
        if action == "start":
            parser.add_argument("path")
            parser.add_argument("--candidates",required=True)
            parser.add_argument("--mode",choices=("auto","ccaes1","ssh-private","zip","7z","pdf","office","pkcs12","qpdf-pdf","openssl-pkcs12","hashcat-sha256","john-sha256","john-zip","hashcat-zip-aes","rar5","john-rar5"),default="ccaes1")
            parser.add_argument("--hours",type=float,default=24)
            parser.add_argument("--max-candidates",type=int,default=100000)
        elif action != "list":
            parser.add_argument("job")
        if action == "show":
            parser.add_argument("--show-password", action="store_true",
                                help="Explicitly display the recovered candidate from the verified original list")
        if action == "work":
            parser.add_argument("--max-attempts",type=int,default=20)
            parser.add_argument("--max-seconds",type=float,default=30)
        if action == "resume":
            parser.add_argument("--reason",help="Required to retry a resource-limited local trial")
        if action == "extend":
            parser.add_argument("--hours",type=float,required=True)
            parser.add_argument("--reason",required=True)
            parser.add_argument("--priority",action="store_true")

COMMANDS = ("web-passive","api-inventory","pentest","web-probe","firmware-timeline","web-lab","symbols","functions","installer","external-analyze","external-tools","recovery-formats","keys","inventory-disk","inventory-pcap","agent-jobs","recovery-session")

def execute(core,args):
    if args.command=="api-inventory":
        from cyber_core.pentest.openapi import run_inventory
        return run_inventory(core,args.case,args.path,args.grant,max_bytes=args.api_max_bytes,
                             max_operations=args.max_operations,output_bytes=args.output_bytes,seconds=args.seconds)
    if args.command=="pentest":
        from cyber_core.pentest import campaigns
        if args.pentest_action=='create':
            return campaigns.create(core,args.case,args.manifest)
        if args.pentest_action=='show':
            return campaigns.show(core,args.case,args.campaign)
        return campaigns.work(core,args.case,args.campaign,max_stages=args.max_stages,max_seconds=args.max_seconds)
    if args.command=="web-passive":
        from cyber_core.pentest.passive import run_passive
        return run_passive(core,args.case,args.manifest,ca_file=args.ca_file,
                           body_bytes=args.body_bytes,seconds=args.seconds)
    if args.command=="web-probe":
        from cyber_core.web_probe import run_probe
        return run_probe(core,args.case,args.manifest,ca_file=args.ca_file,
                         body_bytes=args.body_bytes,seconds=args.seconds,inventory=args.inventory)
    if args.command=="firmware-timeline":
        from cyber_core.forensics.firmware_timeline import run_timeline
        return run_timeline(core,args.case,args.path,max_bytes=args.max_input_bytes,max_events=args.max_events,
                            max_findings=args.max_findings,max_line_bytes=args.max_line_bytes,
                            max_seconds=min(args.max_seconds,core.timeout))
    if args.command=='web-lab':
        from cyber_core.web_lab import run_lab
        return run_lab(core,args.case,args.manifest)
    if args.command == "symbols":
        from cyber_core.reverse_engineering.coff_operation import analyze_symbols
        return analyze_symbols(core,args.case,args.path,llvm_bin=args.llvm_bin,max_symbols=args.max_symbols,
                               max_records=args.max_records,max_name_bytes=args.max_name_bytes,
                               output_bytes=args.output_bytes)
    if args.command == "functions":
        from cyber_core.reverse_engineering.selected import analyze_functions
        return analyze_functions(core,args.case,args.path,ghidra_home=args.ghidra_home,java_home=args.java_home,
                                 names=args.name,addresses=args.address,ranges=args.entry_ranges,
                                 max_functions=args.max_functions,max_references=args.max_references,
                                 decompile_seconds=args.decompile_seconds,analysis_seconds=args.analysis_seconds,
                                 pseudocode_chars=args.pseudocode_chars,output_bytes=args.output_bytes)
    if args.command == "installer":
        from cyber_core.installers import inspect_installer
        return inspect_installer(core,args.case,args.path,seven_zip=args.seven_zip,extract=args.extract,
                                 max_extracted_bytes=args.max_extracted_bytes,memory_bytes=args.memory_bytes)
    if args.command == "external-analyze":
        from cyber_core.external_tools import analyze_tool
        return analyze_tool(core,args.case,args.path,tool=args.tool)
    if args.command == "external-tools":
        from cyber_core.external_tools import tool_inventory
        return tool_inventory()
    if args.command == "recovery-formats":
        from cyber_core.cryptanalysis.formats import inventory
        return inventory()
    if args.command == "keys":
        from cyber_core.recovery import scan_keys
        return scan_keys(core,args.case,args.path,max_files=args.max_files,
                         recursive=args.recursive,max_total_bytes=args.max_total_bytes)
    if args.command == "inventory-disk":
        from cyber_core.operations import inventory_disk
        return inventory_disk(core,args.case,args.path,max_bytes=args.inventory_max_bytes,
                              max_partitions=args.max_partitions,sector_size=args.sector_size)
    if args.command == "inventory-pcap":
        from cyber_core.operations import inventory_pcap
        return inventory_pcap(core,args.case,args.path,max_bytes=args.inventory_max_bytes,max_packets=args.max_packets)
    if args.command == "agent-jobs":
        from cyber_core.orchestrator.broker import Broker
        broker = Broker(core)
        action = args.agent_action
        if action == "enqueue":
            return {"id":broker.enqueue(args.case,agent=args.agent,allow_cloud=args.allow_cloud_summary,depends_on=args.depends_on)}
        if action == "run":
            return broker.run_one(args.case,args.job)
        if action == "list":
            return broker.jobs(args.case)
        return broker.retry(args.case,args.job,allow_cloud=args.allow_cloud_summary,reason=args.reason,
                            acknowledge_uncertain=args.acknowledge_uncertain)
    from cyber_core.cryptanalysis.sessions import RecoverySessions
    manager = RecoverySessions(core)
    action = args.recovery_action
    if action == "start":
        return manager.start(args.case,args.path,args.candidates,mode=args.mode,hours=args.hours,max_candidates=args.max_candidates)
    if action == "work":
        return manager.work(args.case,args.job,max_attempts=args.max_attempts,max_seconds=args.max_seconds)
    if action == "list":
        return manager.jobs(args.case)
    if action == "show":
        if args.show_password:
            return {**manager.get(args.case,args.job), **manager.reveal_password(args.case,args.job)}
        return manager.get(args.case,args.job)
    if action == "extend":
        return manager.extend(args.case,args.job,hours=args.hours,reason=args.reason,priority=args.priority)
    if action == "resume":
        return manager.resume(args.case,args.job,reason=args.reason)
    return getattr(manager,action)(args.case,args.job)
