"""Argument wiring for durable recovery, key metadata, inventories and agent jobs."""
def configure(sub):
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

COMMANDS = ("symbols","functions","installer","external-analyze","external-tools","recovery-formats","keys","inventory-disk","inventory-pcap","agent-jobs","recovery-session")

def execute(core,args):
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
