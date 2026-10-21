"""Argument wiring for durable recovery, key metadata, inventories and agent jobs."""
def configure(sub):
    sub.add_parser("recovery-formats", help="Show supported recovery formats and available dependencies")
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
            parser.add_argument("--mode",choices=("auto","ccaes1","ssh-private","zip","7z","pdf","office","pkcs12"),default="ccaes1")
            parser.add_argument("--hours",type=float,default=24)
            parser.add_argument("--max-candidates",type=int,default=100000)
        elif action != "list":
            parser.add_argument("job")
        if action == "work":
            parser.add_argument("--max-attempts",type=int,default=20)
            parser.add_argument("--max-seconds",type=float,default=30)
        if action == "resume":
            parser.add_argument("--reason",help="Required to retry a resource-limited local trial")
        if action == "extend":
            parser.add_argument("--hours",type=float,required=True)
            parser.add_argument("--reason",required=True)
            parser.add_argument("--priority",action="store_true")

COMMANDS = ("recovery-formats","keys","inventory-disk","inventory-pcap","agent-jobs","recovery-session")

def execute(core,args):
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
        return manager.get(args.case,args.job)
    if action == "extend":
        return manager.extend(args.case,args.job,hours=args.hours,reason=args.reason,priority=args.priority)
    if action == "resume":
        return manager.resume(args.case,args.job,reason=args.reason)
    return getattr(manager,action)(args.case,args.job)
