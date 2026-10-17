"""Item 4 actions within the existing scientific experiment command."""
from cyber_core.errors import CoreError
from cyber_core.investigation.reasoning import Reasoning

ACTIONS = ('strategy', 'rank', 'cycle', 'block', 'unblock', 'note', 'reasoning')


def configure(actions):
    strategy = actions.add_parser('strategy', help='Register priority and grounding for a scientific experiment')
    strategy.add_argument('case'); strategy.add_argument('experiment')
    strategy.add_argument('--actor', required=True); strategy.add_argument('--rationale', required=True)
    strategy.add_argument('--cost', type=float, default=1); strategy.add_argument('--risk', type=float, default=0)
    strategy.add_argument('--evidence', action='append', default=[])
    strategy.add_argument('--source', action='append', default=[])
    strategy.add_argument('--alternative-to')
    actions.add_parser('rank', help='Rank declared experiments without executing them').add_argument('case')
    actions.add_parser('reasoning', help='Inspect persistent reasoning contract').add_argument('case')
    cycle = actions.add_parser('cycle', help='Run bounded, evidence-grounded investigation steps')
    cycle.add_argument('case'); cycle.add_argument('path'); cycle.add_argument('--operator', required=True)
    cycle.add_argument('--compare-to'); cycle.add_argument('--max-steps', type=int, default=10)
    cycle.add_argument('--max-seconds', type=float, default=300)
    block = actions.add_parser('block', help='Record missing data, hardware, keys, permission or resources')
    block.add_argument('case'); block.add_argument('strategy')
    block.add_argument('--kind', choices=('data','hardware','key','authorization','resource'), required=True)
    block.add_argument('--detail', required=True); block.add_argument('--actor', required=True)
    unblock = actions.add_parser('unblock', help='Record blocker resolution; never grants permission')
    unblock.add_argument('case'); unblock.add_argument('blocker')
    unblock.add_argument('--reason', required=True); unblock.add_argument('--actor', required=True)
    note = actions.add_parser('note', help='Record an inference or unknown, never an invented fact')
    note.add_argument('case'); note.add_argument('--kind', choices=('INFERENCE', 'UNKNOWN'), required=True)
    note.add_argument('--statement', required=True); note.add_argument('--actor', required=True)


def execute(core, args):
    engine = Reasoning(core)
    if args.action == 'strategy':
        return {'id': engine.register(args.case, args.experiment, actor=args.actor, rationale=args.rationale,
                                      cost=args.cost, risk=args.risk, evidence=args.evidence, sources=args.source,
                                      alternative_to=args.alternative_to)}
    if args.action == 'rank':
        return engine.rank(args.case)
    if args.action == 'reasoning':
        return engine.snapshot(args.case)
    if args.action == 'cycle':
        return engine.run(args.case, args.path, actor=args.operator, second_path=args.compare_to,
                          max_steps=args.max_steps, max_seconds=args.max_seconds)
    if args.action == 'block':
        return {'id': engine.block(args.case, args.strategy, kind=args.kind, detail=args.detail, actor=args.actor)}
    if args.action == 'unblock':
        return engine.unblock(args.case, args.blocker, actor=args.actor, reason=args.reason)
    if args.action == 'note':
        return {'id': engine.note(args.case, args.kind, args.statement, actor=args.actor)}
    raise CoreError('Unknown reasoning action')
