"""Scientific workflow CLI; supplied criteria are data, never code."""
import json
from cyber_core.errors import CoreError
from cyber_core.investigation.workflow import Workflow

COMMANDS = ('hypothesis', 'experiment', 'research', 'verify', 'history')

def configure(sub):
    hyp = sub.add_parser('hypothesis', help='Register, revise and inspect scientific hypotheses')
    hs = hyp.add_subparsers(dest='action', required=True)
    add = hs.add_parser('add'); add.add_argument('case')
    add.add_argument('--statement', required=True); add.add_argument('--author', required=True)
    add.add_argument('--plausibility', type=float, default=.5)
    revise = hs.add_parser('revise'); revise.add_argument('case'); revise.add_argument('id')
    revise.add_argument('--author', required=True); revise.add_argument('--reason', required=True)
    revise.add_argument('--plausibility', type=float, required=True)
    hs.add_parser('list').add_argument('case')
    exp = sub.add_parser('experiment', help='Plan falsifiable checks, evaluate evidence and record review')
    es = exp.add_subparsers(dest='action', required=True)
    plan = es.add_parser('plan'); plan.add_argument('case'); plan.add_argument('hypothesis')
    for name in ('name', 'criterion', 'author', 'tool', 'assertions-file'):
        plan.add_argument('--' + name, required=True)
    plan.add_argument('--max-runs', type=int, default=3)
    evaluate = es.add_parser('evaluate'); evaluate.add_argument('case'); evaluate.add_argument('id')
    evaluate.add_argument('--task', required=True); evaluate.add_argument('--operator', required=True)
    review = es.add_parser('review'); review.add_argument('case'); review.add_argument('id')
    for name in ('reviewer', 'reason'):
        review.add_argument('--' + name, required=True)
    review.add_argument('--decision', choices=('accepted', 'rejected'), required=True)
    es.add_parser('list').add_argument('case')
    source = sub.add_parser('research', help='Register consulted technical reference metadata; no implicit web retrieval')
    source.add_argument('case')
    for name in ('title', 'url', 'version', 'author'):
        source.add_argument('--' + name, required=True)
    source.add_argument('--provenance', choices=('documented', 'inference', 'experimental'), required=True)
    verify = sub.add_parser('verify', help='Apply evidence and independent-review gates before changing state')
    verify.add_argument('case')
    for name in ('state', 'actor', 'reason'):
        verify.add_argument('--' + name, required=True)
    history = sub.add_parser('history', help='Search investigation metadata in this client storage')
    history.add_argument('--query', required=True); history.add_argument('--project')
    history.add_argument('--limit', type=int, default=20)

def execute(core, args):
    flow = Workflow(core)
    cmd = args.command
    if cmd == 'history':
        return {'matches': flow.search(args.query, project=args.project, limit=args.limit)}
    if cmd == 'hypothesis':
        if args.action == 'add':
            return {'id': flow.add_hypothesis(args.case, args.statement, author=args.author, plausibility=args.plausibility)}
        if args.action == 'revise':
            return flow.revise_hypothesis(args.case, args.id, author=args.author, plausibility=args.plausibility, reason=args.reason)
        return flow.snapshot(args.case)['hypotheses']
    if cmd == 'experiment':
        if args.action == 'plan':
            path = core.authorize(args.case, args.assertions_file)
            with path.open('rb') as handle:
                content = handle.read(16385)
            if len(content) > 16384:
                raise CoreError('Experiment criteria file exceeds 16 KiB')
            criteria = json.loads(content)
            return {'id': flow.plan_experiment(args.case, args.hypothesis, args.name, author=args.author,
                                                criterion=args.criterion, assertions=criteria, tool=args.tool, max_runs=args.max_runs)}
        if args.action == 'evaluate':
            return flow.evaluate(args.case, args.id, args.task, operator=args.operator)
        if args.action == 'review':
            return {'id': flow.review(args.case, args.id, reviewer=args.reviewer, decision=args.decision, reason=args.reason)}
        data = flow.snapshot(args.case)
        return {key: data[key] for key in ('experiments', 'runs', 'reviews')}
    if cmd == 'research':
        return {'id': flow.add_source(args.case, title=args.title, url=args.url, version=args.version,
                                      provenance=args.provenance, author=args.author),
                'retrieval': 'operator_reference_registration_only'}
    if cmd == 'verify':
        return flow.finalize(args.case, args.state, actor=args.actor, reason=args.reason)
    raise CoreError('Unknown scientific workflow operation')
