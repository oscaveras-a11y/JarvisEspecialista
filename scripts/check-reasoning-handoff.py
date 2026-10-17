"""Reproduce item 4 -> item 5 integration using only synthetic GitHub inputs."""
import hashlib
import json
from pathlib import Path
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from cyber_core.service import Core
from cyber_core.investigation.workflow import Workflow
from cyber_core.investigation.reasoning import Reasoning


def main():
    with tempfile.TemporaryDirectory(prefix='cyber-reasoning-handoff-') as folder:
        root = Path(folder)
        inputs = root / 'inputs'
        inputs.mkdir()
        sample = inputs / 'control.bin'
        sample.write_bytes(b'abc')
        core = Core(root / 'state')
        try:
            version = core.db.execute('PRAGMA user_version').fetchone()[0]
            case = core.investigate('handoff', 'Perícia forense de controle sintético',
                                    str(inputs), 'operator', 'Synthetic GitHub laboratory')
            core.classify(case)
            flow, engine = Workflow(core), Reasoning(core)
            source = flow.add_source(case, title='Synthetic fixture specification', url='https://example.org/control',
                                     version='fixture-v1', provenance='experimental', author='analyst')
            parent = None
            for expected in (99, 3):
                hypothesis = flow.add_hypothesis(case, 'Control size equals ' + str(expected), author='analyst')
                experiment = flow.plan_experiment(case, hypothesis, 'Check size ' + str(expected), author='analyst',
                                                   criterion='Measured length matches expected length',
                                                   assertions=[{'field': 'size', 'op': 'eq', 'value': expected}],
                                                   tool='analyze-file')
                strategy = engine.register(case, experiment, actor='analyst', sources=[source],
                                            alternative_to=parent, rationale='Explicit alternative against synthetic control')
                if parent is None:
                    parent = strategy
                out = engine.step(case, sample, actor='operator')
                assert out['status'] == 'evaluated', out
                assert out['run']['outcome'] == ('refutes' if expected == 99 else 'supports')
                flow.review(case, out['run']['id'], reviewer='declared-independent-reviewer',
                            decision='accepted', reason='Synthetic length independently recomputed')
            verdict = flow.finalize(case, 'RESOLVIDO', actor='owner', reason='Three-byte fixture validated after refuting wrong length')
            assert verdict['validated']
            snapshot = engine.snapshot(case)
            assert len(snapshot['cycles']) == 2
            assert all(c['status'] == 'EVALUATED' for c in snapshot['cycles'])
            digest = hashlib.sha256(b'abc').hexdigest()
            matches = core.recall_by_hash(digest)
            assert len(matches) == 2 and all(m['case_id'] == case for m in matches)
            assert any(m['case_id'] == case for m in core.recall_by_type('forensics'))
            report = core.report(case).read_text(encoding='utf-8')
            assert 'contract_version' in report and 'REFUTED' in report and 'SUPPORTED' in report
            assert core.db.execute('PRAGMA user_version').fetchone()[0] == version
            assert core.verify_audit(case)
        finally:
            core.close()
        reopened = Core(root / 'state')
        try:
            saved = Reasoning(reopened).snapshot(case)
            assert len(saved['cycles']) == 2 and saved['validated_resolution']
            assert len(reopened.recall_by_hash(digest)) == 2
            assert reopened.verify_audit(case)
        finally:
            reopened.close()
        print(json.dumps({'item4_item5_handoff': 'passed', 'reasoning_contract': 1,
                          'global_schema_preserved': version, 'cycles': 2,
                          'reviewed_outcomes': ['refutes', 'supports'],
                          'persistent_recall_and_report': True, 'synthetic_only': True}))


if __name__ == '__main__':
    main()
