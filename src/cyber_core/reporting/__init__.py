"""Reports distinguish observations, hypotheses and unvalidated conclusions."""
import json
from uuid import uuid4
from cyber_core.memory import utc, audit
from cyber_core.permissions import storage_root


def write_report(core, case):
    row = core.get(case)
    folder = storage_root(core.home / 'cases' / case / 'reports')
    output = folder / (uuid4().hex + '.md')
    data = {'investigation': row, 'generated_utc': utc(), 'results': core.results(case),
            'hypotheses': core.hypotheses(case), 'tasks': core.tasks(case),
            'checkpoints': core.checkpoints(case), 'audit_chain_valid': core.verify_audit(case),
            'audit': core.audit(case)}
    # JSON is escaped so evidence-derived strings cannot terminate a Markdown code block.
    payload = json.dumps(data, ensure_ascii=True, indent=2).replace('`', '\\u0060')
    text = '# CYBER CORE technical report\n\nStatus: ' + row['state'] + '\n\n'
    text += 'Static observations are reproducible experiments. Hypotheses remain unconfirmed.\n'
    text += 'No independent agent review has been completed. No conclusion of resolution is implied.\n'
    text += 'Audit hash links detect edits only against this stored chain; they are not digital signatures.\n\n```json\n' + payload + '\n```\n'
    with output.open('x', encoding='utf-8') as handle:
        handle.write(text)
    with core.db:
        audit(core.db, case, 'report_generated', {'path': str(output)})
    return output
