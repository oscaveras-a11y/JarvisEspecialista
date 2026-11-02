"""Parse NVD API 2.0 JSON (supplied file or fetched via research.fetch). Offline."""
import json
from cyber_core.errors import CoreError


def parse_nvd(content, *, max_items=2000):
    try:
        data = json.loads(content)
    except (TypeError, ValueError) as exc:
        raise CoreError('Invalid NVD JSON') from exc
    if not isinstance(data, dict) or not isinstance(data.get('vulnerabilities'), list):
        raise CoreError('Not an NVD 2.0 response')
    out = []
    for item in data['vulnerabilities'][:max_items]:
        cve = item.get('cve', {}) if isinstance(item, dict) else {}
        desc = next((d.get('value', '') for d in cve.get('descriptions', []) if d.get('lang') == 'en'), '')
        score = severity = None
        for key in ('cvssMetricV31', 'cvssMetricV40', 'cvssMetricV30', 'cvssMetricV2'):
            metrics = cve.get('metrics', {}).get(key)
            if metrics:
                cvss = metrics[0].get('cvssData', {})
                score, severity = cvss.get('baseScore'), cvss.get('baseSeverity') or metrics[0].get('baseSeverity')
                break
        out.append({'id': cve.get('id'), 'published': cve.get('published'), 'cvss': score, 'severity': severity, 'description': desc[:500]})
    return {'cves': out, 'limitation': 'Dados conforme fornecidos; sem confirmação de aplicabilidade ao alvo.'}
