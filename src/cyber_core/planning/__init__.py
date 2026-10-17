"""Deterministic investigation typing and planning. Pure functions, no side effects.

Implements part of item 3 of the scope (identificar tipo, criar planos, escolher
ferramentas). Design: docs/design/03-arquitetura-core.md. The reasoning engine
(item 4) may refine these later; here everything is explicit and auditable, and
tool selection never leaves the allowlist.
"""
from cyber_core.errors import CoreError

# Tools already allowlisted by the service; planning never invents a tool.
TOOLS = ('analyze-file', 'assess-recovery', 'analyze-firmware', 'analyze-can')

# Lowercased substring signals per investigation type (first-pass heuristic).
TYPE_RULES = (
    ('firmware', ('firmware', 'bootloader', 'microcontrolador', 'ecu', '.bin', '.hex', 's19', 'srec', 'intel hex')),
    ('automotive', ('can fd', 'canbus', 'can bus', 'barramento can', ' obd', 'veicul', 'automotiv')),
    ('crypto', ('cripto', 'crypto', 'aes', 'rsa', 'ecc', 'chacha', 'senha', 'password', 'chave', 'entropia', 'encrypt', 'recupera', 'criptografad')),
    ('forensics', ('forense', 'forensic', 'pericia', 'perícia', 'evidencia', 'evidência', 'imagem de disco', 'metadado', 'timeline', 'linha do tempo', 'custodia', 'custódia')),
    ('vulnerability', ('vulnerab', 'cve', 'exploit', 'auditoria', 'pentest', 'owasp', 'injection', 'injeção')),
)

# Observed file signature (from reverse_engineering.identify) reinforces a type.
FORMAT_TO_TYPE = {
    'ELF signature': 'firmware', 'DOS/PE signature': 'firmware',
    'CYBER CORE AES-GCM envelope': 'crypto', 'ZIP signature': 'crypto',
}

TOOL_BY_TYPE = {
    'firmware': 'analyze-firmware', 'automotive': 'analyze-can',
    'crypto': 'assess-recovery', 'forensics': 'analyze-file',
    'vulnerability': 'analyze-file', 'generic': 'analyze-file',
}


def classify_investigation(objective, *, observed_format=None):
    """Return {type, confidence, rationale, signals} from the objective text."""
    if not isinstance(objective, str) or not objective.strip():
        raise CoreError('Objective is required for classification')
    text = objective.lower()
    scores, signals = {}, []
    for kind, keywords in TYPE_RULES:
        hits = [k for k in keywords if k in text]
        if hits:
            scores[kind] = scores.get(kind, 0) + len(hits)
            signals.extend(kind + ':' + h.strip() for h in hits)
    if observed_format in FORMAT_TO_TYPE:
        reinforced = FORMAT_TO_TYPE[observed_format]
        scores[reinforced] = scores.get(reinforced, 0) + 2
        signals.append('format:' + observed_format)
    if not scores:
        return {'type': 'generic', 'confidence': 0.0,
                'rationale': 'No type-specific signal found in the objective', 'signals': []}
    best = max(scores, key=lambda k: (scores[k], k))
    total = sum(scores.values())
    return {'type': best, 'confidence': round(scores[best] / total, 3),
            'rationale': 'Matched ' + str(scores[best]) + ' of ' + str(total) + ' signal(s) for ' + best,
            'signals': sorted(signals)}


def select_tool(investigation_type, *, available=TOOLS):
    """Pick the default tool for a type; never outside the allowlist."""
    tool = TOOL_BY_TYPE.get(investigation_type, 'analyze-file')
    if tool not in available:
        raise CoreError('Selected tool is not allowlisted')
    return {'tool': tool, 'reason': 'Default tool for investigation type ' + investigation_type}


def build_plan(investigation_type):
    """Ordered, declarative plan steps (data, never executable instructions)."""
    tool = select_tool(investigation_type)['tool']
    steps = [{'goal': 'Adquirir cópia verificada e observar assinatura/entropia',
              'candidate_tool': tool,
              'success_criterion': 'Cópia verificada com hash e formato identificado'}]
    if investigation_type == 'crypto':
        steps.append({'goal': 'Triagem de recuperação sem chave, sem afirmar recuperação',
                      'candidate_tool': 'assess-recovery',
                      'success_criterion': 'Rotas de recuperação avaliadas e limitações registradas'})
    elif investigation_type == 'firmware':
        steps.append({'goal': 'Comparar versões de firmware quando houver segunda amostra',
                      'candidate_tool': 'analyze-firmware',
                      'success_criterion': 'Diferenças estruturais registradas sem modificar originais'})
    elif investigation_type == 'automotive':
        steps.append({'goal': 'Comparar capturas CAN quando houver segunda amostra',
                      'candidate_tool': 'analyze-can',
                      'success_criterion': 'Padrões e diferenças de mensagens em análise passiva'})
    steps.append({'goal': 'Registrar hipótese e exigir verificação independente antes de concluir',
                  'candidate_tool': tool,
                  'success_criterion': 'Estado só muda com evidência reproduzível e revisão (item 13)'})
    return steps
