"""Optional real Codex check using only a fixed synthetic summary, no evidence."""
import json
from pathlib import Path
import sys
import tempfile
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from cyber_core.agents.runner import CodexAdapter
from cyber_core.errors import CoreError

with tempfile.TemporaryDirectory(prefix='cyber-agent-smoke-') as folder:
    try:
        result = CodexAdapter(timeout=30).review({'synthetic': True, 'format': 'ELF signature', 'entropy': 7.99, 'question': 'Does a signature alone validate a complete file?'}, Path(folder))
    except CoreError as exc:
        print(json.dumps({'live_integration': False, 'error': str(exc)}))
        raise SystemExit(2)
    print(json.dumps({'live_integration': True, 'result': result}, indent=2))
