"""Doctor's pretty output may return zero even when some checks failed."""
import json
import subprocess
import sys

result = subprocess.run([sys.executable, '-m', 'openjarvis.cli', 'doctor', '--json'],
                        check=True, capture_output=True, text=True)
checks = json.loads(result.stdout)
failed = [check for check in checks if check.get('status') == 'fail']
for check in failed:
    print(f"Falha: {check.get('name')}: {check.get('message')}", file=sys.stderr)
if failed:
    print('Corrija estas falhas antes de continuar. Veja README.md.', file=sys.stderr)
    sys.exit(1)
print('Doctor: nenhuma verificacao com status fail.')
