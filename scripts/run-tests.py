"""Run the offline test suite with src on sys.path, without shell environment setup."""
from pathlib import Path
import sys
import unittest

root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root / 'src'))
# Subprocess CLI tests inherit this path through the documented environment.
import os
os.environ['PYTHONPATH'] = str(root / 'src')
pattern = sys.argv[1] if len(sys.argv) > 1 else 'test*.py'
print('CYBER CORE offline tests: ' + pattern, flush=True)
if len(sys.argv) > 2:
    unittest.defaultTestLoader.testNamePatterns = ['*' + sys.argv[2] + '*']
suite = unittest.defaultTestLoader.discover(str(root / 'tests'), pattern=pattern)
if suite.countTestCases() == 0:
    print('No tests matched; refusing a successful empty run', file=sys.stderr)
    raise SystemExit(2)
raise SystemExit(0 if unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful() else 1)
