"""The optional live probe is inert unless explicitly requested."""
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

class LiveProbeContract(unittest.TestCase):
    def run_probe(self, *args):
        script = Path(__file__).resolve().parents[1] / 'scripts' / 'agent-broker-smoke.py'
        self.assertTrue(script.is_file(), 'The manual synthetic broker probe must exist')
        env = {key: value for key, value in os.environ.items()
               if key.upper() not in ('CODEX_API_KEY', 'OPENAI_API_KEY', 'CODEX_ACCESS_TOKEN',
                                      'ANTHROPIC_API_KEY', 'CLAUDE_CODE_OAUTH_TOKEN')}
        run = subprocess.run([sys.executable, str(script), *args], capture_output=True,
                             text=True, timeout=10, env=env)
        return run.returncode, json.loads(run.stdout)
    def test_no_opt_in_never_attempts_provider_call(self):
        code, result = self.run_probe()
        self.assertEqual(code, 0)
        self.assertEqual(result['status'], 'not_requested')
        self.assertFalse(result['live_call_attempted'])
        self.assertFalse(result['live_integration'])
    def test_explicit_live_without_ci_credentials_is_missing_resource(self):
        code, result = self.run_probe('--live', '--agents', 'both')
        self.assertEqual(code, 2)
        self.assertEqual(result['status'], 'awaiting_resources')
        self.assertEqual(result['missing'], ['codex', 'claude'])
        self.assertFalse(result['live_call_attempted'])
        self.assertFalse(result['live_integration'])

if __name__ == '__main__':
    unittest.main()
