"""Strict CLI framing and bounded synthetic subprocesses, no provider calls."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
from cyber_core.errors import CoreError
from cyber_core.agents import runner

class AdapterContracts(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
    def test_codex_rejects_nonobject_event_as_operational_error(self):
        with patch.object(runner, 'run_bounded', return_value={'stdout': '[]\n'}):
            with self.assertRaises(CoreError):
                runner.CodexAdapter(executable=sys.executable).review({}, self.root)
    def test_codex_rejects_failed_turn_even_after_message(self):
        events = [{'type': 'item.completed', 'item': {'type': 'agent_message', 'text': 'proposal'}},
                  {'type': 'turn.failed', 'error': {'message': 'private message'}},
                  {'type': 'turn.completed', 'usage': {}}]
        with patch.object(runner, 'run_bounded', return_value={'stdout': '\n'.join(map(json.dumps, events))}):
            with self.assertRaises(CoreError):
                runner.CodexAdapter(executable=sys.executable).review({}, self.root)
    def test_codex_accepts_completed_message_and_normalizes_usage(self):
        events = [{'type': 'thread.started', 'thread_id': 'synthetic'},
                  {'type': 'item.completed', 'item': {'id': 'item_1', 'type': 'agent_message', 'text': 'proposal'}},
                  {'type': 'turn.completed', 'usage': {'input_tokens': 12, 'cached_input_tokens': 0, 'output_tokens': 4}}]
        with patch.object(runner, 'run_bounded', return_value={'stdout': '\n'.join(map(json.dumps, events))}):
            out = runner.CodexAdapter(executable=sys.executable).review({}, self.root)
        self.assertEqual(out['review'], 'proposal')
        self.assertFalse(out['independent_validation'])
        self.assertEqual(out['usage']['input_tokens'], 12)
    def test_claude_real_adapter_parses_success_without_contacting_provider(self):
        result = {'type': 'result', 'subtype': 'success', 'is_error': False,
                  'duration_ms': 10, 'duration_api_ms': 8, 'num_turns': 1,
                  'result': 'independent proposal', 'session_id': 'synthetic',
                  'total_cost_usd': .001, 'usage': {'input_tokens': 10, 'output_tokens': 3}}
        with patch.object(runner, 'run_bounded', return_value={'stdout': json.dumps(result)}):
            out = runner.ClaudeAdapter(executable=sys.executable).review({}, self.root)
        self.assertEqual(out['agent'], 'claude')
        self.assertEqual(out['review'], 'independent proposal')
        self.assertFalse(out['independent_validation'])
    def test_claude_rejects_errors_incomplete_and_wrong_shapes(self):
        fixtures = [[], {'type': 'result', 'subtype': 'error_max_turns', 'is_error': True},
                    {'type': 'result', 'subtype': 'success', 'is_error': False, 'result': ''},
                    {'type': 'assistant', 'message': 'unfinished'}]
        for result in fixtures:
            with self.subTest(result=result):
                with patch.object(runner, 'run_bounded', return_value={'stdout': json.dumps(result)}):
                    with self.assertRaises(CoreError):
                        runner.ClaudeAdapter(executable=sys.executable).review({}, self.root)
    def test_executable_override_does_not_allow_shell_script(self):
        path = self.root / 'claude.cmd'
        path.write_text('@echo off\n')
        with self.assertRaises(CoreError):
            runner.ClaudeAdapter(executable=str(path)).check_available()
    def test_env_configuration_finds_explicit_native_executable(self):
        with patch.dict('os.environ', {'CYBER_CLAUDE_EXECUTABLE': sys.executable}):
            self.assertEqual(Path(runner.ClaudeAdapter().executable), Path(sys.executable))
    def test_process_cancellation_stops_waiting_without_timeout(self):
        script = self.root / 'wait.py'
        script.write_text('import time\ntime.sleep(30)\n')
        with self.assertRaisesRegex(CoreError, 'stopped'):
            runner.run_bounded([sys.executable, str(script)], '', cwd=self.root, timeout=10,
                               should_stop=lambda: 'cancelled')
    def test_stdout_and_stderr_share_one_output_budget(self):
        script = self.root / 'output.py'
        script.write_text('import sys\nsys.stdout.write("x"*80)\nsys.stderr.write("y"*80)\n')
        with self.assertRaisesRegex(CoreError, 'output'):
            runner.run_bounded([sys.executable, str(script)], '', cwd=self.root, timeout=5, max_output=100)
    def test_nonfinite_timeout_is_rejected(self):
        with self.assertRaises(CoreError):
            runner.run_bounded([sys.executable], '', cwd=self.root, timeout=float('nan'))

if __name__ == '__main__':
    unittest.main()
