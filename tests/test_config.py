import os
import tempfile
import unittest
from pathlib import Path

from cyber_core.config import load_defaults
from cyber_core.service import Core, CoreError


class ConfigTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self._previous = os.environ.get('CYBER_CONFIG')
        self.addCleanup(self._restore)

    def _restore(self):
        if self._previous is None:
            os.environ.pop('CYBER_CONFIG', None)
        else:
            os.environ['CYBER_CONFIG'] = self._previous

    def test_explicit_file_is_loaded_and_overrides_builtin(self):
        config = self.root / 'limits.toml'
        config.write_text('max_bytes = 1024\ntimeout_seconds = 86400\nmax_attempts = 7\n', encoding='utf-8')
        os.environ['CYBER_CONFIG'] = str(config)
        values = load_defaults()
        self.assertEqual(values['max_bytes'], 1024)
        self.assertEqual(values['timeout_seconds'], 86400)
        self.assertEqual(values['max_attempts'], 7)
        # A key absent from the file keeps its built-in default.
        self.assertEqual(values['agent_calls_per_case'], 5)

    def test_invalid_config_value_is_rejected(self):
        config = self.root / 'bad.toml'
        config.write_text('max_attempts = -1\n', encoding='utf-8')
        os.environ['CYBER_CONFIG'] = str(config)
        with self.assertRaises(CoreError):
            load_defaults()

    def test_long_timeout_is_accepted_and_absurd_is_rejected(self):
        # A single authorized task may run for days; a full day must be valid.
        core = Core(self.root / 'state-day', timeout=86400)
        self.addCleanup(core.close)
        self.assertEqual(core.timeout, 86400)
        with self.assertRaises(CoreError):
            Core(self.root / 'state-zero', timeout=0)
        with self.assertRaises(CoreError):
            Core(self.root / 'state-absurd', timeout=Core.MAX_TIMEOUT + 1)

    def test_configured_attempt_limit_reaches_the_core(self):
        core = Core(self.root / 'state-attempts', max_attempts=1, agent_calls_per_case=2)
        self.addCleanup(core.close)
        self.assertEqual(core.max_attempts, 1)
        self.assertEqual(core.agent_calls_per_case, 2)


if __name__ == '__main__':
    unittest.main()
