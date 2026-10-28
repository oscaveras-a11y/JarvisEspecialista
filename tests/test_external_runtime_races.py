"""Deterministic filesystem interleaving in the scratch-budget monitor."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from cyber_core.errors import CoreError
from cyber_core.external_tool_runtime import scratch_limit

class ScratchMonitorTests(unittest.TestCase):
    def test_tool_removing_a_checked_temporary_file_is_not_a_failure(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            temporary = root / 'ephemeral'
            temporary.write_bytes(b'bounded temporary data')
            is_file = Path.is_file
            def remove_after_check(path):
                found = is_file(path)
                if path == temporary and found:
                    path.unlink()
                return found
            # Force a real unlink precisely between the existing monitor's
            # is_file() and stat(). Assert the monitor result, not mock calls.
            with patch.object(Path, 'is_file', remove_after_check):
                scratch_limit(root)

    def test_oversized_file_is_still_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            with (root / 'oversized').open('wb') as stream:
                stream.truncate(32 * 1024 * 1024 + 1)
            with self.assertRaises(CoreError):
                scratch_limit(root)

    def test_excessive_entries_are_still_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            for index in range(1025):
                (root / str(index)).mkdir()
            with self.assertRaises(CoreError):
                scratch_limit(root)

if __name__ == '__main__':
    unittest.main()
