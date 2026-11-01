import tempfile
import unittest
from hashlib import sha256
from pathlib import Path

from cyber_core.firmware.redundancy import inspect_redundancy


class RedundancyTests(unittest.TestCase):
    def test_repeated_nonuniform_block(self):
        with tempfile.TemporaryDirectory() as directory:
            file=Path(directory)/"firmware.bin"
            block=bytes(range(256))
            file.write_bytes(block + bytes([7])*256 + block)
            report=inspect_redundancy(file,block_size=256)
            self.assertEqual(report["sha256"],sha256(file.read_bytes()).hexdigest())
            self.assertEqual(report["repeated_block_groups"][0]["offsets"],[0,512])
            self.assertFalse(report["recovery_demonstrated"])

    def test_uniform_padding_is_not_backup(self):
        with tempfile.TemporaryDirectory() as directory:
            file=Path(directory)/"firmware.bin"
            file.write_bytes(bytes([255])*1024)
            self.assertEqual(inspect_redundancy(file,block_size=256)["groups_total"],0)

    def test_limits_and_symlinks(self):
        with tempfile.TemporaryDirectory() as directory:
            file=Path(directory)/"firmware.bin"
            file.write_bytes(b"abc")
            with self.assertRaises(ValueError):
                inspect_redundancy(file,max_bytes=2)
            with self.assertRaises(ValueError):
                inspect_redundancy(file,block_size=0)
            link=Path(directory)/"alias.bin"
            link.symlink_to(file)
            with self.assertRaises(ValueError):
                inspect_redundancy(link)
