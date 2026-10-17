"""Exercise public command flows with synthetic files and real storage."""
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
from cyber_core.service import Core
from cyber_core.errors import CoreError

class OperationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.scope = self.root / "scope"
        self.scope.mkdir()
        self.core = Core(self.root / "state")
        self.addCleanup(self.core.close)
        self.case = self.core.investigate("lab", "offline", str(self.scope), "owner", "Synthetic scope")

    def command(self, *args):
        return subprocess.run([sys.executable, "-m", "cyber_core", "--home", str(self.core.home), *args],
                              capture_output=True, text=True, timeout=60)

    def test_pcap_cli_acquires_verified_copy_and_persists_inventory_in_report(self):
        path = self.scope / "empty.pcap"
        path.write_bytes(struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        run = self.command("inventory-pcap", self.case, str(path))
        self.assertEqual(run.returncode, 0, run.stderr)
        result = json.loads(run.stdout)
        self.assertEqual(result["kind"], "pcap_inventory")
        self.assertTrue(result["evidence"]["copy_verified"])
        self.assertIn(result["id"], self.core.report(self.case).read_text())
        self.assertTrue(self.core.verify_audit(self.case))

    def test_disk_cli_is_read_only(self):
        path = self.scope / "image.raw"
        raw = bytearray(1024)
        raw[510:512] = b"\x55\xaa"
        path.write_bytes(raw)
        run = self.command("inventory-disk", self.case, str(path))
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(path.read_bytes(), raw)
        self.assertEqual(json.loads(run.stdout)["kind"], "disk_inventory")

    def test_pause_and_input_bounds_stop_inventory(self):
        from cyber_core.operations import inventory_pcap
        path = self.scope / "empty.pcap"
        path.write_bytes(struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        with self.assertRaises(CoreError):
            inventory_pcap(self.core, self.case, path, max_bytes=-1)
        self.core.pause(self.case)
        with self.assertRaises(CoreError):
            inventory_pcap(self.core, self.case, path)

    def test_persistent_agent_jobs_cli_requires_cloud_opt_in(self):
        path = self.scope / "input"
        path.write_bytes(b"Synthetic bytes")
        task = self.core.enqueue(self.case, path)
        self.core.run_one(self.case, task_id=task)
        run = self.command("agent-jobs", "enqueue", self.case, "--agent", "codex")
        self.assertEqual(run.returncode, 2)
        self.assertIn("approval", run.stderr)
        run = self.command("agent-jobs", "list", self.case)
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(json.loads(run.stdout), [])

if __name__ == "__main__":
    unittest.main()
