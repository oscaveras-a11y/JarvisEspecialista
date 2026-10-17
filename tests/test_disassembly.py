"""Capstone preview contracts over synthetic byte fixtures, never executed."""
import importlib.util
import os
from pathlib import Path
import struct
import tempfile
import unittest

from cyber_core.firmware import analyze_firmware
from cyber_core.service import Core
from test_binary_structure import elf_fixture, pe_fixture


class DisassemblyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def parse(self, data):
        path = self.root / "input.bin"
        path.write_bytes(data)
        return analyze_firmware(path).get("code_preview", {})

    def backend(self):
        available = importlib.util.find_spec("capstone") is not None
        if os.environ.get("CYBER_REQUIRE_CAPSTONE") == "1":
            self.assertTrue(available, "The reverse-engineering CI job must install real Capstone")
        return available

    def test_optional_dependency_is_explicit_without_breaking_firmware(self):
        preview = self.parse(elf_fixture())
        if self.backend():
            self.assertEqual(preview.get("status"), "decoded")
            self.assertIn("backend_version", preview)
        else:
            self.assertEqual(preview.get("status"), "dependency_unavailable")

    def test_opaque_binary_never_guesses_a_cpu(self):
        preview = self.parse(b"\x90\x90\xc3")
        self.assertEqual(preview.get("status"), "architecture_not_declared")
        self.assertEqual(preview.get("instructions", []), [])

    def test_real_x86_64_decoding_uses_file_backed_entry_bytes(self):
        if not self.backend():
            self.skipTest("Optional Capstone; required by the combined CI job")
        data = elf_fixture()
        data[0x100:0x104] = b"\x90\x90\xc3\x0f"
        out = self.parse(data)
        self.assertEqual([i["mnemonic"] for i in out["instructions"]], ["nop", "nop", "ret"])
        self.assertEqual([i["address"] for i in out["instructions"]], [0x400100, 0x400101, 0x400102])
        self.assertEqual(out["undecoded_bytes"], 1)
        self.assertEqual(out["selection_basis"], "declared_entry_point")
        self.assertIs(out["sample_truncated"], False)

    def test_real_pe_preview_and_bounded_instruction_count(self):
        if not self.backend():
            self.skipTest("Optional Capstone; required by the combined CI job")
        data = pe_fixture()
        data[0x200:0x400] = b"\x90" * 512
        struct.pack_into("<I", data, 88 + 224 + 8, 512)
        out = self.parse(data)
        self.assertEqual(len(out["instructions"]), 128)
        self.assertTrue(out["instruction_limit_reached"])
        self.assertEqual(out["instructions"][0]["address"], 0x401000)
        self.assertEqual(out["source_file_offset"], 512)

    def test_entry_in_zero_fill_memory_is_not_disassembled(self):
        data = elf_fixture()
        struct.pack_into("<Q", data, 24, 0x400108)
        out = self.parse(data)
        self.assertEqual(out.get("status"), "entry_not_file_backed")
        self.assertEqual(out.get("instructions", []), [])

    def test_preview_uses_real_child_and_persisted_copy(self):
        if not self.backend():
            self.skipTest("Optional Capstone; required by the combined CI job")
        inputs = self.root / "inputs"
        inputs.mkdir()
        source = inputs / "sample.elf"
        source.write_bytes(elf_fixture())
        core = Core(self.root / "state")
        self.addCleanup(core.close)
        case = core.investigate("lab", "Disassembly control", inputs, "owner", "synthetic")
        task = core.enqueue(case, source, tool="analyze-firmware")
        result = core.run_one(case, task_id=task)
        out = result["firmware"]["code_preview"]
        self.assertEqual(out["instructions"][0]["mnemonic"], "nop")
        self.assertTrue(result["copy_verified"])
        self.assertEqual(core.results(case)[0]["firmware"]["code_preview"]["backend_version"], out["backend_version"])
        self.assertIn("backend_version", core.report(case).read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
