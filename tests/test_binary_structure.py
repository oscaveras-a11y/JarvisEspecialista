"""Synthetic structural fixtures; they are parsed as bytes and never executed."""
import json
from pathlib import Path
import struct
import tempfile
import unittest
import zlib

from cyber_core.errors import CoreError
from cyber_core.firmware import analyze_firmware
from cyber_core.service import Core


def elf_fixture(bits=64, endian="little", machine=None):
    order = "<" if endian == "little" else ">"
    header = 64 if bits == 64 else 52
    phsize, shsize = (56, 64) if bits == 64 else (32, 40)
    data = bytearray(0x300)
    data[:7] = b"\x7fELF" + bytes((2 if bits == 64 else 1, 1 if endian == "little" else 2, 1))
    machine = (62 if bits == 64 else 40) if machine is None else machine
    struct.pack_into(order + ("HHIQQQIHHHHHH" if bits == 64 else "HHIIIIIHHHHHH"),
                     data, 16, 2, machine, 1, 0x400100, header, 0x180, 0,
                     header, phsize, 1, shsize, 4, 3)
    ph = ((1, 5, 0x100, 0x400100, 0, 4, 20, 0x100) if bits == 64 else
          (1, 0x100, 0x400100, 0, 4, 20, 5, 0x100))
    struct.pack_into(order + ("IIQQQQQQ" if bits == 64 else "IIIIIIII"), data, header, *ph)
    data[0x100:0x104] = b"\x90\x90\xc3\x00"
    names = b"\0.text\0.bss\0.shstrtab\0"
    data[0x120:0x120 + len(names)] = names
    records = (
        (0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
        (1, 1, 6, 0x400100, 0x100, 4, 0, 0, 16, 0),
        (7, 8, 3, 0x400104, 0x4000, 16, 0, 0, 4, 0),
        (12, 3, 0, 0, 0x120, len(names), 0, 0, 1, 0),
    )
    for index, record in enumerate(records):
        struct.pack_into(order + ("IIQQQQIIQQ" if bits == 64 else "IIIIIIIIII"),
                         data, 0x180 + index * shsize, *record)
    return data


def pe_fixture(bits=32):
    data = bytearray(0x600)
    optional_size = 224 if bits == 32 else 240
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 60, 64)
    data[64:68] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", data, 68, 0x14c if bits == 32 else 0x8664,
                     2, 0, 0, 0, optional_size, 0x2002)
    struct.pack_into("<H", data, 88, 0x10b if bits == 32 else 0x20b)
    struct.pack_into("<I", data, 104, 0x1000)
    struct.pack_into("<I" if bits == 32 else "<Q", data, 116 if bits == 32 else 112,
                     0x400000 if bits == 32 else 0x140000000)
    struct.pack_into("<II", data, 120, 0x1000, 0x200)
    struct.pack_into("<II", data, 144, 0x3000, 0x200)
    struct.pack_into("<H", data, 156, 3)
    struct.pack_into("<I", data, 180 if bits == 32 else 196, 16)
    table = 88 + optional_size
    struct.pack_into("<8sIIIIIIHHI", data, table, b".text\0\0\0",
                     4, 0x1000, 0x200, 0x200, 0, 0, 0, 0, 0x60000020)
    struct.pack_into("<8sIIIIIIHHI", data, table + 40, b".bss\0\0\0\0",
                     32, 0x2000, 0, 0, 0, 0, 0, 0, 0xc0000080)
    data[0x200:0x204] = b"\x90\x90\xc3\x00"
    return data


class BinaryStructureTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def parse(self, data):
        path = self.root / "sample.bin"
        path.write_bytes(data)
        return analyze_firmware(path)["metadata"]

    def test_elf_sections_segments_and_zero_fill_are_distinct(self):
        meta = self.parse(elf_fixture())
        self.assertEqual(meta.get("architecture"), "x86_64")
        self.assertEqual(meta.get("section_count"), 4)
        self.assertEqual(meta.get("program_header_count"), 1)
        sections = meta.get("section_headers", [])
        self.assertEqual([s["name"] for s in sections], ["", ".text", ".bss", ".shstrtab"])
        text, bss = sections[1:3]
        self.assertEqual((text["file_offset"], text["file_size"], text["virtual_address"]), (256, 4, 0x400100))
        self.assertTrue(text["executable"])
        self.assertEqual((bss["file_size"], bss["memory_size"]), (0, 16))
        self.assertEqual(meta["segments"][0]["zero_fill_bytes"], 16)

    def test_elf_32_big_endian_uses_its_own_field_order(self):
        meta = self.parse(elf_fixture(32, "big"))
        self.assertEqual(meta.get("architecture"), "arm")
        self.assertEqual(meta.get("section_headers", [{}, {}])[1].get("name"), ".text")
        self.assertEqual(meta.get("segments", [{}])[0].get("file_size"), 4)
        self.assertEqual(meta["entry_point"], 0x400100)

    def test_unknown_machine_is_preserved_without_guessing(self):
        meta = self.parse(elf_fixture(machine=0xfefe))
        self.assertEqual(meta["machine"], 0xfefe)
        self.assertEqual(meta.get("architecture"), "unknown")

    def test_elf_section_payload_outside_file_is_rejected(self):
        data = elf_fixture()
        struct.pack_into("<Q", data, 0x180 + 64 + 32, 0x10000)
        with self.assertRaises(CoreError):
            self.parse(data)

    def test_elf_segment_cannot_claim_more_file_bytes_than_memory(self):
        data = elf_fixture()
        struct.pack_into("<Q", data, 64 + 40, 3)
        with self.assertRaises(CoreError):
            self.parse(data)

    def test_elf_invalid_string_reference_is_rejected(self):
        data = elf_fixture()
        struct.pack_into("<I", data, 0x180 + 64, 1000)
        with self.assertRaises(CoreError):
            self.parse(data)

    def test_elf_bad_alignment_and_address_wrap_are_rejected(self):
        for offset, value in ((64 + 48, 3), (0x180 + 2 * 64 + 16, 0xfffffffffffffff8)):
            with self.subTest(offset=offset):
                data = elf_fixture()
                struct.pack_into("<Q", data, offset, value)
                with self.assertRaises(CoreError):
                    self.parse(data)

    def test_pe_32_and_64_report_sections_and_declared_addresses(self):
        for bits, arch, base in ((32, "x86", 0x400000), (64, "x86_64", 0x140000000)):
            with self.subTest(bits=bits):
                meta = self.parse(pe_fixture(bits))
                self.assertEqual(meta.get("architecture"), arch)
                self.assertEqual(meta.get("image_base"), base)
                self.assertEqual(meta.get("entry_point_rva"), 0x1000)
                self.assertTrue(meta.get("is_dll"))
                text, bss = meta.get("section_headers", [{}, {}])
                self.assertEqual(text.get("name"), ".text")
                self.assertEqual((text.get("file_offset"), text.get("file_size")), (512, 512))
                self.assertEqual(text.get("virtual_address"), base + 0x1000)
                self.assertTrue(text.get("executable"))
                self.assertEqual((bss.get("file_size"), bss.get("memory_size")), (0, 32))

    def test_pe_address_wrap_is_rejected(self):
        data = pe_fixture()
        struct.pack_into("<I", data, 88 + 224 + 40 + 12, 0xfffffff0)
        with self.assertRaises(CoreError):
            self.parse(data)

    def test_table_resource_limit_rejects_before_large_response(self):
        data = bytearray(64 + 513 * 64)
        data[:7] = b"\x7fELF\x02\x01\x01"
        struct.pack_into("<HHIQQQIHHHHHH", data, 16, 2, 62, 1, 0, 0, 64, 0,
                         64, 0, 0, 64, 513, 0)
        with self.assertRaises(CoreError):
            self.parse(data)

    def test_structure_survives_real_child_persistence_and_report(self):
        inputs = self.root / "inputs"
        inputs.mkdir()
        source = inputs / "control.elf"
        original = bytes(elf_fixture())
        source.write_bytes(original)
        core = Core(self.root / "state")
        self.addCleanup(core.close)
        case = core.investigate("lab", "Structure control", inputs, "owner", "synthetic test")
        task = core.enqueue(case, source, tool="analyze-firmware")
        result = core.run_one(case, task_id=task)
        self.assertEqual(result["firmware"]["metadata"].get("architecture"), "x86_64")
        self.assertEqual(source.read_bytes(), original)
        self.assertTrue(result["copy_verified"])
        self.assertIn(".shstrtab", Path(core.report(case)).read_text(encoding="utf-8"))
        self.assertEqual(core.results(case)[0]["firmware"]["metadata"]["section_count"], 4)


    def test_dll_with_zero_entry_rva_has_no_entry_point(self):
        data = pe_fixture()
        struct.pack_into("<I", data, 104, 0)
        meta = self.parse(data)
        self.assertIsNone(meta.get("entry_point"))
        self.assertIs(meta.get("has_entry_point"), False)
        self.assertEqual(meta["entry_point_rva"], 0)

    def test_compressed_elf_uses_physical_size_without_entry_modulo(self):
        data = elf_fixture()
        payload = struct.pack("<IIQQ", 1, 0, 8, 8) + zlib.compress(bytes(8))
        data[0x280:0x280 + len(payload)] = payload
        struct.pack_into("<IIQQQQIIQQ", data, 0x180 + 64,
                         1, 1, 0x800, 0, 0x280, len(payload), 0, 0, 1, 8)
        meta = self.parse(data)
        section = meta["section_headers"][1]
        self.assertTrue(section.get("compressed"))
        self.assertEqual(section["file_size"], len(payload))
        self.assertEqual(section["memory_size"], 0)


if __name__ == "__main__":
    unittest.main()
