"""Real Sleuth Kit (mmls/fls/icat/fsstat) integration for section 8. Real CLIs run only in Actions."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from cyber_core.errors import CoreError
from cyber_core.forensics.sleuthkit_child import normalize_mmls, normalize_fls
from cyber_core.service import Core


class NormalizeContracts(unittest.TestCase):
    """Regression fixtures captured verbatim from real `mmls`/`fls -l -a` output
    (The Sleuth Kit 4.12.1) against a real OpenWrt firmware image and a
    synthetic FAT image with a deleted file, so parsing stays correct even
    when the real binaries aren't installed in this test environment."""

    def test_real_mmls_dos_partition_table_sample(self):
        sample = (
            b"DOS Partition Table\n"
            b"Offset Sector: 0\n"
            b"Units are in 512-byte sectors\n\n"
            b"      Slot      Start        End          Length       Description\n"
            b"000:  Meta      0000000000   0000000000   0000000001   Primary Table (#0)\n"
            b"001:  -------   0000000000   0000000511   0000000512   Unallocated\n"
            b"002:  000:000   0000000512   0000033279   0000032768   Linux (0x83)\n"
            b"003:  -------   0000033280   0000033791   0000000512   Unallocated\n"
            b"004:  000:001   0000033792   0000246783   0000212992   Linux (0x83)\n")
        result = normalize_mmls(sample)
        self.assertEqual(result["partitions_total"], 4)
        self.assertFalse(result["truncated"])
        allocated = [p for p in result["partitions"] if p["allocated"]]
        self.assertEqual([p["start_sector"] for p in allocated], [512, 33792])
        self.assertEqual(allocated[0]["description"], "Linux (0x83)")

    def test_mmls_with_no_recognized_rows_is_rejected(self):
        with self.assertRaises(CoreError):
            normalize_mmls(b"not a partition table\n")

    def test_real_fls_sample_with_a_deleted_fat_entry(self):
        sample = (
            b"r/r 3:\tTEST        (Volume Label Entry)\t2026-11-02 03:23:46 (UTC)\t"
            b"2026-11-02 00:00:00 (UTC)\t0000-00-00 00:00:00 (UTC)\t2026-11-02 03:23:46 (UTC)\t0\t0\t0\n"
            b"r/r * 4:\t_eleteme.txt\t2026-11-02 03:23:46 (UTC)\t2026-11-02 00:00:00 (UTC)\t"
            b"0000-00-00 00:00:00 (UTC)\t2026-11-02 03:23:46 (UTC)\t15\t0\t0\n"
            b"r/r 5:\tkeepme.txt\t2026-11-02 03:23:46 (UTC)\t2026-11-02 00:00:00 (UTC)\t"
            b"0000-00-00 00:00:00 (UTC)\t2026-11-02 03:23:46 (UTC)\t7\t0\t0\n")
        result = normalize_fls(sample)
        self.assertEqual(result["entries_total"], 3)
        deleted = [e for e in result["entries"] if e["deleted"]]
        self.assertEqual(len(deleted), 1)
        self.assertEqual(deleted[0]["inode"], "4")
        self.assertEqual(deleted[0]["size"], 15)
        kept = next(e for e in result["entries"] if e["name"] == "keepme.txt")
        self.assertFalse(kept["deleted"])

    def test_fls_lines_that_do_not_match_are_skipped_not_fatal(self):
        result = normalize_fls(b"garbage line with no structure\n\n")
        self.assertEqual(result, {"entries": [], "entries_total": 0, "truncated": False})


def _mbr_image(root):
    import struct
    path = root / "disk.img"
    image = bytearray(100 * 512)
    image[510:512] = b"\x55\xaa"
    struct.pack_into("<BBB", image, 446, 0, 0, 0)
    image[446 + 4] = 0x83
    struct.pack_into("<II", image, 446 + 8, 2, 90)
    path.write_bytes(image)
    return path


def _fat_image_with_deleted_file(root):
    path = root / "fat.img"
    with path.open("wb") as fh:
        fh.truncate(16 * 1024 * 1024)
    subprocess.run(["mkfs.vfat", "-n", "TEST", str(path)], check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    keep = root / "keepme.txt"
    keep.write_text("keepme\n")
    gone = root / "deleteme.txt"
    gone.write_text("secret content\n")
    subprocess.run(["mcopy", "-i", str(path), str(gone), "::deleteme.txt"], check=True)
    subprocess.run(["mcopy", "-i", str(path), str(keep), "::keepme.txt"], check=True)
    subprocess.run(["mdel", "-i", str(path), "::deleteme.txt"], check=True)
    return path


@unittest.skipUnless(os.environ.get("CYBER_REQUIRE_EXTERNAL_TOOLS") == "1",
                     "Real Sleuth Kit integration executes in its dedicated Linux Actions workflow")
class RealSleuthKitTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.scope = self.root / "scope"
        self.scope.mkdir()
        self.core = Core(self.root / "state", timeout=120)
        self.addCleanup(self.core.close)
        self.case = self.core.investigate("synthetic", "Sleuth Kit", str(self.scope),
                                          "owner", "Synthetic fixtures only")

    def test_tools_are_available(self):
        from cyber_core.external_tools import tool_inventory
        inventory = tool_inventory()
        for tool in ("mmls", "fls", "icat", "fsstat"):
            self.assertTrue(inventory[tool]["available"], inventory[tool])

    def test_mmls_identifies_a_real_synthetic_mbr_partition_table(self):
        from cyber_core.forensics.sleuthkit import list_partitions
        source = shutil.copy(_mbr_image(self.root), self.scope / "disk.img")
        result = list_partitions(self.core, self.case, source)
        analysis = result["analysis"]
        self.assertEqual(analysis["backend"], "mmls")
        allocated = [p for p in analysis["partitions"] if p["allocated"]]
        self.assertEqual(len(allocated), 1)
        self.assertEqual(allocated[0]["start_sector"], 2)
        self.assertTrue(self.core.verify_audit(self.case))

    def test_fls_lists_and_icat_recovers_a_real_deleted_file(self):
        from cyber_core.forensics.sleuthkit import list_filesystem_entries, recover_file
        source = shutil.copy(_fat_image_with_deleted_file(self.root), self.scope / "fat.img")
        listed = list_filesystem_entries(self.core, self.case, source, partition_offset_sectors=0)
        analysis = listed["analysis"]
        self.assertEqual(analysis["backend"], "fls")
        deleted = [e for e in analysis["entries"] if e["deleted"]]
        self.assertEqual(len(deleted), 1)
        self.assertIn("eleteme.txt", deleted[0]["name"])

        recovered = recover_file(self.core, self.case, source, partition_offset_sectors=0,
                                 inode=deleted[0]["inode"])
        analysis = recovered["analysis"]
        self.assertEqual(analysis["backend"], "icat")
        content = Path(analysis["output"]).read_bytes()
        self.assertEqual(content, b"secret content\n")
        self.assertTrue(self.core.verify_audit(self.case))
        report = self.core.report(self.case).read_text(encoding="utf-8")
        self.assertNotIn("secret content", report)

    def test_unknown_inode_is_rejected_before_any_tool_runs(self):
        from cyber_core.forensics.sleuthkit import recover_file
        source = shutil.copy(_fat_image_with_deleted_file(self.root), self.scope / "fat.img")
        with self.assertRaises(CoreError):
            recover_file(self.core, self.case, source, partition_offset_sectors=0, inode="not-an-inode")


if __name__ == "__main__":
    unittest.main()
