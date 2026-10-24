"""Only generated laboratory bytes; no proprietary fixture is required."""
import hashlib
from pathlib import Path
import tempfile
import tracemalloc
import unittest

from cyber_core.errors import CoreError
from cyber_core.firmware import analyze_firmware, compare_firmware
from cyber_core.service import Core

MIB = 1024 * 1024

def sparse(path, size, prefix=b'lab'):
    with path.open('wb') as stream:
        stream.write(prefix)
        stream.truncate(size)
    return path

def digest(path):
    result = hashlib.sha256()
    with path.open('rb') as stream:
        while block := stream.read(MIB):
            result.update(block)
    return result.hexdigest()

class LargeInputTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_600_mib_analysis_bounds_python_allocations(self):
        path = sparse(self.root / 'installer.bin', 600 * MIB)
        expected = digest(path)
        tracemalloc.start()
        try:
            result = analyze_firmware(path, max_bytes=1024 * MIB)
            peak = tracemalloc.get_traced_memory()[1]
        finally:
            tracemalloc.stop()
        self.assertEqual(result['size_bytes'], 600 * MIB)
        self.assertEqual(result['sha256'], expected)
        self.assertLess(peak, 16 * MIB, 'Reader allocated whole input in Python heap')
        self.assertEqual(digest(path), expected)
        path.unlink()  # also proves mappings/handles are closed on Windows

    def test_250_mib_pe_keeps_header_validation(self):
        pe = bytearray(224)
        pe[:2] = b'MZ'
        pe[60:64] = (64).to_bytes(4, 'little')
        pe[64:68] = b'PE\0\0'
        pe[68:70] = (0x14c).to_bytes(2, 'little')
        pe[70:72] = (1).to_bytes(2, 'little')
        pe[84:86] = (96).to_bytes(2, 'little')
        pe[88:90] = (0x10b).to_bytes(2, 'little')
        path = sparse(self.root / 'desktop.exe', 250 * MIB, pe)
        result = analyze_firmware(path, max_bytes=1024 * MIB)
        self.assertEqual(result['format'], 'pe')
        self.assertTrue(result['structure_validated'])
        self.assertEqual(result['metadata']['architecture'], 'x86')
        self.assertEqual(result['sha256'], digest(path))

    def test_core_accepts_600_mib_and_persists_verified_result(self):
        path = sparse(self.root / 'lab.bin', 600 * MIB)
        core = Core(self.root / 'state', max_bytes=1024 * MIB, timeout=300)
        self.addCleanup(core.close)
        case = core.investigate('large lab', 'Synthetic capacity', str(self.root), 'owner', 'Synthetic test')
        task = core.enqueue(case, path, tool='analyze-firmware')
        result = core.run_one(case)
        self.assertEqual(result['size'], 600 * MIB)
        self.assertTrue(result['copy_verified'])
        self.assertEqual(result['firmware']['sha256'], digest(path))
        self.assertEqual(core.tasks(case)[0]['status'], 'done')
        self.assertEqual(core.results(case)[0]['task_id'], task)
        self.assertTrue(core.verify_audit(case))

    def test_comparison_skips_equal_chunks_and_closes_inputs(self):
        left = sparse(self.root / 'left', 65 * MIB + 2)
        right = sparse(self.root / 'right', 65 * MIB + 3)
        with right.open('r+b') as stream:
            stream.seek(65 * MIB)
            stream.write(b'xyz')
        result = compare_firmware(left, right, max_bytes=128 * MIB)
        self.assertEqual(result['differing_bytes'], 3)
        self.assertEqual(result['missing_from_first'], 1)
        self.assertEqual(result['changed_ranges'], [{'start': 65 * MIB, 'end_exclusive': 65 * MIB + 3}])
        left.unlink()
        right.unlink()

    def test_custom_limit_and_failure_release_file(self):
        path = sparse(self.root / 'limit', 65 * MIB)
        with self.assertRaises(CoreError):
            analyze_firmware(path)
        with self.assertRaises(CoreError):
            analyze_firmware(path, max_bytes=64 * MIB)
        for invalid in (True, 0, -1, 1024 * MIB + 1):
            with self.subTest(limit=invalid), self.assertRaises(CoreError):
                analyze_firmware(path, max_bytes=invalid)
        path.unlink()

if __name__ == '__main__':
    unittest.main()
