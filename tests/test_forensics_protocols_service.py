"""CORE/CLI wiring for forensics/disk.py and protocols_pcap.py (items 8/10).

Module-level contract tests for inspect_disk_image/inspect_pcap live in
tests/test_forensics_protocols.py. This file only covers the Core service
layer: authorize/pause guard, byte-limit enforcement, side_analyses
persistence, and audit-trail summary-only logging.
"""
import json
import struct
import tempfile
import unittest
from pathlib import Path

from cyber_core.service import Core, CoreError


def _minimal_mbr():
    # 512-byte sector: no partition entries declared, signature at the end.
    # inspect_disk_image treats an all-zero entry (status=kind=first=count=0)
    # as "unused" and skips it, so this is a valid, empty MBR image.
    image = bytearray(512)
    image[510:512] = b'\x55\xaa'
    return bytes(image)


def _minimal_pcap():
    # Classic PCAP 2.4 global header only (little-endian magic), no packets.
    return struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)


class ForensicsProtocolsServiceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.scope = root / 'inputs'
        self.scope.mkdir()
        self.core = Core(root / 'state')
        self.addCleanup(self.core.close)
        self.case = self.core.investigate('p', 'Inventário de imagem de disco e captura', str(self.scope), 'owner', 'auth')

    def test_inspect_disk_image_persists_and_audits_only_summary(self):
        src = self.scope / 'image.raw'
        src.write_bytes(_minimal_mbr())
        result = self.core.inspect_disk_image(self.case, str(src))
        self.assertEqual(result['format'], 'mbr')
        self.assertEqual(result['partitions'], [])
        stored = self.core.side_analyses(self.case, kind='disk_inventory')
        self.assertEqual(len(stored), 1)
        self.assertEqual(stored[0]['data'], result)
        entries = self.core.audit(self.case)
        last = entries[-1]
        self.assertEqual(last['event'], 'disk_image_inspected')
        self.assertNotIn('partitions', json.loads(last['data']))
        self.assertTrue(self.core.verify_audit(self.case))

    def test_inspect_disk_image_rejects_while_paused(self):
        src = self.scope / 'image.raw'
        src.write_bytes(_minimal_mbr())
        self.core.pause(self.case)
        with self.assertRaises(CoreError):
            self.core.inspect_disk_image(self.case, str(src))

    def test_inspect_disk_image_rejects_over_byte_limit(self):
        src = self.scope / 'image.raw'
        src.write_bytes(_minimal_mbr())
        with self.assertRaisesRegex(CoreError, 'byte limit'):
            self.core.inspect_disk_image(self.case, str(src), max_bytes=100)

    def test_inspect_disk_image_wraps_invalid_image_as_core_error(self):
        src = self.scope / 'image.raw'
        src.write_bytes(b'\x00' * 512)
        with self.assertRaisesRegex(CoreError, 'Disk image inventory failed'):
            self.core.inspect_disk_image(self.case, str(src))

    def test_inspect_pcap_persists_and_audits_only_summary(self):
        src = self.scope / 'capture.pcap'
        src.write_bytes(_minimal_pcap())
        result = self.core.inspect_pcap(self.case, str(src))
        self.assertEqual(result['format'], 'pcap_classic')
        self.assertEqual(result['packets'], [])
        stored = self.core.side_analyses(self.case, kind='pcap_inventory')
        self.assertEqual(len(stored), 1)
        self.assertEqual(stored[0]['data'], result)
        entries = self.core.audit(self.case)
        last = entries[-1]
        self.assertEqual(last['event'], 'pcap_inspected')
        self.assertEqual(json.loads(last['data'])['packets'], 0)
        self.assertTrue(self.core.verify_audit(self.case))

    def test_inspect_pcap_rejects_while_paused(self):
        src = self.scope / 'capture.pcap'
        src.write_bytes(_minimal_pcap())
        self.core.pause(self.case)
        with self.assertRaises(CoreError):
            self.core.inspect_pcap(self.case, str(src))

    def test_inspect_pcap_rejects_over_byte_limit(self):
        src = self.scope / 'capture.pcap'
        src.write_bytes(_minimal_pcap())
        with self.assertRaisesRegex(CoreError, 'byte limit'):
            self.core.inspect_pcap(self.case, str(src), max_bytes=10)

    def test_inspect_pcap_wraps_invalid_capture_as_core_error(self):
        src = self.scope / 'capture.pcap'
        src.write_bytes(b'not a pcap file')
        with self.assertRaisesRegex(CoreError, 'PCAP inventory failed'):
            self.core.inspect_pcap(self.case, str(src))


if __name__ == '__main__':
    unittest.main()
