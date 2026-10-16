import tempfile
import unittest
from pathlib import Path

from cyber_core.errors import CoreError
from cyber_core.firmware import analyze_firmware, compare_firmware


def ihex(address, kind, data=b''):
    body = bytes([len(data)]) + address.to_bytes(2, 'big') + bytes([kind]) + data
    return ':' + (body + bytes([-sum(body) & 255])).hex().upper() + '\n'


def srec(kind, address, data=b''):
    widths = {0: 2, 1: 2, 2: 3, 3: 4, 5: 2, 6: 3, 7: 4, 8: 3, 9: 2}
    body = bytes([widths[kind] + len(data) + 1]) + address.to_bytes(widths[kind], 'big') + data
    return 'S' + str(kind) + (body + bytes([255 - (sum(body) & 255)])).hex().upper() + '\n'


class FirmwareTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def write(self, name, data):
        path = self.root / name
        path.write_bytes(data.encode() if isinstance(data, str) else data)
        return path

    def test_raw_and_limits(self):
        p = self.write('x.bin', b'abc')
        self.assertEqual(analyze_firmware(p)['format'], 'bin')
        for options in ({'max_bytes': 2}, {'max_bytes': 0}, {'max_records': 0}):
            with self.assertRaises(CoreError): analyze_firmware(p, **options)
        with self.assertRaises(CoreError): analyze_firmware(self.write('empty', b''))

    def test_hex_sparse_and_compare(self):
        a = self.write('a.hex', ihex(0, 0, b'ab') + ihex(0, 4, b'\xff\xff') + ihex(65535, 0, b'z') + ihex(0, 1))
        b = self.write('b.hex', ihex(0, 0, b'acd') + ihex(0, 1))
        self.assertEqual(analyze_firmware(a)['data_bytes'], 3)
        diff = compare_firmware(a, b)
        self.assertEqual(diff['differing_bytes'], 3)
        self.assertEqual(diff['missing_from_first'], 1)
        self.assertEqual(diff['missing_from_second'], 1)

    def test_hex_invalid(self):
        valid = ihex(0, 0, b'a')
        cases = [valid, valid + valid + ihex(0, 1), valid + ihex(0, 0, b'b') + ihex(0, 1), valid + ihex(0, 1) + valid, ':010000006100\n' + ihex(0, 1), ':abcd', ihex(65535, 0, b'ab') + ihex(0, 1)]
        for i, data in enumerate(cases):
            with self.subTest(i=i), self.assertRaises(CoreError): analyze_firmware(self.write(str(i), data))
        with self.assertRaises(CoreError): analyze_firmware(self.write('limit', valid + ihex(0, 1)), max_records=1)

    def test_srecords(self):
        for data_kind, end_kind in ((1, 9), (2, 8), (3, 7)):
            data = srec(0, 0, b'name') + srec(data_kind, 5, b'abc') + srec(5, 1) + srec(end_kind, 5)
            self.assertEqual(analyze_firmware(self.write('x.srec', data))['data_bytes'], 3)
        for data in (srec(1, 0, b'a'), srec(1, 0, b'a') + srec(8, 0), srec(1, 0, b'a') + srec(5, 2) + srec(9, 0), 'S10400006100\n', srec(1, 0, b'a') * 2 + srec(9, 0)):
            with self.assertRaises(CoreError): analyze_firmware(self.write('bad', data))

    def test_structured_headers(self):
        elf = bytearray(64)
        elf[:7] = b'\x7fELF\x02\x01\x01'
        elf[18:20] = (62).to_bytes(2, 'little')
        elf[20:24] = (1).to_bytes(4, 'little')
        elf[52:54] = (64).to_bytes(2, 'little')
        result = analyze_firmware(self.write('a.elf', elf))
        self.assertEqual(result['metadata']['machine'], 62)
        with self.assertRaises(CoreError): analyze_firmware(self.write('short', b'\x7fELF'))
        with self.assertRaises(CoreError): analyze_firmware(self.write('shortpe', b'MZ'))

    def test_unchanged(self):
        p = self.write('x', b'firmware version 1')
        self.assertEqual(compare_firmware(p, p)['differing_bytes'], 0)
        q = self.write('y', b'firmware version 2')
        self.assertEqual(compare_firmware(p, q)['differing_bytes'], 1)

    def test_segment_mode_and_cross_format(self):
        h = self.write('x.hex', ihex(0, 2, b'\x12\x34') + ihex(5, 0, b'a') + ihex(0, 3, b'\x12\x34\x00\x05') + ihex(0, 1))
        s = self.write('x.s28', srec(2, 0x12345, b'a') + srec(8, 0x12345))
        self.assertEqual(analyze_firmware(h)['metadata']['entry_point'], 0x12345)
        self.assertEqual(compare_firmware(h, s)['differing_bytes'], 0)
        with self.assertRaises(CoreError): compare_firmware(h, self.write('x.bin', b'a'))

    def test_elf_big_endian_and_table_bounds(self):
        elf = bytearray(52)
        elf[:7] = b'\x7fELF\x01\x02\x01'
        elf[18:20] = (40).to_bytes(2, 'big')
        elf[20:24] = (1).to_bytes(4, 'big')
        elf[40:42] = (52).to_bytes(2, 'big')
        self.assertEqual(analyze_firmware(self.write('be', elf))['metadata']['endian'], 'big')
        elf[28:32] = (52).to_bytes(4, 'big')
        elf[42:44] = (32).to_bytes(2, 'big')
        elf[44:46] = (1).to_bytes(2, 'big')
        with self.assertRaises(CoreError): analyze_firmware(self.write('badtable', elf))

    def test_pe_header_and_section_bounds(self):
        pe = bytearray(224)
        pe[:2] = b'MZ'
        pe[60:64] = (64).to_bytes(4, 'little')
        pe[64:68] = b'PE\0\0'
        pe[68:70] = (0x14c).to_bytes(2, 'little')
        pe[70:72] = (1).to_bytes(2, 'little')
        pe[84:86] = (96).to_bytes(2, 'little')
        pe[88:90] = (0x10b).to_bytes(2, 'little')
        result = analyze_firmware(self.write('validpe', pe))
        self.assertEqual(result['format'], 'pe')
        pe[200:204] = (1000).to_bytes(4, 'little')
        with self.assertRaises(CoreError): analyze_firmware(self.write('badpe', pe))

    def test_decoded_byte_limit(self):
        for name, content in (
            ('x.hex', ihex(0, 0, b'abcde') + ihex(0, 1)),
            ('x.s19', srec(1, 0, b'abcde') + srec(9, 0)),
        ):
            p = self.write(name, content)
            with self.subTest(name=name):
                with self.assertRaises(CoreError):
                    analyze_firmware(p, max_decoded_bytes=4)
                with self.assertRaises(CoreError):
                    compare_firmware(p, p, max_decoded_bytes=4)
                self.assertEqual(analyze_firmware(p, max_decoded_bytes=5)['data_bytes'], 5)
        p = self.write('raw', b'abcde')
        self.assertEqual(analyze_firmware(p, max_decoded_bytes=4)['data_bytes'], 5)
        for cap in (0, -1, True, 1048577):
            with self.assertRaises(CoreError):
                analyze_firmware(p, max_decoded_bytes=cap)

    def test_range_limit(self):
        left = self.write('a', bytes(2002))
        right = self.write('b', bytes([1, 0]) * 1001)
        result = compare_firmware(left, right)
        self.assertEqual(result['differing_bytes'], 1001)
        self.assertEqual(result['changed_ranges_total'], 1001)
        self.assertEqual(len(result['changed_ranges']), 1000)
        self.assertTrue(result['ranges_truncated'])


if __name__ == '__main__': unittest.main()
