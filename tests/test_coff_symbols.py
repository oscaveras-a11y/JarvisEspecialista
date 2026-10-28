"""Synthetic standard COFF symbol tables; no proprietary inputs."""
import importlib
import struct
import unittest
from cyber_core.errors import CoreError

def fixture(pe=False):
    name = b'?selected@Lab@@YAHH@Z'
    symbols = (struct.pack('<8sIhHBB',b'short',4,1,0x20,2,1) + bytes(18) +
               struct.pack('<8sIhHBB',struct.pack('<II',0,4),8,1,0x20,2,0))
    strings = struct.pack('<I',5+len(name)) + name + b'\0'
    raw = 512 if pe else 60
    pointer = raw+16
    header = struct.pack('<HHIIIHH',0x8664,1,0,pointer,3,240 if pe else 0,0)
    section = struct.pack('<8sIIIIIIHHI',b'.text',16,0x1000 if pe else 0,16,raw,0,0,0,0,0x60000020)
    if pe:
        data = bytearray(128)
        data[:2] = b'MZ'
        struct.pack_into('<I',data,60,128)
        optional = bytearray(240)
        struct.pack_into('<H',optional,0,0x20b)
        struct.pack_into('<I',optional,16,0x1000)
        struct.pack_into('<Q',optional,24,0x140000000)
        data += b'PE\0\0' + header + optional + section
        data += bytes(raw-len(data))
    else:
        data = bytearray(header+section)
    data += bytes(16) + symbols + strings
    return data,pointer

class CoffSymbolsTests(unittest.TestCase):
    def api(self):
        try:
            return importlib.import_module('cyber_core.reverse_engineering.coff')
        except ImportError:
            self.fail('Bounded COFF symbol reader is not implemented')

    def test_auxiliary_records_and_long_names_are_not_confused_with_symbols(self):
        data,_ = fixture()
        result = self.api().read_symbols(data)
        self.assertEqual(result['status'],'completed')
        self.assertEqual(result['record_count'],3)
        self.assertEqual(result['symbol_count'],2)
        self.assertEqual([s['name'] for s in result['symbols']],['short','?selected@Lab@@YAHH@Z'])
        self.assertEqual([s['record_index'] for s in result['symbols']],[0,2])
        self.assertEqual(result['symbols'][1]['section_offset'],8)
        self.assertIsNone(result['symbols'][1]['virtual_address'])
        self.assertEqual(result['symbols'][1]['file_offset'],68)

    def test_pe_addresses_distinguish_section_offset_rva_and_va(self):
        data,_ = fixture(pe=True)
        result = self.api().read_symbols(data)
        symbol = result['symbols'][1]
        self.assertEqual(symbol['section_offset'],8)
        self.assertEqual(symbol['rva'],0x1008)
        self.assertEqual(symbol['virtual_address'],0x140001008)
        self.assertEqual(symbol['file_offset'],520)

    def test_invalid_bounds_indices_auxiliary_counts_and_declared_counts(self):
        valid,ptr = fixture()
        cases = []
        cases.append(valid[:-1])
        bad=bytearray(valid);struct.pack_into('<I',bad,8,len(bad)+1);cases.append(bad)
        bad=bytearray(valid);struct.pack_into('<I',bad,12,100001);cases.append(bad)
        bad=bytearray(valid);bad[ptr+17]=3;cases.append(bad)
        bad=bytearray(valid);struct.pack_into('<h',bad,ptr+12,2);cases.append(bad)
        bad=bytearray(valid);struct.pack_into('<I',bad,ptr+36+4,2);cases.append(bad)
        bad=bytearray(valid);struct.pack_into('<I',bad,ptr+54,0xffffffff);cases.append(bad)
        for data in cases:
            with self.subTest(size=len(data)),self.assertRaises(CoreError):
                self.api().read_symbols(data)

    def test_result_cap_still_validates_unexported_records(self):
        data,ptr=fixture()
        result=self.api().read_symbols(data,max_symbols=1)
        self.assertEqual(result['status'],'partial')
        self.assertTrue(result['symbols_truncated'])
        self.assertEqual(result['symbol_count'],2)
        self.assertEqual(len(result['symbols']),1)
        struct.pack_into('<h',data,ptr+36+12,99)
        with self.assertRaises(CoreError):
            self.api().read_symbols(data,max_symbols=1)

    def test_bigobj_is_explicitly_unsupported_and_budgets_are_validated(self):
        self.assertEqual(self.api().read_symbols(b'\0\0\xff\xff'+bytes(52))['status'],'unsupported_variant')
        data,_=fixture()
        for options in ({'max_symbols':0},{'max_symbols':True},{'max_records':100001},
                        {'max_name_bytes':0},{'max_symbols':1024,'max_name_bytes':4096}):
            with self.subTest(options=options),self.assertRaises(CoreError):
                self.api().read_symbols(data,**options)

if __name__=='__main__':
    unittest.main()
