"""Synthetic static crypto contracts; specimens are never executed."""
import importlib
import json
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest
import zlib

AES=bytes.fromhex('637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0b7fd9326363ff7cc34a5e5f171d83115304c723c31896059a071280e2eb27b27509832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cfd0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2cd0c13ec5f974417c4a77e3d645d197360814fdc22a908846eeb814de5e0bdb e0323a0a4906245cc2d3ac629195e479 e7c8376d8dd54ea96c56f4ea657aae08 ba78252e1ca6b4c6e8dd741f4bbd8b8a 703eb5664803f60e613557b986c11d9e e1f8981169d98e949b1e87e9ce5528df 8ca1890dbfe6426841992d0fb054bb16')
CHACHA=b'expand 32-byte k'
def ihex(payload):
    lines=[]
    for at in range(0,len(payload),16):
        body=bytes([len(payload[at:at+16])])+at.to_bytes(2,'big')+b'\0'+payload[at:at+16]
        lines.append(':'+ (body+bytes([-sum(body)&255])).hex())
    return ('\n'.join(lines)+'\n:00000001ff\n').encode()
def srecord(payload):
    lines=[]
    for at in range(0,len(payload),16):
        body=bytes([len(payload[at:at+16])+3])+at.to_bytes(2,'big')+payload[at:at+16]
        lines.append('S1'+(body+bytes([255-(sum(body)&255)])).hex())
    return ('\n'.join(lines)+'\nS9030000fc\n').encode()

def pe(payload, dll=False):
    data=bytearray(512)
    data[:2]=b'MZ';struct.pack_into('<I',data,60,128)
    data[128:132]=b'PE\0\0'
    struct.pack_into('<HHIIIHH',data,132,0x8664,1,0,0,0,240,0x2000 if dll else 2)
    struct.pack_into('<H',data,152,0x20b)
    struct.pack_into('<Q',data,176,0x140000000)
    struct.pack_into('<I',data,260,16)
    struct.pack_into('<8sIIIIIIHHI',data,392,b'.rdata',len(payload),0x1000,len(payload),512,0,0,0,0,0x40000040)
    return bytes(data)+payload

class CryptoInspectTests(unittest.TestCase):
    def api(self):
        try:
            return importlib.import_module('cyber_core.reverse_engineering.crypto_inspect')
        except ImportError:
            self.fail('crypto-inspect static adapter is not implemented')
    def scan(self, data, **options):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'synthetic.bin';path.write_bytes(data)
            return self.api().inspect_file(path,**options)
    def test_full_aes_constant_and_weak_name_have_distinct_evidence(self):
        result=self.scan(b'private-secret-do-not-export\0AES-256\0'+AES)
        self.assertEqual(result['format'],'bin')
        constant=next(f for f in result['findings'] if f['kind']=='constant')
        weak=next(f for f in result['findings'] if f['kind']=='technical_string')
        self.assertEqual(constant['rule'],'aes.sbox.v1')
        self.assertEqual(constant['offset'],37)
        self.assertEqual(weak['strength'],'weak')
        self.assertNotIn('private-secret',json.dumps(result))
        self.assertIsNone(constant['virtual_address'])
    def test_incomplete_and_compressed_bytes_do_not_become_aes(self):
        for data in [AES[:128], zlib.compress(AES), b'random negative without crypto']:
            result=self.scan(data)
            self.assertFalse(any(f['kind']=='constant' and f['family']=='AES' for f in result['findings']))
    def test_pe_exe_and_dll_preserve_offsets_and_validated_va(self):
        for dll in (False,True):
            result=self.scan(pe(AES,dll))
            finding=next(f for f in result['findings'] if f['kind']=='constant')
            self.assertEqual(result['format'],'pe')
            self.assertEqual(finding['offset'],512)
            self.assertEqual(finding['virtual_address'],0x140001000)
    def test_hex_and_srecord_decode_without_filling_gaps(self):
        for maker,fmt in [(ihex,'intel_hex'),(srecord,'srecord')]:
            result=self.scan(maker(AES))
            finding=next(f for f in result['findings'] if f['kind']=='constant')
            self.assertEqual(result['format'],fmt)
            self.assertEqual(finding['decoded_address'],0)
            self.assertIsNone(finding['offset'])
            self.assertEqual(finding['source_record_offset'],0)
            broken=bytearray(maker(AES));broken[10]=ord('f') if broken[10]!=ord('f') else ord('0')
            with self.assertRaises(Exception):self.scan(bytes(broken))
    def test_chunk_overlap_and_explicit_caps(self):
        result=self.scan(bytes(65530)+AES+CHACHA*300,max_findings=3)
        self.assertTrue(result['findings_truncated'])
        self.assertLessEqual(len(result['findings']),3)
        self.assertEqual(result['status'],'partial')
        self.assertEqual(next(f for f in result['findings'] if f['rule']=='aes.sbox.v1')['offset'],65530)
        self.assertLessEqual(len(self.api().encode_result(result,4096).encode())+1,4096)
    def test_malformed_structures_and_invalid_limits_fail_closed(self):
        for data in [b'MZ'+bytes(100),b'\x7fELF'+bytes(100)]:
            with self.assertRaises(Exception):self.scan(data)
        for limits in [dict(max_findings=257),dict(max_findings=True),dict(seconds=301),dict(max_bytes=1073741825)]:
            with self.assertRaises(Exception):self.scan(AES,**limits)
    def test_core_verified_acquisition_audit_and_pause(self):
        from cyber_core.service import Core
        from cyber_core.operations import saved_operations
        from cyber_core.errors import CoreError
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);scope=root/'scope';scope.mkdir()
            path=scope/'specimen.bin';path.write_bytes(AES)
            core=Core(root/'core',timeout=30)
            try:
                case=core.investigate('synthetic','static crypto',scope,'owner','test')
                result=self.api().run_crypto_inspect(core,case,path,seconds=10)
                self.assertEqual(result['kind'],'crypto_inspect')
                self.assertEqual(saved_operations(core,case)[0]['analysis']['input_sha256'],result['evidence']['sha256'])
                self.assertTrue(core.verify_audit(case))
                core.pause(case)
                with self.assertRaises(CoreError):self.api().run_crypto_inspect(core,case,path)
            finally:core.close()
    @unittest.skipUnless(os.environ.get('CYBER_CRYPTO_REAL')=='1','real Linux tools job')
    def test_real_compiled_elf_symbols_instructions_and_ghidra_references(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            src=root/'lab.c';binary=root/'lab'
            src.write_text('extern int puts(const char*);\nconst unsigned char crypto_table[256]={'+','.join(map(str,AES))+'};\n__attribute__((noinline)) int EVP_EncryptInit_ex(void){return crypto_table[3];}\n__attribute__((noinline)) int crypto_fixture(int x){asm volatile("aesenc %xmm0,%xmm1");return EVP_EncryptInit_ex()+crypto_table[x&255];}\nint main(int argc,char**argv){return crypto_fixture(argc);}\n')
            subprocess.run(['gcc','-O0','-fno-pie','-no-pie','-g',str(src),'-o',str(binary)],check=True)
            result=self.api().inspect_file(binary,seconds=240,ghidra_home=os.environ['CYBER_GHIDRA_HOME'],java_home=os.environ['JAVA_HOME'],capstone=True)
            self.assertEqual(result['format'],'elf')
            self.assertTrue(any(f['kind']=='symbol' and f['rule']=='api.EVP_EncryptInit_ex.v1' for f in result['findings']))
            self.assertTrue(any(f['kind']=='instruction' and f['family']=='AES' for f in result['findings']))
            self.assertEqual(result['coverage']['ghidra']['status'],'completed')
            self.assertTrue(any(f['kind']=='static_reference' for f in result['findings']))
            self.assertNotIn('crypto_fixture',json.dumps(result))
if __name__=='__main__':unittest.main()
