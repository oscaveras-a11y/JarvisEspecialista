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
from cyber_core.errors import CoreError

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
        compressed=zlib.compress(AES*32)
        self.assertNotIn(AES,compressed)
        for data in [AES[:128], compressed, b'random negative without crypto']:
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
            with self.assertRaises(CoreError):self.scan(bytes(broken))
    def test_pe_structural_import_is_distinct_from_embedded_api_name(self):
        data=bytearray(pe(bytes(256)))
        struct.pack_into('<II',data,272,0x1000,40)
        struct.pack_into('<IIIII',data,512,0x1040,0,0,0x1060,0x1040)
        struct.pack_into('<QQ',data,576,0x1080,0)
        data[608:619]=b'bcrypt.dll\0'
        data[640:656]=b'\0\0BCryptEncrypt\0'
        result=self.scan(bytes(data))
        imported=next(f for f in result['findings'] if f['kind']=='import')
        self.assertEqual(imported['rule'],'api.BCryptEncrypt.v1')
        self.assertEqual(imported['offset'],642)
        plain=self.scan(b'BCryptEncrypt\0')
        self.assertFalse(any(f['kind']=='import' for f in plain['findings']))
        struct.pack_into('<Q',data,576,0x9000)
        with self.assertRaises(CoreError):self.scan(bytes(data))
    def test_sha256_full_round_table_is_versioned(self):
        words='428a2f98 71374491 b5c0fbcf e9b5dba5 3956c25b 59f111f1 923f82a4 ab1c5ed5 d807aa98 12835b01 243185be 550c7dc3 72be5d74 80deb1fe 9bdc06a7 c19bf174 e49b69c1 efbe4786 0fc19dc6 240ca1cc 2de92c6f 4a7484aa 5cb0a9dc 76f988da 983e5152 a831c66d b00327c8 bf597fc7 c6e00bf3 d5a79147 06ca6351 14292967 27b70a85 2e1b2138 4d2c6dfc 53380d13 650a7354 766a0abb 81c2c92e 92722c85 a2bfe8a1 a81a664b c24b8b70 c76c51a3 d192e819 d6990624 f40e3585 106aa070 19a4c116 1e376c08 2748774c 34b0bcb5 391c0cb3 4ed8aa4a 5b9cca4f 682e6ff3 748f82ee 78a5636f 84c87814 8cc70208 90befffa a4506ceb bef9a3f7 c67178f2'
        payload=b''.join(int(w,16).to_bytes(4,'little') for w in words.split())
        result=self.scan(payload)
        self.assertTrue(any(f['rule']=='sha256.k.le.v1' for f in result['findings']))
        self.assertFalse(any(f['kind']=='constant' for f in self.scan(payload[:-4])['findings']))
    def test_managed_pe_and_missing_elf_symbol_tables_are_explicit_partial(self):
        data=bytearray(pe(AES))
        struct.pack_into('<II',data,264+14*8,0x1000,72)
        result=self.scan(bytes(data))
        self.assertEqual(result['status'],'partial')
        self.assertEqual(result['coverage']['format']['reason'],'managed_metadata_not_interpreted')
        header=bytearray(64)
        header[:7]=b'\\x7fELF\\x02\\x01\\x01'
        struct.pack_into('<HHIQQQIHHHHHH',header,16,2,62,1,0,0,0,0,64,0,0,0,0,0)
        result=self.scan(bytes(header)+AES)
        self.assertEqual(result['status'],'partial')
        self.assertEqual(result['coverage']['structures']['reason'],'no_section_symbol_tables')
    def test_import_name_must_remain_inside_its_declared_mapping(self):
        data=bytearray(pe(bytes(256)))
        struct.pack_into('<II',data,272,0x1000,40)
        struct.pack_into('<IIIII',data,512,0x1040,0,0,0x1060,0x1040)
        struct.pack_into('<QQ',data,576,0x10f0,0)
        data[608:619]=b'bcrypt.dll\\0'
        data[752:768]=b'\\0\\0BCryptEncryptX'
        data+=b'\\0'
        with self.assertRaises(CoreError):self.scan(bytes(data))
    def test_core_commit_guard_rejects_evidence_tamper(self):
        from unittest.mock import patch
        from cyber_core.service import Core
        from cyber_core.operations import save_operation,saved_operations
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);scope=root/'scope';scope.mkdir()
            path=scope/'specimen.bin';path.write_bytes(AES)
            core=Core(root/'core',timeout=30)
            try:
                case=core.investigate('synthetic','static crypto',scope,'owner','test')
                def tamper(core,case,kind,data,**options):
                    Path(data['evidence']['copy']).write_bytes(b'changed')
                    return save_operation(core,case,kind,data,**options)
                with patch('cyber_core.operations.save_operation',side_effect=tamper):
                    with self.assertRaises(CoreError):self.api().run_crypto_inspect(core,case,path,seconds=10)
                self.assertEqual(core.db.execute('SELECT COUNT(*) FROM operation_results').fetchone()[0],0)
            finally:core.close()
    def test_chunk_overlap_and_explicit_caps(self):
        result=self.scan(bytes(65530)+AES+CHACHA*300,max_findings=3)
        self.assertTrue(result['findings_truncated'])
        self.assertLessEqual(len(result['findings']),3)
        self.assertEqual(result['status'],'partial')
        self.assertEqual(next(f for f in result['findings'] if f['rule']=='aes.sbox.v1')['offset'],65530)
        self.assertLessEqual(len(self.api().encode_result(result,4096).encode())+1,4096)
    def test_malformed_structures_and_invalid_limits_fail_closed(self):
        for data in [b'MZ'+bytes(100),b'\x7fELF'+bytes(100)]:
            with self.assertRaises(CoreError):self.scan(data)
        for limits in [dict(max_findings=257),dict(max_findings=True),dict(seconds=301),dict(max_bytes=1073741825)]:
            with self.assertRaises(CoreError):self.scan(AES,**limits)
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
