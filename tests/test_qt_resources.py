"""Synthetic Qt layouts from pinned Qt 6.8.3; real tool proof is separate."""
import hashlib
import importlib
import struct
import unittest
import sys
import subprocess
import zlib
from cyber_core.errors import CoreError

def qml_fixture():
    values=['','QtObject','value','mode','synthetic-mode','label','Laboratory only','enabled']
    data=bytearray(248+len(values)*4)
    for i,value in enumerate(values):
        data+=bytes((-len(data))%8)
        struct.pack_into('<I',data,248+i*4,len(data))
        encoded=value.encode('utf-16-le')
        data+=struct.pack('<i',len(encoded)//2)+encoded+b'\0\0'
    data+=bytes((-len(data))%8)
    constants=len(data)
    data+=struct.pack('<Q',0x0003c00000000025)
    translations=len(data)
    data+=struct.pack('<IIiI',6,0,-1,0xffffffff)
    data+=bytes((-len(data))%8)
    qml=len(data)
    data+=struct.pack('<IIII',0,0,1,16)+struct.pack('<I',24)+bytes(4)
    obj=bytearray(88)
    struct.pack_into('<II',obj,0,1,0)
    struct.pack_into('<i',obj,12,-1)
    struct.pack_into('<H',obj,46,4)
    struct.pack_into('<I',obj,48,88)
    data+=obj
    for prop,typ,val,string in ((2,2,0,0),(3,3,0,4),(5,5,0,0),(7,1,1,0)):
        data+=struct.pack('<IIIIII',prop,typ<<16,val,string,0,0)
    data[:8]=b'qv4cdata'
    struct.pack_into('<II',data,8,0x42,0x060803)
    struct.pack_into('<I',data,24,len(data))
    struct.pack_into('<II',data,112,len(values),248)
    struct.pack_into('<II',data,168,1,constants)
    struct.pack_into('<II',data,184,1,translations)
    struct.pack_into('<I',data,244,qml)
    data[76:92]=hashlib.md5(data[92:],usedforsecurity=False).digest()
    return data

def rcc_fixture(payload=b'lab-resource',compressed=False):
    names=bytearray()
    offsets=[]
    for name in ('','lab','fixture.qmlc'):
        offsets.append(len(names))
        encoded=name.encode('utf-16-be')
        names+=struct.pack('>HI',len(encoded)//2,0)+encoded
    blob=struct.pack('>I',len(payload))+zlib.compress(payload) if compressed else payload
    files=struct.pack('>I',len(blob))+blob
    tree=bytearray()
    tree+=struct.pack('>IHIIQ',offsets[0],2,1,1,0)
    tree+=struct.pack('>IHIIQ',offsets[1],2,1,2,0)
    tree+=struct.pack('>IHHHIQ',offsets[2],1 if compressed else 0,0,1,0,0)
    header=struct.pack('>4sIIIII',b'qres',3,24+len(files)+len(names),24,24+len(files),1 if compressed else 0)
    return bytearray(header+files+names+tree)

class QtResourceTests(unittest.TestCase):
    def api(self):
        try:
            return importlib.import_module('cyber_core.reverse_engineering.qt')
        except ImportError:
            self.fail('Static Qt resource reader is not implemented')

    def test_qml_strings_constants_translations_objects_and_bindings(self):
        result=self.api().inspect_qml_unit(qml_fixture())
        self.assertEqual(result['checksum_status'],'match')
        self.assertEqual(result['constants'][0]['value'],37)
        self.assertEqual(result['translations'][0]['text'],'Laboratory only')
        self.assertEqual(result['objects'][0]['type'],'QtObject')
        bindings={b['property']:b for b in result['objects'][0]['bindings']}
        self.assertEqual(bindings['value']['value'],37)
        self.assertEqual(bindings['mode']['value'],'synthetic-mode')
        self.assertTrue(bindings['enabled']['value'])

    def test_qml_invalid_sizes_offsets_counts_and_indices(self):
        valid=qml_fixture()
        cases=[valid[:-1]]
        for at,value in ((24,0xffffffff),(116,0xffffffff),(112,100001),(244,0xffffffff)):
            bad=bytearray(valid);struct.pack_into('<I',bad,at,value);cases.append(bad)
        bad=bytearray(valid)
        obj=struct.unpack_from('<I',bad,244)[0]+24
        struct.pack_into('<I',bad,obj+88,99999);cases.append(bad)
        for bad in cases:
            with self.subTest(size=len(bad)),self.assertRaises(CoreError):
                self.api().inspect_qml_unit(bad)

    def test_qml_unknown_versions_and_checksum_mismatch_are_explicit(self):
        data=qml_fixture()
        struct.pack_into('<I',data,8,0x43)
        self.assertEqual(self.api().inspect_qml_unit(data)['status'],'unsupported_version')
        data=qml_fixture();data[76]^=1
        result=self.api().inspect_qml_unit(data)
        self.assertEqual(result['checksum_status'],'mismatch')
        self.assertEqual(result['status'],'partial')

    def test_real_payload_hash_after_bounded_zlib_decode(self):
        payload=b'lab-resource'*20
        for compressed in (False,True):
            result=self.api().inspect_rcc(rcc_fixture(payload,compressed))
            record=result['resources'][0]
            self.assertEqual(record['path'],'/lab/fixture.qmlc')
            self.assertEqual(record['sha256'],hashlib.sha256(payload).hexdigest())
            self.assertEqual(record['size_bytes'],240)
            self.assertEqual(record['compression'],'zlib' if compressed else 'none')

    def test_unsupported_compression_still_obeys_stored_byte_budget(self):
        data=rcc_fixture(b'opaque-stored-payload')
        struct.pack_into('>I',data,20,4)
        tree=struct.unpack_from('>I',data,8)[0]
        struct.pack_into('>H',data,tree+2*22+4,4)
        with self.assertRaises(CoreError):
            self.api().inspect_rcc(data,max_decoded_bytes=1)

    def test_compressed_node_must_match_declared_header_features(self):
        data=rcc_fixture(b'lab-resource',True)
        struct.pack_into('>I',data,20,0)
        with self.assertRaises(CoreError):
            self.api().inspect_rcc(data)

    def test_rcc_truncation_cycles_invalid_offsets_and_expansion_limit(self):
        valid=rcc_fixture()
        cases=[valid[:-1]]
        bad=bytearray(valid);struct.pack_into('>I',bad,8,len(bad)+1);cases.append(bad)
        bad=bytearray(valid);tree=struct.unpack_from('>I',bad,8)[0]
        struct.pack_into('>I',bad,tree+10,0);cases.append(bad)
        for bad in cases:
            with self.subTest(size=len(bad)),self.assertRaises(CoreError):
                self.api().inspect_rcc(bad)
        with self.assertRaises(CoreError):
            self.api().inspect_rcc(rcc_fixture(b'x'*4096,True),max_resource_bytes=1024)
        bad=rcc_fixture();struct.pack_into('>I',bad,4,99)
        self.assertEqual(self.api().inspect_rcc(bad)['status'],'unsupported_version')


class QtOutputBudgetTests(unittest.TestCase):
    @unittest.skipUnless(sys.platform=='linux','Linux address-space containment fixture')
    def test_repeated_unicode_bindings_fit_a_limited_encoder_process(self):
        source = """import json, resource
resource.setrlimit(resource.RLIMIT_AS,(268435456,268435456))
from cyber_core.reverse_engineering.qt_operation import _encode
large='界'*4096
unit={'objects':[{'bindings':[{'property':'x','value':large} for _ in range(10000)]}]}
result={'status':'partial','rcc':[],'qml_units':[unit],'candidates':[]}
encoded=_encode(result,output_bytes=16384)
bounded=json.loads(encoded)
assert len(encoded.encode('utf-8'))+1<=16384
assert bounded['output_truncated'] and bounded['output_qml_units_omitted']==1
assert bounded['qml_units']==[] and bounded['status']=='partial'
print('Streaming byte budget verified under 256 MiB address space')
"""
        completed=subprocess.run([sys.executable,'-c',source],capture_output=True,text=True,timeout=20)
        self.assertEqual(completed.returncode,0,completed.stderr[-1000:])
        self.assertIn('byte budget verified',completed.stdout)

if __name__=='__main__':
    unittest.main()
