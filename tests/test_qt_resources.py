"""Synthetic Qt layouts from pinned Qt 6.8.3; real tool proof is separate."""
import hashlib
import importlib
import struct
import unittest
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

if __name__=='__main__':
    unittest.main()
