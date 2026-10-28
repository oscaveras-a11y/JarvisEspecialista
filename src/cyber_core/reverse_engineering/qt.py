"""Bounded static Qt RCC v3 and pinned QML compiled-unit readers."""
import hashlib
import struct
import zlib
from cyber_core.errors import CoreError
from cyber_core.reverse_engineering.qt_qml import inspect_qml_unit

def _fail(message):
    raise CoreError('Qt RCC: '+message)

def _hash(data,at,length):
    digest=hashlib.sha256()
    for pos in range(at,at+length,1048576):
        digest.update(data[pos:min(at+length,pos+1048576)])
    return digest.hexdigest()

def inspect_rcc(data, offset=0, *, max_entries=4096, max_resource_bytes=8388608,
                max_decoded_bytes=67108864, max_ratio=200):
    for value,minimum,maximum in ((max_entries,1,10000),(max_resource_bytes,1,67108864),
                                  (max_decoded_bytes,1,268435456),(max_ratio,1,10000)):
        if type(value) is not int or not minimum<=value<=maximum:
            _fail('invalid resource budget')
    if type(offset) is not int or not 0<=offset<=len(data)-8 or data[offset:offset+4]!=b'qres':
        _fail('missing RCC header')
    version=struct.unpack_from('>I',data,offset+4)[0]
    base={'offset':offset,'format_version':version,'resources':[],
          'limitations':'Static RCC tree and bounded payload interpretation; name hashes and Qt runtime semantics are not verified.'}
    if version!=3:
        return {**base,'status':'unsupported_version'}
    if len(data)-offset<24:
        _fail('truncated v3 header')
    tree,payload,names,features=struct.unpack_from('>IIII',data,offset+8)
    positions=(tree,payload,names)
    if len(set(positions))!=3 or any(v<24 or v>=len(data)-offset for v in positions):
        _fail('invalid section offsets')
    if features&~5:
        return {**base,'status':'unsupported_features','features_declared':features}
    def bound(start):
        return min([v for v in positions if v>start]+[len(data)-offset])
    tree_end,payload_end,names_end=bound(tree),bound(payload),bound(names)
    def need(at,length,begin,end):
        if at<begin or at>end or length<0 or length>end-at:
            _fail('record outside section bounds')
    def name(at):
        at=names+at
        need(at,6,names,names_end)
        count=struct.unpack_from('>H',data,offset+at)[0]
        if count>4096:
            _fail('resource name exceeds character limit')
        need(at+6,count*2,names,names_end)
        value=data[offset+at+6:offset+at+6+count*2].decode('utf-16-be',errors='surrogatepass')
        if not value or value in ('.','..') or any(c in value for c in ('/','\\','\0')) or any(ord(c)<32 for c in value):
            _fail('invalid resource path component')
        return value
    capacity=(tree_end-tree)//22
    seen=set()
    stack=[(0,'',0)]
    decoded=0
    partial=False
    identities=set()
    while stack:
        node,parent,depth=stack.pop()
        if node in seen or len(seen)>=max_entries or node>=capacity or depth>128:
            _fail('cycle, invalid node or tree budget exceeded')
        seen.add(node)
        at=tree+node*22
        need(at,22,tree,tree_end)
        name_at,flags=struct.unpack_from('>IH',data,offset+at)
        if flags&~7 or (flags&2 and flags&5) or flags&5==5:
            _fail('unsupported node flags')
        path=parent if node==0 else parent+'/'+name(name_at)
        if len(path)>8192:
            _fail('resource path exceeds budget')
        if flags&2:
            count,first=struct.unpack_from('>II',data,offset+at+6)
            if count>max_entries or first>capacity or count>capacity-first:
                _fail('child range exceeds tree bounds or budget')
            if node==0 and parent:
                _fail('invalid root')
            for child in range(first+count-1,first-1,-1):
                stack.append((child,path,depth+1))
            continue
        if node==0:
            _fail('resource root is not a directory')
        territory,language,relative=struct.unpack_from('>HHI',data,offset+at+6)
        identity=(path,territory,language)
        if identity in identities:
            _fail('ambiguous duplicate resource locale/path')
        identities.add(identity)
        blob=payload+relative
        need(blob,4,payload,payload_end)
        size=struct.unpack_from('>I',data,offset+blob)[0]
        need(blob+4,size,payload,payload_end)
        if size>max_resource_bytes+4:
            _fail('stored resource exceeds budget')
        record={'path':path,'territory_declared':territory,'language_declared':language,
                'source_file_offset':offset+blob+4,'stored_size_bytes':size,
                'stored_sha256':_hash(data,offset+blob+4,size)}
        if flags&4:
            record.update(status='unsupported_compression',compression='zstd',sha256=None)
            base['resources'].append(record)
            partial=True
            continue
        if flags&1:
            need(blob+4,4,payload,payload_end)
            if size<4:
                _fail('truncated compressed resource')
            expected=struct.unpack_from('>I',data,offset+blob+4)[0]
            if expected>max_resource_bytes or expected>max_ratio*max(1,size-4):
                _fail('expanded size or ratio exceeds budget')
            if decoded+expected>max_decoded_bytes:
                _fail('aggregate decoded bytes exceed budget')
            decoder=zlib.decompressobj()
            output=bytearray()
            try:
                for pos in range(blob+8,blob+4+size,65536):
                    output.extend(decoder.decompress(data[offset+pos:offset+min(blob+4+size,pos+65536)],
                                                     expected-len(output)+1))
                    if len(output)>expected or decoder.unused_data:
                        _fail('compressed resource size mismatch or trailing stream')
                if not decoder.eof or len(output)!=expected:
                    _fail('incomplete compressed stream or declared size mismatch')
            except zlib.error as exc:
                raise CoreError('Qt RCC: invalid zlib stream') from exc
            decoded+=expected
            record.update(status='decoded',compression='zlib',size_bytes=expected,
                          sha256=hashlib.sha256(output).hexdigest())
            if output[:8]==b'qv4cdata':
                record['qml']=inspect_qml_unit(output,max_entries=max_entries)
                partial|=record['qml']['status']!='completed'
        else:
            if size>max_resource_bytes or decoded+size>max_decoded_bytes:
                _fail('decoded resource bytes exceed budget')
            decoded+=size
            record.update(status='decoded',compression='none',size_bytes=size,
                          sha256=record['stored_sha256'])
            if data[offset+blob+4:offset+blob+12]==b'qv4cdata':
                record['qml']=inspect_qml_unit(data,offset+blob+4,available=size,max_entries=max_entries)
                partial|=record['qml']['status']!='completed'
        base['resources'].append(record)
    return {**base,'status':'partial' if partial else 'completed','entry_count':len(seen),
            'resource_count':len(base['resources']),'decoded_bytes':decoded}
