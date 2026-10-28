"""Partial static decoder for Qt 6.8.3 QV4 unit layout 0x42.

Layout source: qtdeclarative v6.8.3 qv4compileddata_p.h and
qv4staticvalue_p.h. Bytecode is never interpreted or executed.
"""
import hashlib
import math
import struct
from cyber_core.errors import CoreError

def _fail(message):
    raise CoreError('Qt QML: '+message)

def _constant(raw):
    tag=raw>>32
    record={'raw_hex':struct.pack('<Q',raw).hex(),'kind':'unsupported_encoded_value'}
    if tag==0x3c000:
        record.update(kind='integer',value=struct.unpack('<i',struct.pack('<I',raw&0xffffffff))[0])
    elif tag==0x38000 and raw&0xffffffff in (0,1):
        record.update(kind='boolean',value=bool(raw&0xffffffff))
    elif tag==0x30000 and not raw&0xffffffff:
        record.update(kind='null',value=None)
    elif raw&0x7ff5000000000000>=0x0005000000000000:
        value=struct.unpack('<d',struct.pack('<Q',raw^0x7ff5400000000000))[0]
        if math.isfinite(value):
            record.update(kind='double',value=value)
        else:
            record.update(kind='nonfinite_number',value_text=str(value))
    return record

def inspect_qml_unit(data, offset=0, *, available=None, max_unit_bytes=33554432, max_entries=4096):
    for value,minimum,maximum in ((max_unit_bytes,248,67108864),(max_entries,1,10000)):
        if type(value) is not int or not minimum<=value<=maximum:
            _fail('invalid resource budget')
    if type(offset) is not int or not 0<=offset<=len(data):
        _fail('invalid unit offset')
    if available is None:
        available=len(data)-offset
    if type(available) is not int or not 0<=available<=len(data)-offset:
        _fail('invalid available span')
    if available<28 or data[offset:offset+8]!=b'qv4cdata':
        _fail('missing or truncated unit header')
    version,qt=struct.unpack_from('<II',data,offset+8)
    size=struct.unpack_from('<I',data,offset+24)[0]
    if not 28<=size<=min(available,max_unit_bytes):
        _fail('declared unit size exceeds input or budget')
    base={'offset':offset,'size_bytes':size,'format_version':version,'qt_version_declared':qt,
          'strings':[],'constants':[],'translations':[],'objects':[],
          'limitations':'Partial static Qt layout interpretation; not original QML reconstruction, execution or manufacturer authenticity.'}
    if version!=0x42 or qt!=0x060803:
        return {**base,'status':'unsupported_version'}
    if size<248:
        _fail('truncated Qt 6.8.3 header')
    def need(at,length):
        if at<0 or length<0 or at>size or length>size-at:
            _fail('table or record outside declared unit')
    def u32(at):
        need(at,4)
        return struct.unpack_from('<I',data,offset+at)[0]
    def table(count,at,width,minimum=248):
        if count>max_entries:
            _fail('entry count exceeds budget')
        if count:
            if at<minimum:
                _fail('table overlaps fixed header')
            need(at,count*width)
    checksum=hashlib.md5(usedforsecurity=False)
    for at in range(92,size,1048576):
        checksum.update(data[offset+at:offset+min(size,at+1048576)])
    base['checksum_status']='match' if checksum.digest()==data[offset+76:offset+92] else 'mismatch'
    base['checksum_scope']='MD5 of unit bytes following the checksum field; integrity hint, no authentication'
    base['library_hash_hex']=data[offset+28:offset+76].hex()
    strings_count,strings_at=u32(112),u32(116)
    table(strings_count,strings_at,4)
    strings=[]
    characters=0
    for i in range(strings_count):
        at=u32(strings_at+i*4)
        if at<248:
            _fail('string overlaps header')
        need(at,4)
        length=struct.unpack_from('<i',data,offset+at)[0]
        if not 0<=length<=4096:
            _fail('string length exceeds budget')
        characters+=length
        if characters>1048576:
            _fail('total string characters exceed budget')
        need(at+4,(length+1)*2)
        end=offset+at+4+length*2
        if data[end:end+2]!=b'\0\0':
            _fail('unterminated UTF-16 string')
        value=data[offset+at+4:end].decode('utf-16-le',errors='surrogatepass')
        strings.append(value)
        base['strings'].append({'index':i,'value':value})
    def string(index):
        if index>=len(strings):
            _fail('string index outside table')
        return strings[index]
    base['source_file_declared']=string(u32(236))
    base['final_url_declared']=string(u32(240))
    count,at=u32(168),u32(172)
    table(count,at,8)
    for i in range(count):
        record=_constant(struct.unpack_from('<Q',data,offset+at+i*8)[0])
        base['constants'].append({'index':i,**record})
    count,at=u32(184),u32(188)
    table(count,at,16)
    for i in range(count):
        text,comment,number,context=struct.unpack_from('<IIiI',data,offset+at+i*16)
        base['translations'].append({'index':i,'text':string(text),'comment':string(comment),
                                     'number_declared':number,'context':None if context==0xffffffff else string(context)})
    unparsed=[]
    for field,name,width in ((120,'functions',4),(128,'classes',4),(136,'template_objects',4),
                             (144,'blocks',4),(152,'lookups',4),(160,'regexps',4),
                             (176,'js_classes',4),(192,'local_exports',4),(200,'indirect_exports',4),
                             (208,'star_exports',4),(216,'imports',4),(224,'module_requests',4)):
        count,at=u32(field),u32(field+4)
        table(count,at,width)
        if count:
            unparsed.append({'table':name,'count':count,'offset':at,'validation':'minimum table span only'})
    qml=u32(244)
    bindings_total=0
    if qml:
        if qml<248:
            _fail('QML header overlaps unit header')
        need(qml,16)
        imports,imports_at,objects,objects_at=struct.unpack_from('<IIII',data,offset+qml)
        table(imports,qml+imports_at,20,qml+16)
        table(objects,qml+objects_at,4,qml+16)
        if imports:
            unparsed.append({'table':'qml_imports','count':imports,'validation':'fixed record span only'})
        for i in range(objects):
            obj=qml+u32(qml+objects_at+i*4)
            if obj<qml+16:
                _fail('object overlaps QML header')
            need(obj,84)
            record={'index':i,'type':string(u32(obj)),'id_name':string(u32(obj+4)),
                    'flags_declared':u32(obj+8),'bindings':[]}
            for count_at,offset_at,width,name in ((16,20,4,'functions'),(18,24,12,'properties'),
                 (32,28,20,'aliases'),(34,36,4,'enums'),(44,40,4,'signals'),
                 (72,68,8,'inline_components'),(80,76,4,'required_properties')):
                count=struct.unpack_from('<H',data,offset+obj+count_at)[0]
                table(count,obj+u32(obj+offset_at),width,obj+84)
                if count:
                    unparsed.append({'object':i,'table':name,'count':count,'validation':'record/table span only'})
            named=u32(obj+52)
            table(named,obj+u32(obj+56),4,obj+84)
            count=struct.unpack_from('<H',data,offset+obj+46)[0]
            at=obj+u32(obj+48)
            table(count,at,24,obj+84)
            bindings_total+=count
            if bindings_total>max_entries:
                _fail('total binding count exceeds budget')
            for n in range(count):
                prop,flags_type,value,index,loc,vloc=struct.unpack_from('<IIIIII',data,offset+at+n*24)
                typ=flags_type>>16
                binding={'property':string(prop),'type_code':typ,'flags':flags_type&0xffff}
                if typ==1:
                    b=data[offset+at+n*24+8]
                    if b not in (0,1):
                        _fail('invalid boolean binding')
                    binding.update(type='boolean',value=bool(b))
                elif typ==2:
                    if value>=len(base['constants']):
                        _fail('constant index outside table')
                    binding.update(type='number',constant_index=value)
                    if base['constants'][value]['kind'] in ('integer','double'):
                        binding['value']=base['constants'][value]['value']
                elif typ==3:
                    binding.update(type='string',value=string(index))
                elif typ==4:
                    binding.update(type='null',value=None)
                elif typ in (5,6):
                    if value>=len(base['translations']):
                        _fail('translation index outside table')
                    binding.update(type='translation' if typ==5 else 'translation_by_id',
                                   translation_index=value,value=base['translations'][value])
                elif typ==7:
                    binding.update(type='script',script_index=value,string_hint=string(index),
                                   interpretation='Bytecode not decoded or executed')
                elif typ in (8,9,10):
                    if value>=objects:
                        _fail('object binding index outside table')
                    binding.update(type='object_reference',object_index=value)
                else:
                    binding.update(type='unsupported',raw_value=value,string_index=index)
                record['bindings'].append(binding)
            base['objects'].append(record)
    base.update(status='partial',binding_count=bindings_total,unparsed_tables=unparsed,
                unparsed_features=['JS bytecode','semantic property/alias/enum/signal/import resolution'],
                constants_encoding='Qt 6.8.3 StaticValue; exercised with x86_64 compiler')
    return base
