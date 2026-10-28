"""Bounded standard Microsoft COFF records; no evidence is executed."""
import struct
from cyber_core.errors import CoreError

_LIMITATION = ('Declared COFF symbols are not function boundaries or runtime behavior. '
               'Auxiliary payloads, BigObj, imports and archives are not decoded.')

def _fail(message):
    raise CoreError('COFF: '+message)

def read_symbols(data, *, max_symbols=128, max_records=100000, max_name_bytes=512):
    for value,minimum,maximum in ((max_symbols,1,1024),(max_records,1,100000),(max_name_bytes,8,4096)):
        if type(value) is not int or not minimum <= value <= maximum:
            _fail('invalid resource budget')
    if max_symbols*(8*max_name_bytes+1024)>850000:
        _fail('combined result budget too large')
    base = {'limitations':_LIMITATION,'symbols':[],'symbols_truncated':False}
    if data[:4]==b'\0\0\xff\xff':
        return {**base,'status':'unsupported_variant','variant':'BigObj or anonymous COFF'}
    pe = data[:2]==b'MZ'
    image_base = None
    if pe:
        from cyber_core.firmware import _pe
        metadata = _pe(data)
        header = int.from_bytes(data[60:64],'little')+4
        sections = metadata['section_headers']
        image_base = metadata['image_base']
    else:
        from cyber_core.firmware.structures import _PE_ARCH
        if len(data)<2 or int.from_bytes(data[:2],'little') not in _PE_ARCH:
            return {**base,'status':'unsupported_format'}
        header=0
    if len(data)<header+20:
        _fail('truncated header')
    machine,count,stamp,pointer,records,optional,flags=struct.unpack_from('<HHIIIHH',data,header)
    table=header+20+optional
    end=table+count*40
    if count>256 or end>len(data) or (not pe and optional):
        _fail('unsupported or truncated section table')
    if not pe:
        sections=[]
        for i in range(count):
            at=table+i*40
            size,offset=struct.unpack_from('<II',data,at+16)
            section_flags=struct.unpack_from('<I',data,at+36)[0]
            uninitialized=bool(section_flags&0x80) and not bool(section_flags&0x60)
            if uninitialized and offset:
                _fail('unsupported file payload for uninitialized section')
            file_size=0 if uninitialized else size
            if file_size and (offset<end or offset+file_size>len(data)):
                _fail('section payload outside input')
            sections.append({'file_size':file_size,'file_offset':offset,'memory_size':size,
                             'declared_size':size,'uninitialized':uninitialized})
    base.update(container='pe' if pe else 'coff_object',machine=machine,
                record_count=records,symbol_count=0,string_table_bytes=0)
    if not pointer and not records:
        return {**base,'status':'no_symbols'}
    if not pointer or records>max_records or pointer<end or pointer+records*18+4>len(data):
        _fail('symbol table outside input or record budget exceeded')
    strings=pointer+records*18
    string_size=struct.unpack_from('<I',data,strings)[0]
    if not 4<=string_size<=16*1024*1024 or strings+string_size>len(data):
        _fail('invalid string table bounds')
    if string_size>4 and data[strings+string_size-1]!=0:
        _fail('unterminated string table')
    for section in sections:
        begin=section['file_offset']
        length=section['file_size']
        if length and pointer<begin+length and begin<strings+string_size:
            _fail('symbol/string table overlaps a section payload')
    base['string_table_bytes']=string_size
    index=0
    name_partial=False
    while index<records:
        at=pointer+index*18
        name_field,value,number,kind,storage,aux=struct.unpack_from('<8sIhHBB',data,at)
        if index+1+aux>records:
            _fail('auxiliary count exceeds symbol table')
        if number not in (-2,-1,0) and not 1<=number<=count:
            _fail('symbol section index outside table')
        truncated=False
        if name_field[:4]==bytes(4):
            name_offset=int.from_bytes(name_field[4:],'little')
            if not 4<=name_offset<string_size:
                _fail('symbol name outside string table')
            start=strings+name_offset
            stop=min(strings+string_size,start+max_name_bytes+1)
            terminator=data.find(b'\0',start,stop)
            truncated=terminator<0
            raw=data[start:start+max_name_bytes] if truncated else data[start:terminator]
        else:
            raw=name_field.split(b'\0',1)[0]
        name_partial |= truncated
        base['symbol_count']+=1
        if len(base['symbols'])<max_symbols:
            rva=virtual=file_offset=None
            section_offset=value if number>0 else None
            if number>0:
                section=sections[number-1]
                if value<section['file_size']:
                    file_offset=section['file_offset']+value
                if pe and value<=max(section['file_size'],section['memory_size']):
                    candidate=section['virtual_address_rva']+value
                    if candidate<2**32 and image_base+candidate<2**metadata['class_bits']:
                        rva=candidate
                        virtual=image_base+candidate
            base['symbols'].append({'record_index':index,'name':raw.decode('utf-8',errors='replace'),
                                    'name_raw_hex':raw.hex(),'name_truncated':truncated,
                                    'section_number':number,'section_offset':section_offset,
                                    'value':value,'rva':rva,'virtual_address':virtual,'file_offset':file_offset,
                                    'type':kind,'storage_class':storage,'auxiliary_count':aux,
                                    'function_type_declared':(kind&0x30)==0x20})
        index+=1+aux
    base['symbols_truncated']=base['symbol_count']>len(base['symbols'])
    base['names_partial']=name_partial
    base['status']='partial' if name_partial or base['symbols_truncated'] else 'completed'
    return base
