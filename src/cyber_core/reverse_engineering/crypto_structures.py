"""Bounded PE import/export and ELF symbol metadata over validated layouts."""
import struct
from cyber_core.errors import CoreError
from cyber_core.reverse_engineering.crypto_rules import APIS

MAX_RECORDS=100000
def fail():
    raise CoreError('Crypto structural metadata is malformed or exceeds parser limits')
def span(data,at,n):
    if type(at) is not int or at<0 or n<0 or at>len(data) or n>len(data)-at:fail()
def cstring(data,at,end):
    span(data,at,1)
    stop=data.find(b'\0',at,min(end,at+513))
    if stop<0:fail()
    return data[at:stop]
def regions(meta,fmt):
    if fmt=='elf':
        if meta['type'] not in (2,3):return []
        return [r for r in meta['segments'] if r.get('type')==1 and r.get('file_size')]
    return [r for r in meta.get('section_headers',[]) if r.get('file_size')]
def address(meta,fmt,offset,size=1):
    matches=[r['virtual_address']+offset-r['file_offset'] for r in regions(meta,fmt)
             if r['file_offset']<=offset and offset+size<=r['file_offset']+r['file_size']]
    if not matches or len(set(matches))!=1:return None
    value=matches[0]
    # Overlapping virtual mappings must resolve to the same file bytes.
    for r in regions(meta,fmt):
        overlap=max(value,r['virtual_address'])
        if overlap<min(value+size,r['virtual_address']+r['file_size']):
            if r['file_offset']+overlap-r['virtual_address']!=offset+overlap-value:return None
    return value
def file_offset(meta,fmt,va,size=1):
    matches=[r['file_offset']+va-r['virtual_address'] for r in regions(meta,fmt)
             if r['virtual_address']<=va and va+size<=r['virtual_address']+r['file_size']]
    if not matches or len(set(matches))!=1:fail()
    offset=matches[0]
    if address(meta,fmt,offset,size)!=va:fail()
    return offset
def _record(name,kind,at,va=None):
    try:name=name.decode('ascii').split('@',1)[0]
    except UnicodeError:return None
    if name not in APIS:return None
    return dict(kind=kind,rule='api.'+name+'.v1',family=APIS[name],strength='structural',
                offset=at,virtual_address=va,decoded_address=None,source_record_offset=None)

def pe_symbols(data,meta,check):
    optional=int.from_bytes(data[60:64],'little')+24
    wide=meta['class_bits']==64
    directory=optional+(112 if wide else 96)
    count=int.from_bytes(data[directory-4:directory],'little')
    base=meta['image_base']
    def rva(value,size=1):
        return file_offset(meta,'pe',base+value,size)
    def mapped_string(value,skip=0):
        at=rva(value,skip+1)+skip
        ends=[r['file_offset']+r['file_size'] for r in regions(meta,'pe')
              if r['file_offset']<=at<r['file_offset']+r['file_size']]
        if not ends:fail()
        return at,cstring(data,at,min(ends))
    output=[]
    if count>1:
        start,length=struct.unpack_from('<II',data,directory+8)
        if bool(start)!=bool(length):fail()
        if start:
            if length<20 or length>20*4096:fail()
            at=rva(start,length);terminated=False;total=0
            for pos in range(at,at+length-19,20):
                check()
                lookup,stamp,chain,module,iat=struct.unpack_from('<IIIII',data,pos)
                if not any((lookup,stamp,chain,module,iat)):terminated=True;break
                mapped_string(module)
                if not iat:fail()
                table=lookup or iat
                width=8 if wide else 4
                for index in range(MAX_RECORDS-total):
                    total+=1
                    slot=rva(table+index*width,width)
                    value=int.from_bytes(data[slot:slot+width],'little')
                    if not value:break
                    if value>>(width*8-1):continue
                    if value>0xffffffff:fail()
                    name_at,name=mapped_string(value,2)
                    row=_record(name,'import',name_at)
                    if row:output.append(row)
                    if len(output)>256:output=output[:257]
                else:fail()
            if not terminated:fail()
    if count:
        start,length=struct.unpack_from('<II',data,directory)
        if bool(start)!=bool(length):fail()
        if start:
            at=rva(start,40)
            nfunc,nnames,funcs,names,ordinals=struct.unpack_from('<IIIII',data,at+20)
            if max(nfunc,nnames)>MAX_RECORDS or nnames>nfunc:fail()
            f=rva(funcs,nfunc*4) if nfunc else 0
            n=rva(names,nnames*4) if nnames else 0
            o=rva(ordinals,nnames*2) if nnames else 0
            for i in range(nnames):
                if i%1024==0:check()
                ordinal=struct.unpack_from('<H',data,o+i*2)[0]
                if ordinal>=nfunc:fail()
                target=struct.unpack_from('<I',data,f+ordinal*4)[0]
                at,name=mapped_string(struct.unpack_from('<I',data,n+i*4)[0])
                # Forwarder strings are not executable addresses.
                va=None if start<=target<start+length else base+target
                if va is not None:rva(target)
                row=_record(name,'symbol',at,va)
                if row and len(output)<257:output.append(row)
    return output

def elf_symbols(data,meta,check):
    output=[];total=0
    order='<' if meta['endian']=='little' else '>'
    wide=meta['class_bits']==64
    sections=meta['section_headers']
    for sec in sections:
        if sec['type'] not in (2,11):continue
        width=24 if wide else 16
        if sec.get('compressed') or sec['entry_size']!=width or sec['file_size']%width:fail()
        total+=sec['file_size']//width
        if total>MAX_RECORDS:fail()
        linked=sec['link']
        if not linked or linked>=len(sections) or sections[linked]['type']!=3:fail()
        strings=sections[linked]
        if strings.get('compressed'):fail()
        end=strings['file_offset']+strings['file_size']
        for pos in range(sec['file_offset'],sec['file_offset']+sec['file_size'],width):
            if pos%1024==0:check()
            if wide:name,info,other,index,value,size=struct.unpack_from(order+'IBBHQQ',data,pos)
            else:name,value,size,info,other,index=struct.unpack_from(order+'IIIBBH',data,pos)
            if index==0xffff:fail()
            if index and index<0xff00 and index>=len(sections):fail()
            if name>=strings['file_size']:fail()
            at=strings['file_offset']+name
            raw=cstring(data,at,end)
            va=None
            if index and index<0xff00 and meta['type'] in (2,3):
                try:
                    file_offset(meta,'elf',value)
                    va=value
                except CoreError:pass
            row=_record(raw,'symbol' if index else 'import',at,va)
            if row and len(output)<257:output.append(row)
    return output
