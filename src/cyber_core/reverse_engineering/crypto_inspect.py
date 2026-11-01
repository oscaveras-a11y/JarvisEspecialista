"""Supervised static cryptographic evidence, never key recovery or specimen execution."""
import hashlib
import json
import math
from pathlib import Path
import sys
import tempfile
import time
from collections import Counter
from cyber_core.errors import CoreError
from cyber_core.reverse_engineering.crypto_rules import CONSTANTS, STRINGS, INSTRUCTIONS
from cyber_core.reverse_engineering.crypto_structures import address, regions, pe_symbols, elf_symbols

MAX_BYTES=1073741824
MAX_OUTPUT=262144
def limits(max_bytes,max_findings,seconds):
    if type(max_bytes) is not int or not 1<=max_bytes<=MAX_BYTES:
        raise CoreError('Invalid crypto input byte budget')
    if type(max_findings) is not int or not 1<=max_findings<=256:
        raise CoreError('Invalid crypto finding budget')
    if type(seconds) not in (int,float) or not math.isfinite(seconds) or not 0<seconds<=300:
        raise CoreError('Invalid crypto time budget')
def encode_result(result,output_bytes=MAX_OUTPUT):
    if type(output_bytes) is not int or not 4096<=output_bytes<=MAX_OUTPUT:
        raise CoreError('Invalid crypto output byte budget')
    result={**result,'findings':list(result['findings']),'output_truncated':False}
    while True:
        text=json.dumps(result,ensure_ascii=True,separators=(',',':'))
        if len(text.encode())+1<=output_bytes:return text
        if not result['findings']:raise CoreError('Crypto metadata exceeds output budget')
        result['findings'].pop()
        result.update(output_truncated=True,findings_truncated=True,status='partial')
class _Cap(Exception):pass

def _decoded_runs(memory):
    start=previous=None;block=bytearray()
    for at in sorted(memory):
        if previous is not None and at!=previous+1:
            yield start,bytes(block)
            block=bytearray()
        if not block:start=at
        block.append(memory[at]);previous=at
    if block:yield start,bytes(block)

def _record_sources(data,fmt):
    # Validated decoder has already checked checksums, record structure and overlap.
    sources=[];base=0;offset=0
    for raw in data[:].splitlines(keepends=True):
        line=raw.rstrip(b'\r\n')
        if line:
            record=bytes.fromhex(line[1:].decode()) if fmt=='intel_hex' else bytes.fromhex(line[2:].decode())
            if fmt=='intel_hex':
                kind=record[3];at=int.from_bytes(record[1:3],'big')
                if kind==0 and record[0]:sources.append((base+at,base+at+record[0],offset))
                elif kind in (2,4):base=int.from_bytes(record[4:-1],'big')<<(4 if kind==2 else 16)
            else:
                kind=int(chr(line[1]))
                if kind in (1,2,3):
                    width=kind+1;at=int.from_bytes(record[1:1+width],'big')
                    sources.append((at,at+len(record)-width-2,offset))
        offset+=len(raw)
    return sorted(sources)

def _instructions(data,meta,fmt,add,check):
    try:import capstone
    except (ImportError,OSError):return {'status':'dependency_unavailable'}
    architecture=meta.get('architecture')
    modes={'x86':(capstone.CS_ARCH_X86,capstone.CS_MODE_32),
           'x86_64':(capstone.CS_ARCH_X86,capstone.CS_MODE_64),
           'aarch64':(capstone.CS_ARCH_ARM64,capstone.CS_MODE_ARM)}
    if architecture not in modes or meta.get('endian','little')!='little':
        return {'status':'unsupported_architecture'}
    decoder=capstone.Cs(*modes[architecture])
    consumed=visited=0;partial=False;eligible=0
    for region in meta.get('section_headers',[]):
        if not region.get('executable') or region.get('compressed') or not region.get('file_size'):continue
        start=region['file_offset'];size=region['file_size'];va=address(meta,fmt,start,size)
        if va is None:partial=True;continue
        eligible+=size;at=0
        if architecture=='aarch64' and va%4:partial=True;continue
        while at<size:
            check()
            budget=min(size-at,1048576,16777216-consumed)
            if budget<=0 or visited>=1000000:partial=True;break
            sample=data[start+at:start+at+budget]
            used=0
            for ip,width,mnemonic,operand in decoder.disasm_lite(sample,va+at):
                if width<=0 or ip!=va+at+used or used+width>len(sample):
                    raise CoreError('Invalid crypto instruction mapping')
                visited+=1;used+=width
                if visited%4096==0:check()
                if mnemonic in INSTRUCTIONS:
                    add(dict(kind='instruction',rule='instruction.'+mnemonic+'.v1',
                             family=INSTRUCTIONS[mnemonic],strength='instruction',
                             offset=start+at+used-width,virtual_address=ip,
                             decoded_address=None,source_record_offset=None))
                if visited>=1000000:break
            consumed+=used;at+=used
            if not used or used<len(sample) and (len(sample)<1048576 or visited>=1000000):
                partial=True;break
            # If the sample ends inside an instruction, next chunk starts at last
            # decoded boundary. Invalid encodings stop; skipdata is never enabled.
    return {'status':'partial' if partial else 'completed' if eligible else 'no_executable_file_bytes',
            'backend_version':capstone.__version__,'decoded_bytes':consumed,
            'visited_instructions':visited,'limit_bytes':16777216,'limit_instructions':1000000}

def inspect_file(path,*,max_bytes=MAX_BYTES,max_findings=256,seconds=300,
                 capstone=False,ghidra_home=None,java_home=None,expected_sha256=None):
    limits(max_bytes,max_findings,seconds)
    if type(capstone) is not bool:raise CoreError('Invalid crypto instruction option')
    if (ghidra_home is None)!=(java_home is None):raise CoreError('Ghidra and Java paths required together')
    from cyber_core.firmware import _mapped,_digest,_pe,_elf,_load
    deadline=time.monotonic()+seconds
    def check():
        if time.monotonic()>=deadline:raise CoreError('Crypto shared deadline exceeded')
    findings=[];truncated=False;scanned=0;entropy_scanned=0;entropy_regions=0
    coverage={'constants':{'status':'completed'},'technical_strings':{'status':'completed'},
              'structures':{'status':'not_applicable'},'capstone':{'status':'not_requested'},
              'ghidra':{'status':'not_requested'},'entropy':{'status':'completed','window_bytes':4096}}
    with _mapped(path,max_bytes) as data:
        digest=_digest(data);check()
        if expected_sha256 is not None and digest!=expected_sha256:
            raise CoreError('Crypto evidence digest mismatch')
        fmt='bin';meta={};memory=None;sources=[]
        if data[:2]==b'MZ':fmt='pe';meta=_pe(data)
        elif data[:4]==b'\x7fELF':fmt='elf';meta=_elf(data)
        elif data[:1]==b':' or data[:1]==b'S' and data[1:2].isdigit():
            loaded,memory=_load(data,100000,1048576)
            fmt=loaded['format'];meta=loaded['metadata'];sources=_record_sources(data,fmt)
        def add(row):
            nonlocal truncated
            if len(findings)>=max_findings:
                truncated=True
                raise _Cap()
            findings.append(row)
        def finding(kind,rule,family,at,length,base=None):
            decoded=base+at if base is not None else None
            source=next((s for a,b,s in sources if a<=decoded<b),None) if decoded is not None else None
            return dict(kind=kind,rule=rule,family=family,
                        strength='constant' if kind=='constant' else 'weak',
                        offset=at if decoded is None else None,decoded_address=decoded,
                        virtual_address=address(meta,fmt,at,length) if fmt in ('pe','elf') and decoded is None else None,
                        source_record_offset=source)
        rules=[('constant',rule,family,payload) for rule,family,payload in CONSTANTS]
        rules += [('technical_string','string.'+name+'.v1',family,name.encode()) for name,family in STRINGS.items()]
        runs=_decoded_runs(memory) if memory is not None else [(None,data)]
        try:
            for base,content in runs:
                for at in range(0,len(content),65536):
                    check();end=min(len(content),at+65536)
                    sample=content[at:min(len(content),end+511)]
                    for kind,rule,family,payload in rules:
                        index=sample.find(payload)
                        while 0<=index<end-at:
                            add(finding(kind,rule,family,at+index,len(payload),base))
                            index=sample.find(payload,index+1)
                    scanned+=end-at
                    # Entropy is descriptive only, never an algorithm claim.
                    for window in range(at,end,4096):
                        block=content[window:min(window+4096,len(content))]
                        if len(block)<4096:continue
                        counts=Counter(block);entropy=-sum((n/4096)*math.log2(n/4096) for n in counts.values())
                        entropy_scanned+=len(block)
                        if entropy>=7.8:
                            entropy_regions+=1
                            add(dict(kind='entropy',rule='entropy.high.v1',family=None,strength='ambiguous',
                                     offset=window if base is None else None,decoded_address=base+window if base is not None else None,
                                     virtual_address=None,source_record_offset=None,
                                     window_bytes=4096,entropy=round(entropy,4)))
        except _Cap:
            coverage['constants']['status']=coverage['technical_strings']['status']='partial'
            coverage['entropy']['status']='partial'
        coverage['constants']['scanned_bytes']=scanned
        coverage['technical_strings']['scanned_bytes']=scanned
        coverage['entropy'].update(scanned_bytes=entropy_scanned,regions_observed=entropy_regions)
        if fmt in ('pe','elf'):
            rows=(pe_symbols if fmt=='pe' else elf_symbols)(data,meta,check)
            coverage['structures']={'status':'completed','record_limit':100000}
            try:
                for row in rows:add(row)
            except _Cap:coverage['structures']['status']='partial'
        if capstone:
            try:coverage['capstone']=_instructions(data,meta,fmt,add,check)
            except _Cap:coverage['capstone']={'status':'partial','reason':'finding_budget'}
        if ghidra_home is not None:
            from cyber_core.reverse_engineering.crypto_ghidra import references
            rows,state=references(Path(path),fmt,meta,findings,ghidra_home,java_home,deadline)
            coverage['ghidra']=state
            try:
                for row in rows:add(row)
            except _Cap:coverage['ghidra']['status']='partial'
        check()
        if _digest(data)!=digest:raise CoreError('Crypto evidence changed during analysis')
        partial=truncated or fmt=='bin' or fmt in ('intel_hex','srecord') or any(
            v['status'] in ('partial','failed','dependency_unavailable','unsupported_architecture','unsupported_format','unsupported_platform')
            for v in coverage.values())
        return dict(schema_version=1,status='partial' if partial else 'completed',format=fmt,
                    input_sha256=digest,input_bytes=len(data),findings=findings,
                    findings_truncated=truncated,coverage=coverage,
                    limits={'input_bytes':max_bytes,'findings':max_findings,'output_bytes':MAX_OUTPUT,'seconds':seconds,
                            'record_decoded_bytes':1048576,'record_input_bytes':67108864},
                    limitations=['Static evidence is not proof of execution or absence of cryptography.',
                                 'Generic crypto APIs do not determine algorithm, mode or key.',
                                 'BIN architecture unknown; record formats have decoded addresses, not source byte offsets.',
                                 'Compression is not unpacked; high entropy cannot identify an algorithm.',
                                 'Only allowlisted API names and rule IDs exported; no keys, arbitrary strings or pseudocode.'])

def run_crypto_inspect(core,case,path,*,max_findings=256,seconds=300,
                       capstone=False,ghidra_home=None,java_home=None,output_bytes=MAX_OUTPUT):
    from cyber_core.agents.runner import run_bounded
    from cyber_core.operations import save_operation
    from cyber_core.verification.artifacts import verified_result
    maximum=min(core.max_bytes,MAX_BYTES);timeout=min(core.timeout,seconds,300)
    limits(maximum,max_findings,seconds)
    encode_result({'findings':[]},output_bytes)
    if type(capstone) is not bool:raise CoreError('Invalid crypto instruction option')
    if (ghidra_home is None)!=(java_home is None):raise CoreError('Ghidra and Java paths required together')
    if ghidra_home is not None:
        from cyber_core.reverse_engineering.external import _path
        ghidra_home=str(_path(ghidra_home));java_home=str(_path(java_home))
    def stopped():
        return bool(core.authorize(case)['paused'])
    if stopped():raise CoreError('Investigation is paused')
    started=time.monotonic()
    task=core.enqueue(case,path)
    core.run_one(case,task_id=task,time_budget=timeout)
    evidence,_=verified_result(core,case,task)
    remaining=timeout-(time.monotonic()-started)
    if remaining<=0:raise CoreError('Crypto shared deadline exceeded')
    request=dict(path=evidence['copy'],expected_sha256=evidence['sha256'],max_bytes=maximum,
                 max_findings=max_findings,seconds=remaining,capstone=capstone,
                 ghidra_home=ghidra_home,java_home=java_home,output_bytes=output_bytes)
    with tempfile.TemporaryDirectory(prefix='cyber-crypto-') as scratch:
        response=run_bounded([sys.executable,'-I',str(Path(__file__).with_name('crypto_child.py'))],
                             json.dumps(request),cwd=scratch,timeout=remaining,max_output=output_bytes,
                             should_stop=stopped,env={})
        result=json.loads(response['stdout'])
    if not isinstance(result,dict) or result.get('input_sha256')!=evidence['sha256']:
        raise CoreError('Crypto worker evidence mismatch')
    def guard():
        if stopped():raise CoreError('Investigation is paused')
        core.authorize(case,path)
        verified_result(core,case,task)
    guard()
    return save_operation(core,case,'crypto_inspect',
                          {'evidence':evidence,'analysis':result},commit_guard=guard)
