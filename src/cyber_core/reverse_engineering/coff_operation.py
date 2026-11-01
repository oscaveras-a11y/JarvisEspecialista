"""Audited COFF metadata and optional trusted LLVM demanglers."""
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import time
from cyber_core.errors import CoreError

def _inspect(source, expected_sha256, max_bytes, timeout, options, llvm_bin):
    from cyber_core.firmware import _mapped, _digest
    from cyber_core.reverse_engineering.coff import read_symbols
    from cyber_core.reverse_engineering.external import _path, _run
    deadline=time.monotonic()+timeout
    with _mapped(source,max_bytes) as data:
        digest=_digest(data)
        if digest!=expected_sha256:
            raise CoreError('COFF evidence mismatch')
        result=read_symbols(data,**options)
        if _digest(data)!=digest:
            raise CoreError('COFF evidence changed during inspection')
        result.update(input_sha256=digest,input_bytes=len(data),tools={})
    if llvm_bin is not None and sys.platform!='linux':
        raise CoreError('LLVM demangling backend currently requires Linux')
    directory=_path(llvm_bin) if llvm_bin is not None else None
    with tempfile.TemporaryDirectory(prefix='cyber-coff-tools-') as folder:
        scratch=Path(folder)
        env={'PATH':'/usr/bin:/bin','HOME':str(scratch),'TMPDIR':str(scratch),
             'LANG':'C.UTF-8','LC_ALL':'C.UTF-8'}
        for symbol in result['symbols']:
            name=symbol['name']
            symbol.update(display_name=name,demangle_status='not_mangled')
            tool='llvm-undname' if name.startswith('?') else 'llvm-cxxfilt' if name.startswith(('_Z','__Z')) else None
            if tool is None:
                continue
            symbol['demangle_abi']='microsoft' if tool=='llvm-undname' else 'itanium'
            if symbol['name_truncated']:
                symbol['demangle_status']='skipped_truncated'
                continue
            if any(ord(c)<32 or ord(c)==127 for c in name) or name.encode('utf-8').hex()!=symbol['name_raw_hex']:
                symbol['demangle_status']='unsupported_name_encoding'
            elif directory is None:
                symbol['demangle_status']='not_requested'
            else:
                executable=directory/tool
                try:
                    if tool not in result['tools']:
                        if not executable.is_file() or executable.stat().st_size>128*1024*1024:
                            raise CoreError('LLVM tool unavailable or oversized')
                        version=_run([executable,'--version'],scratch,env,deadline)
                        digest=hashlib.sha256()
                        with executable.open('rb') as stream:
                            for block in iter(lambda:stream.read(65536),b''):
                                digest.update(block)
                        result['tools'][tool]={'path':str(executable),'version':version.strip()[:512],
                                               'sha256':digest.hexdigest()}
                    query=name[1:] if name.startswith('__Z') else name
                    output=_run([executable,query],scratch,env,deadline)
                    lines=[line for line in output.splitlines() if line]
                    if tool=='llvm-undname':
                        if len(lines)!=2 or lines[0]!=query:
                            raise CoreError('Unexpected LLVM undecorator output')
                        display=lines[1]
                    else:
                        if len(lines)!=1:
                            raise CoreError('Unexpected LLVM demangler output')
                        display=lines[0]
                    if display==query or not display or len(display)>2048 or any(ord(c)<32 for c in display):
                        raise CoreError('LLVM did not return a supported demangled name')
                    symbol.update(display_name=display,demangle_status='demangled')
                except (CoreError,OSError):
                    symbol['demangle_status']='failed'
            if symbol['demangle_status'] not in ('demangled','not_mangled'):
                if result['status']=='completed':
                    result['status']='partial'
    return result

def _encode(result, output_bytes=1048576):
    bounded={**result,'symbols':list(result['symbols']),'output_truncated':False,
             'output_symbols_omitted':0,'output_bytes_limit':output_bytes}
    while True:
        text=json.dumps(bounded,ensure_ascii=True)
        if len(text.encode('utf-8'))+1<=output_bytes:
            return text
        if not bounded['symbols']:
            raise CoreError('COFF metadata exceeds output budget')
        bounded['symbols'].pop()
        bounded.update(status='partial',symbols_truncated=True,output_truncated=True)
        bounded['output_symbols_omitted']+=1

def analyze_symbols(core, case, path, *, llvm_bin=None, max_symbols=128,
                    max_records=100000, max_name_bytes=512, output_bytes=1048576):
    from cyber_core.agents.runner import run_bounded
    from cyber_core.operations import save_operation
    from cyber_core.verification.artifacts import verified_result
    from cyber_core.reverse_engineering.coff import read_symbols
    from cyber_core.reverse_engineering.external import _path
    options=dict(max_symbols=max_symbols,max_records=max_records,max_name_bytes=max_name_bytes)
    read_symbols(b'',**options) # Validate budgets before acquisition.
    if type(output_bytes) is not int or not 4096<=output_bytes<=1048576:
        raise CoreError('Invalid COFF output byte budget')
    if llvm_bin is not None:
        llvm_bin=str(_path(llvm_bin))
        if sys.platform!='linux':
            raise CoreError('LLVM demangling backend currently requires Linux')
    def stopped():
        return bool(core.authorize(case)['paused'])
    if stopped():
        raise CoreError('Investigation is paused')
    task=core.enqueue(case,path)
    core.run_one(case,task_id=task)
    evidence,_=verified_result(core,case,task)
    request=dict(source=evidence['copy'],expected_sha256=evidence['sha256'],max_bytes=core.max_bytes,
                 timeout=core.timeout,options=options,llvm_bin=llvm_bin,output_bytes=output_bytes)
    with tempfile.TemporaryDirectory(prefix='cyber-coff-') as folder:
        response=run_bounded([sys.executable,'-I',str(Path(__file__).with_name('coff_child.py'))],
                             json.dumps(request),cwd=folder,timeout=core.timeout,
                             max_output=output_bytes,should_stop=stopped,env={})
        result=json.loads(response['stdout'])
        if not isinstance(result,dict) or result.get('input_sha256')!=evidence['sha256']:
            raise CoreError('COFF analysis evidence mismatch')
        verified_result(core,case,task)
        return save_operation(core,case,'coff_symbols',
                              {'evidence':evidence,'parameters':{**options,'output_bytes':output_bytes},
                               'analysis':result})
