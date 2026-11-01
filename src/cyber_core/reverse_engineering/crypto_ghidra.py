"""Trusted bounded Ghidra reference adapter; sample names and pseudocode never exported."""
import json
from pathlib import Path
import sys
import tempfile
import time
from cyber_core.errors import CoreError
from cyber_core.reverse_engineering.crypto_rules import APIS
from cyber_core.reverse_engineering.crypto_structures import file_offset
from cyber_core.reverse_engineering.external import _path,_run,_read_json,GHIDRA_VERSION

def references(path,fmt,meta,findings,ghidra_home,java_home,deadline):
    if fmt not in ('elf','pe'):return [],{'status':'unsupported_format'}
    if sys.platform!='linux':return [],{'status':'unsupported_platform'}
    home=_path(ghidra_home);java=_path(java_home)
    executable=home/'support'/'analyzeHeadless'
    if not executable.is_file() or not (java/'bin'/'java').is_file():
        return [],{'status':'dependency_unavailable'}
    props=home/'Ghidra'/'application.properties'
    if not props.is_file() or props.stat().st_size>65536 or (
        'application.version='+GHIDRA_VERSION) not in props.read_text().splitlines():
        return [],{'status':'failed','reason':'unsupported_backend_version'}
    targets=[{'address':str(f['virtual_address']),'rule':f['rule']} for f in findings
             if f.get('virtual_address') is not None and f['kind'] in ('constant','symbol')]
    allowed={f['rule'] for f in targets}|{'api.'+name+'.v1' for name in APIS}
    with tempfile.TemporaryDirectory(prefix='cyber-crypto-ghidra-') as folder:
        scratch=Path(folder);(scratch/'home').mkdir()
        env={'PATH':'/usr/bin:/bin','HOME':str(scratch/'home'),'TMPDIR':str(scratch),
             'LANG':'C.UTF-8','LC_ALL':'C.UTF-8','JAVA_HOME':str(java),'GHIDRA_HEADLESS_MAXMEM':'1G'}
        options=scratch/'targets.json';output=scratch/'result.json'
        options.write_text(json.dumps({'targets':targets,'apis':list(APIS)}))
        loader=['-loader','ElfLoader' if fmt=='elf' else 'PeLoader','-loader-loadLibraries','false']
        if fmt=='elf':loader+=['-loader-applyRelocations','false']
        command=[executable,scratch,'Crypto','-import',path,*loader,'-readOnly',
                 '-scriptPath',Path(__file__).with_name('ghidra_scripts'),
                 '-postScript','ExportCrypto.java',output,options,
                 '-analysisTimeoutPerFile',str(max(1,min(120,int(deadline-time.monotonic())-5))),
                 '-max-cpu','1','-log',scratch/'application.log','-scriptlog',scratch/'script.log']
        try:
            _run(command,scratch,env,deadline)
            raw=_read_json(output)
        except (CoreError,OSError):
            return [],{'status':'failed','reason':'trusted_static_backend_failed'}
    if not isinstance(raw,dict) or raw.get('backend_version')!=GHIDRA_VERSION:
        raise CoreError('Invalid crypto Ghidra schema')
    rows=raw.get('references')
    if not isinstance(rows,list) or len(rows)>256 or any(type(raw.get(k)) is not bool for k in ('truncated','analysis_timed_out')):
        raise CoreError('Invalid crypto Ghidra result budget')
    output=[]
    for row in rows:
        if not isinstance(row,dict) or row.get('rule') not in allowed:raise CoreError('Unexpected crypto reference rule')
        try:
            origin=int(row['from'],16);function=int(row['function'],16)
            offset=file_offset(meta,fmt,origin)
            file_offset(meta,fmt,function)
        except (KeyError,ValueError,TypeError,CoreError):
            raise CoreError('Crypto Ghidra reference outside file-backed mapping') from None
        target=row.get('target')
        if not isinstance(target,str) or len(target)>64:raise CoreError('Invalid crypto target')
        # Target external API may live in Ghidra EXTERNAL address space. Its
        # supplied allowlist rule, not that synthetic address, identifies API.
        if row['rule'].startswith('api.'):
            target_address=None
        else:
            try:target_address=int(target,16);file_offset(meta,fmt,target_address)
            except (ValueError,CoreError):raise CoreError('Invalid crypto constant target') from None
            if not any(t['rule']==row['rule'] and int(t['address'])==target_address for t in targets):
                raise CoreError('Ghidra constant target differs from verified signature')
        output.append(dict(kind='static_reference',rule=row['rule'],family='static crypto reference',
                           strength='static_reference',offset=offset,virtual_address=origin,
                           function_address=function,target_address=target_address,
                           decoded_address=None,source_record_offset=None))
    return output,{'status':'partial' if raw['truncated'] or raw['analysis_timed_out'] else 'completed',
                   'backend_version':GHIDRA_VERSION,'references':len(output),
                   'analysis_timed_out':raw['analysis_timed_out'],'references_truncated':raw['truncated']}
