"""Supervised and audited static Qt scans; no Qt runtime is loaded."""
import json
from pathlib import Path
import sys
import tempfile
import time
from cyber_core.errors import CoreError
from cyber_core.reverse_engineering.qt_budget import bounded_size, compact_qml

def _validate(options):
    ranges={'max_candidates':(1,128),'max_entries':(1,10000),
            'max_resource_bytes':(1,67108864),'max_decoded_bytes':(248,268435456),
            'max_unit_bytes':(248,67108864),'max_ratio':(1,10000),
            'output_bytes':(4096,1048576),'memory_bytes':(268435456,8589934592)}
    if set(options)!=set(ranges):
        raise CoreError('Invalid Qt analysis budget schema')
    for key,(minimum,maximum) in ranges.items():
        value=options[key]
        if type(value) is not int or not minimum<=value<=maximum:
            raise CoreError('Invalid Qt analysis budget: '+key)
    if max(options['max_resource_bytes'],options['max_unit_bytes'])>options['max_decoded_bytes']:
        raise CoreError('Qt per-resource/unit budget exceeds aggregate budget')
    return dict(options)

def _scan(data, options, deadline):
    from cyber_core.reverse_engineering.qt import inspect_rcc, inspect_qml_unit
    result={'status':'no_candidates','decoder_version':'qt-static-1','python_version':sys.version.split()[0],
            'rcc':[],'qml_units':[],'candidates':[],'candidate_scan_truncated':False,
            'interpretation':'Static bounded candidates and partial layout decoding; not original QML or proof of execution/authenticity.'}
    signatures=(b'qres',b'qv4cdata')
    positions=[data.find(signature) for signature in signatures]
    work=0
    detail_bytes=0
    candidates=0
    while any(pos>=0 for pos in positions):
        if candidates>=options['max_candidates']:
            result['candidate_scan_truncated']=True
            break
        if time.monotonic()>=deadline:
            raise CoreError('Qt analysis shared deadline exceeded')
        kind=min((i for i in range(2) if positions[i]>=0),key=lambda i:positions[i])
        at=positions[kind]
        positions[kind]=data.find(signatures[kind],at+len(signatures[kind]))
        candidates+=1
        candidate={'offset':at,'kind':'rcc' if kind==0 else 'qml_unit'}
        remaining=options['max_decoded_bytes']-work
        try:
            if remaining<248:
                raise CoreError('Qt aggregate interpretation byte budget exhausted')
            if kind==0:
                parsed=inspect_rcc(data,at,max_entries=options['max_entries'],
                                   max_resource_bytes=options['max_resource_bytes'],
                                   max_decoded_bytes=remaining,max_ratio=options['max_ratio'],
                                   max_result_bytes=min(524288,options['output_bytes']),max_unit_bytes=options['max_unit_bytes'])
                work+=max(parsed.get('decoded_bytes',0),parsed.get('stored_bytes',0))
                target='rcc'
            else:
                parsed=inspect_qml_unit(data,at,max_entries=options['max_entries'],
                                        max_unit_bytes=min(remaining,options['max_unit_bytes']))
                work+=parsed['size_bytes']
                target='qml_units'
            candidate['status']=parsed['status']
            room=max(0,options['output_bytes']-4096-detail_bytes)
            size=bounded_size(parsed,room)
            if size is None:
                if kind==1:
                    parsed=compact_qml(parsed)
                else:
                    parsed={key:parsed[key] for key in ('offset','format_version','entry_count','resource_count',
                                                        'decoded_bytes','stored_bytes') if key in parsed} | {
                            'status':'partial','detail_omitted':True,'resources':[],'resources_truncated':True}
                size=bounded_size(parsed,max(0,options['output_bytes']-2048-detail_bytes))
            if size is not None:
                result[target].append(parsed)
                detail_bytes+=size+1
            else:
                candidate['detail_omitted']=True
        except CoreError as exc:
            candidate.update(status='candidate_unparsed',reason=str(exc)[:256])
        result['candidates'].append(candidate)
    result.update(candidate_count=candidates,interpreted_bytes=work,
                  status='partial' if candidates or result['candidate_scan_truncated'] else 'no_candidates')
    return result

def _encode(result, *, output_bytes=1048576):
    if type(output_bytes) is not int or not 4096<=output_bytes<=1048576:
        raise CoreError('Invalid Qt output byte budget')
    bounded={**result,'rcc':list(result['rcc']),'qml_units':list(result['qml_units']),
             'candidates':list(result['candidates']),'output_truncated':False,
             'output_rcc_omitted':0,'output_qml_units_omitted':0,'output_candidates_omitted':0,
             'output_bytes_limit':output_bytes}
    while bounded_size(bounded,output_bytes-1) is None:
        for field in ('qml_units','rcc','candidates'):
            if bounded[field]:
                bounded[field].pop()
                bounded['output_'+field+'_omitted']+=1
                bounded.update(output_truncated=True,status='partial')
                break
        else:
            raise CoreError('Qt metadata exceeds output budget')
    return ''.join(json.JSONEncoder(ensure_ascii=True,allow_nan=False).iterencode(bounded))

def _inspect(source, expected_sha256, max_bytes, timeout, options):
    from cyber_core.firmware import _mapped, _digest
    options=_validate(options)
    applied=False
    if sys.platform=='linux':
        import resource
        resource.setrlimit(resource.RLIMIT_AS,(options['memory_bytes'],options['memory_bytes']))
        applied=True
    deadline=time.monotonic()+timeout
    with _mapped(source,max_bytes) as data:
        digest=_digest(data)
        if digest!=expected_sha256:
            raise CoreError('Qt evidence mismatch')
        result=_scan(data,options,deadline)
        if _digest(data)!=digest:
            raise CoreError('Qt evidence changed during interpretation')
        result.update(input_sha256=digest,input_bytes=len(data),
                      memory_limit={'address_space_bytes':options['memory_bytes'],'hard_limit_applied':applied,
                                    'scope':'Linux child address space including mapping; not aggregate RSS'})
    return result

def analyze_qt(core, case, path, *, max_candidates=32, max_entries=4096,
               max_resource_bytes=8388608, max_decoded_bytes=67108864,max_unit_bytes=33554432,
               max_ratio=200,output_bytes=1048576,memory_bytes=2147483648):
    from cyber_core.agents.runner import run_bounded
    from cyber_core.operations import save_operation
    from cyber_core.verification.artifacts import verified_result
    options=_validate(dict(max_candidates=max_candidates,max_entries=max_entries,
                           max_resource_bytes=max_resource_bytes,max_decoded_bytes=max_decoded_bytes,
                           max_unit_bytes=max_unit_bytes,max_ratio=max_ratio,output_bytes=output_bytes,
                           memory_bytes=memory_bytes))
    def stopped():
        return bool(core.authorize(case)['paused'])
    if stopped():
        raise CoreError('Investigation is paused')
    task=core.enqueue(case,path)
    core.run_one(case,task_id=task)
    evidence,_=verified_result(core,case,task)
    request=dict(source=evidence['copy'],expected_sha256=evidence['sha256'],max_bytes=core.max_bytes,
                 timeout=core.timeout,options=options)
    with tempfile.TemporaryDirectory(prefix='cyber-qt-') as folder:
        response=run_bounded([sys.executable,'-I',str(Path(__file__).with_name('qt_child.py'))],
                             json.dumps(request),cwd=folder,timeout=core.timeout,
                             max_output=output_bytes,should_stop=stopped,env={})
        result=json.loads(response['stdout'])
        if not isinstance(result,dict) or result.get('input_sha256')!=evidence['sha256']:
            raise CoreError('Qt analysis evidence mismatch')
        verified_result(core,case,task)
        return save_operation(core,case,'qt_resources',
                              {'evidence':evidence,'parameters':options,'analysis':result})
