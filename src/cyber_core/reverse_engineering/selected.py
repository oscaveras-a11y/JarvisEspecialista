"""Bounded targeted Ghidra selection and audited CORE operation."""
import json
from pathlib import Path
import sys
import tempfile

from cyber_core.errors import CoreError

def selection(*, names=None, addresses=None, ranges=None, max_functions=8, max_references=64,
              decompile_seconds=5, analysis_seconds=30, pseudocode_chars=4096, max_scan_instructions=10000, output_bytes=1048576):
    names, addresses, ranges = names or [], addresses or [], ranges or []
    if any(not isinstance(v, (list, tuple)) or len(v) > 32 for v in (names, addresses, ranges)):
        raise CoreError('Invalid function selectors')
    if not (names or addresses or ranges):
        raise CoreError('Explicit function selection required')
    if any(not isinstance(n, str) or not 1 <= len(n) <= 256 or any(ord(c)<32 for c in n) for n in names):
        raise CoreError('Invalid function name')
    def address(v):
        return type(v) is int and 0 <= v < 2**64
    if any(not address(v) for v in addresses) or any(
        not isinstance(v,(list,tuple)) or len(v)!=2 or not all(address(a) for a in v) or v[0]>=v[1] for v in ranges):
        raise CoreError('Invalid function address or half-open entry range')
    for value, maximum, minimum in ((max_functions,128,1),(max_references,512,1),(decompile_seconds,60,1),
                                    (analysis_seconds,600,1),(pseudocode_chars,8192,256),(max_scan_instructions,100000,1),(output_bytes,1048576,4096)):
        if type(value) is not int or not minimum <= value <= maximum:
            raise CoreError('Invalid selected-analysis budget')
    if max_functions*(pseudocode_chars + max_references*640 + 1024) > 850000:
        raise CoreError('Selected-analysis combined result budget too large')
    result = dict(names=list(dict.fromkeys(names)), addresses=list(dict.fromkeys(addresses)),
                  ranges=[list(v) for v in ranges], max_functions=max_functions, max_references=max_references,
                  decompile_seconds=decompile_seconds, analysis_seconds=analysis_seconds,
                  pseudocode_chars=pseudocode_chars, max_scan_instructions=max_scan_instructions, output_bytes=output_bytes)
    if len(json.dumps(result,ensure_ascii=True).encode()) > 8192:
        raise CoreError('Selected-analysis request too large')
    return result

def normalize(raw, options):
    from cyber_core.reverse_engineering.external import _ghidra_result
    if not isinstance(raw,dict) or not isinstance(raw.get('functions'),list) or len(raw['functions'])>options['max_functions']:
        raise CoreError('Invalid selected Ghidra functions')
    functions = []
    # Reuse the legacy validated metadata schema in bounded eight-record batches.
    base = _ghidra_result({**raw,'functions':[]})
    for start in range(0,len(raw['functions']),8):
        functions.extend(_ghidra_result({**raw,'functions':raw['functions'][start:start+8]})['functions'])
    for clean, original in zip(functions, raw['functions']):
        refs = original.get('references')
        if not isinstance(refs,list) or len(refs)>options['max_references'] or len(clean['pseudocode'])>options['pseudocode_chars']:
            raise CoreError('Invalid selected Ghidra references')
        clean['references'] = []
        for ref in refs:
            if not isinstance(ref,dict) or ref.get('direction') not in ('incoming','outgoing') or type(ref.get('call')) is not bool:
                raise CoreError('Invalid Ghidra reference type')
            for field, maximum in (('from',64),('to',64),('type',64),('symbol',256)):
                if not isinstance(ref.get(field),str) or len(ref[field])>maximum or any(ord(c)<32 for c in ref[field]):
                    raise CoreError('Invalid Ghidra reference text')
            clean['references'].append({key:ref[key] for key in ('from','to','type','symbol','direction','call')})
        if type(original.get('references_truncated')) is not bool:
            raise CoreError('Invalid Ghidra reference truncation')
        clean['references_truncated'] = original['references_truncated']
    for field in ('selection_scan_truncated',):
        if type(raw.get(field)) is not bool:
            raise CoreError('Invalid selected scan metadata')
    for field in ('visited_functions','matched_functions'):
        if type(raw.get(field)) is not int or not 0 <= raw[field] <= 100000:
            raise CoreError('Invalid selected function count')
    matches = raw.get('name_matches')
    if not isinstance(matches,dict) or set(matches)!=set(options['names']) or any(type(v) is not int or not 0 <= v <=100000 for v in matches.values()):
        raise CoreError('Invalid selected name-match counts')
    return {**base,'functions':functions,'selection_scan_truncated':raw['selection_scan_truncated'],
            'visited_functions':raw['visited_functions'],'matched_functions':raw['matched_functions'],
            'name_matches':matches,'interpretation':'Ghidra-generated pseudocode and static reference model; not recovered original source or proof of runtime behavior.'}

def encode_result(result, *, output_bytes=1048576):
    """Limit serialized bytes, including JSON escaping and the trailing newline.

    Complete function records are omitted from the tail when needed. The caller
    retains match counts and explicit partial/truncation metadata for persistence.
    """
    if type(output_bytes) is not int or not 4096 <= output_bytes <= 1048576:
        raise CoreError('Invalid selected-analysis output byte budget')
    if not isinstance(result,dict):
        raise CoreError('Invalid selected-analysis output')
    bounded = {**result,'output_bytes_limit':output_bytes,'output_truncated':False,
               'output_functions_omitted':0}
    if 'functions' in result:
        if not isinstance(result['functions'],list):
            raise CoreError('Invalid selected-analysis function output')
        bounded['functions'] = list(result['functions'])
    while True:
        encoded = json.dumps(bounded,ensure_ascii=True)
        if len(encoded.encode('utf-8')) + 1 <= output_bytes:
            return encoded
        if not bounded.get('functions'):
            raise CoreError('Selected-analysis metadata exceeds output byte budget')
        bounded['functions'].pop()
        bounded['output_functions_omitted'] += 1
        bounded.update(output_truncated=True,functions_truncated=True,status='partial')

def analyze_functions(core, case, path, *, ghidra_home, java_home, **selectors):
    from cyber_core.agents.runner import run_bounded
    from cyber_core.operations import save_operation
    from cyber_core.verification.artifacts import verified_result
    from cyber_core.reverse_engineering.external import _config
    if sys.platform != 'linux':
        raise CoreError('Selected Ghidra backend currently requires Linux')
    options = selection(**selectors)
    config = _config({'ghidra':{'home':ghidra_home,'java_home':java_home}})
    def stopped():
        return bool(core.authorize(case)['paused'])
    if stopped():
        raise CoreError('Investigation is paused')
    task = core.enqueue(case,path)
    core.run_one(case,task_id=task)
    evidence, _ = verified_result(core,case,task)
    with tempfile.TemporaryDirectory(prefix='cyber-functions-') as scratch:
        request = {'source':evidence['copy'],'sha256':evidence['sha256'],'max_bytes':core.max_bytes,
                   'timeout':core.timeout,'selection':options,
                   'config':{key:{k:str(v) for k,v in fields.items()} for key,fields in config.items()}}
        response = run_bounded([sys.executable,'-I',str(Path(__file__).with_name('selected_child.py'))],
                               json.dumps(request),cwd=scratch,timeout=core.timeout,max_output=options['output_bytes'],
                               should_stop=stopped,env={})
        result = json.loads(response['stdout'])
        if not isinstance(result,dict) or result.get('input_sha256')!=evidence['sha256']:
            raise CoreError('Selected analysis evidence mismatch')
        verified_result(core,case,task)
        return save_operation(core,case,'selected_functions',
                              {'evidence':evidence,'selection':options,'tools':request['config'],'analysis':result})
