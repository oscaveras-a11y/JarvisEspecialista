"""Authorized static NSIS listing/extraction; examined binaries never run."""
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import shutil
import sys
import tempfile
from uuid import uuid4

from cyber_core.errors import CoreError

def safe_member(value):
    if (not isinstance(value, str) or not 1 <= len(value) <= 240 or
        value.startswith(('/', '-')) or any(ord(c) < 32 for c in value) or
        any(c in value for c in '\\:*?"<>|')):
        raise CoreError('Unsafe archive member')
    parts = value.split('/')
    for part in parts:
        if (not part or part in ('.', '..') or part.endswith(('.', ' ')) or
            part.split('.')[0].upper() in ('CON','PRN','AUX','NUL',*(f'COM{i}' for i in range(1,10)),*(f'LPT{i}' for i in range(1,10)))):
            raise CoreError('Unsafe archive member')
    return value

def parse_listing(text, max_entries, max_bytes):
    if '----------\n' not in text.replace('\r\n','\n'):
        raise CoreError('Unsupported 7-Zip listing')
    header, body = text.replace('\r\n','\n').split('----------\n', 1)
    if not re.search(r'^Type = Nsis\s*$', header, re.MULTILINE | re.IGNORECASE):
        raise CoreError('Input is not identified as NSIS by 7-Zip')
    result, seen = [], set()
    for block in body.strip().split('\n\n'):
        if not block.strip():
            continue
        fields = {}
        for line in block.splitlines():
            if ' = ' not in line:
                raise CoreError('Ambiguous archive listing')
            key, value = line.split(' = ', 1)
            if key in fields:
                raise CoreError('Duplicate archive listing field')
            fields[key] = value
        # 7-Zip uses host separators; a literal backslash on Unix is not accepted.
        name = safe_member(fields.get('Path'))
        key = name.casefold()
        if key in seen:
            raise CoreError('Archive member collision')
        seen.add(key)
        if any('link' in k.lower() for k in fields) or 'l' in fields.get('Attributes','').lower():
            raise CoreError('Archive links unsupported')
        folder = fields.get('Folder') == '+' or 'D' in fields.get('Attributes','')
        raw = fields.get('Size', '0' if folder else '')
        if raw == '' and 'Size' in fields and not folder:
            size = None  # NSIS solid streams may omit the last member size.
        elif raw.isascii() and raw.isdigit() and len(raw) <= 16:
            size = int(raw)
        else:
            raise CoreError('Invalid archive size')
        if (size is not None and size > max_bytes) or len(result) >= max_entries:
            raise CoreError('Archive listing resource limit')
        result.append({'member': name, 'size': size, 'folder': folder})
    return result

def selected_member(name):
    path = PurePosixPath(name)
    return name == 'VisionFT.exe' or (len(path.parts) == 2 and path.parts[0] == 'Firmwares' and path.suffix == '.vftw')

def file_hash(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        while block := stream.read(1024*1024):
            digest.update(block)
    return digest.hexdigest()

def inspect_installer(core, case, path, *, seven_zip, extract=False, max_extracted_bytes=1024*1024*1024,
                      max_entries=1000, memory_bytes=512*1024*1024):
    from cyber_core.agents.runner import run_bounded
    from cyber_core.operations import save_operation
    from cyber_core.permissions import storage_root
    from cyber_core.verification.artifacts import verified_result
    if sys.platform != 'linux':
        raise CoreError('NSIS backend currently requires Linux')
    for value, lower, upper in ((max_extracted_bytes,1,2*1024**3),(max_entries,1,1000),(memory_bytes,128*1024**2,2*1024**3)):
        if type(value) is not int or not lower <= value <= upper:
            raise CoreError('Invalid NSIS resource budget')
    if type(extract) is not bool or not Path(seven_zip).is_absolute() or not Path(seven_zip).is_file():
        raise CoreError('Trusted absolute 7-Zip executable required')
    def stopped():
        row = core.authorize(case)
        return bool(row['paused'])
    if stopped():
        raise CoreError('Investigation is paused')
    task = core.enqueue(case, path)
    core.run_one(case, task_id=task)
    evidence, _ = verified_result(core, case, task)
    folder = storage_root(core.home / 'cases' / case)
    stage = Path(tempfile.mkdtemp(prefix='nsis-stage-', dir=folder))
    final = folder / ('nsis-' + uuid4().hex)
    committed = False
    try:
        request = {'source': evidence['copy'], 'sha256': evidence['sha256'],
                   'seven_zip': str(Path(seven_zip).resolve()), 'stage': str(stage),
                   'extract': extract, 'max_entries': max_entries,
                   'max_extracted_bytes': max_extracted_bytes, 'memory_bytes': memory_bytes,
                   'timeout': core.timeout}
        response = run_bounded([sys.executable, '-I', str(Path(__file__).with_name('child.py'))],
                               json.dumps(request), cwd=stage, timeout=core.timeout,
                               max_output=1048576, should_stop=stopped, env={})
        result = json.loads(response['stdout'])
        if result.get('source_sha256') != evidence['sha256'] or type(result.get('extracted')) is not list:
            raise CoreError('Invalid NSIS result')
        verified_result(core, case, task)
        total = 0
        for item in result['extracted']:
            member = safe_member(item['member'])
            target = stage / member
            if not selected_member(member) or target.is_symlink() or not target.is_file():
                raise CoreError('Invalid extracted member')
            total += target.stat().st_size
            if total > max_extracted_bytes or target.stat().st_size != item['size'] or file_hash(target) != item['sha256']:
                raise CoreError('Extracted member verification failed')
            item['path'] = str(final / member)
        if stopped():
            raise CoreError('Investigation is paused')
        if extract:
            stage.rename(final)
        data = {'evidence': evidence, 'parameters': {k:v for k,v in request.items() if k not in ('source','stage')},
                'installer': result,
                'limitations': 'Static extraction only; no firmware interpretation or execution. Linux backend; monitored disk budget.'}
        # save_operation rechecks authorization in its write transaction.
        saved = save_operation(core, case, 'nsis_installer', data)
        committed = True
        return saved
    finally:
        shutil.rmtree(stage, ignore_errors=True)
        if not committed:
            shutil.rmtree(final, ignore_errors=True)
