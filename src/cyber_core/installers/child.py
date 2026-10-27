"""Trusted bounded 7-Zip worker. Must run under the CORE process-tree supervisor."""
import json
import os
from pathlib import Path
import resource
import stat
import subprocess
import sys
import threading
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from cyber_core.installers import parse_listing, selected_member, file_hash
from cyber_core.errors import CoreError

def run(command, root, deadline, maximum, memory_bytes, destination=None):
    buffers, errors = bytearray(), bytearray()
    failed = threading.Event()
    count = [0]
    env = {'PATH':'/usr/bin:/bin','LANG':'C.UTF-8','LC_ALL':'C.UTF-8',
           'HOME':str(root),'TMPDIR':str(root)}
    def limits():
        resource.setrlimit(resource.RLIMIT_AS, (memory_bytes, memory_bytes))
        resource.setrlimit(resource.RLIMIT_CORE, (0,0))
    process = subprocess.Popen(command, cwd=root, env=env, stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, preexec_fn=limits,
                               shell=False)
    def read_output():
        try:
            with (destination.open('xb') if destination else __import__('contextlib').nullcontext(None)) as target:
                while block := process.stdout.read(65536):
                    count[0] += len(block)
                    if count[0] > maximum:
                        failed.set()
                        return
                    if target:
                        target.write(block)
                    else:
                        buffers.extend(block)
        except (OSError, ValueError):
            failed.set()
    def read_errors():
        try:
            while block := process.stderr.read(4096):
                if len(errors) + len(block) > 65536:
                    failed.set()
                    return
                errors.extend(block)
        except (OSError, ValueError):
            failed.set()
    readers = [threading.Thread(target=read_output), threading.Thread(target=read_errors)]
    for reader in readers:
        reader.start()
    try:
        while process.poll() is None:
            if failed.is_set() or time.monotonic() >= deadline:
                raise CoreError('NSIS process budget exceeded')
            size, entries = 0, 0
            for item in root.rglob('*'):
                entries += 1
                try:
                    info = item.lstat()
                except FileNotFoundError:
                    continue
                if stat.S_ISLNK(info.st_mode) or entries > 3000:
                    raise CoreError('NSIS scratch entry limit exceeded')
                size += info.st_size if stat.S_ISREG(info.st_mode) else 0
                if size > 2*1024**3:
                    raise CoreError('NSIS scratch disk limit exceeded')
            time.sleep(.02)
        for reader in readers:
            reader.join(timeout=2)
        if failed.is_set() or any(r.is_alive() for r in readers) or process.returncode or time.monotonic() >= deadline:
            raise CoreError('NSIS tool failed or exceeded budget')
        return bytes(buffers), count[0]
    finally:
        if process.poll() is None:
            process.kill()
        process.wait(timeout=3)
        for stream in (process.stdout, process.stderr):
            stream.close()
        for reader in readers:
            reader.join(timeout=2)

def execute(data):
    source, root, executable = Path(data['source']), Path(data['stage']), data['seven_zip']
    deadline = time.monotonic() + data['timeout']
    if file_hash(source) != data['sha256']:
        raise CoreError('NSIS input hash mismatch')
    listing, _ = run([executable,'l','-slt','-sccUTF-8','--',str(source)],root,deadline,524288,
                     data['memory_bytes'])
    text = listing.decode('utf-8', errors='strict')
    entries = parse_listing(text, data['max_entries'], 2*1024**3)
    selected = [item for item in entries if not item['folder'] and selected_member(item['member'])]
    if data['extract'] and not selected:
        raise CoreError('No supported members selected')
    if data['extract'] and sum(item['size'] for item in selected) > data['max_extracted_bytes']:
        raise CoreError('Selected extraction exceeds budget')
    output, total = [], 0
    if data['extract']:
        for item in selected:
            name = item['member']
            destination = root / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            _, size = run([executable,'x','-so','-spd','-y','--',str(source),name],
                          root,deadline,data['max_extracted_bytes']-total,
                          data['memory_bytes'],destination)
            total += size
            if size != item['size']:
                raise CoreError('Extracted size differs from listing')
            output.append({'member':name,'size':size,'sha256':file_hash(destination),
                           'origin_sha256':data['sha256']})
    if file_hash(source) != data['sha256']:
        raise CoreError('NSIS source changed')
    version = next((line.strip() for line in text.splitlines() if '7-Zip' in line), 'unknown')[:256]
    return {'format':'nsis','source_sha256':data['sha256'],'tool_version':version,
            'tool_sha256':file_hash(executable),'members':entries,'selected':selected,'extracted':output,
            'status':'extracted' if data['extract'] else 'listed','executed_input':False}

def main():
    try:
        raw = sys.stdin.buffer.read(16385)
        if len(raw) > 16384:
            raise CoreError('NSIS request too large')
        result = execute(json.loads(raw))
        payload = json.dumps(result, ensure_ascii=True)
        if len(payload.encode()) > 1000000:
            raise CoreError('NSIS result too large')
        print(payload)
        return 0
    except Exception:
        # No evidence-derived errors, names or tool output in public diagnostics.
        print('{"error":"nsis_static_operation_failed"}')
        return 2

if __name__ == '__main__':
    raise SystemExit(main())
