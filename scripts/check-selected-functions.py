"""Real selected Ghidra analysis through CORE; generated ELF is never executed."""
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
from cyber_core.service import Core

def main():
    from cyber_core.reverse_engineering.selected import analyze_functions
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        source = root / 'fixture.c'
        source.write_text('volatile int fixture_value = 37;\n'
                          '__attribute__((noinline)) int fixture_helper(int x){return x+5;}\n'
                          '__attribute__((noinline)) int fixture_target(void){return fixture_helper(fixture_value);}\n'
                          '__attribute__((noinline)) int fixture_other(void){return 99;}\n')
        binary = root / 'fixture.elf'
        subprocess.run(['gcc','-g','-O0','-fno-pie','-no-pie','-nostdlib',
                        '-Wl,-e,fixture_target','-o',str(binary),str(source)],check=True,timeout=30)
        symbols = subprocess.check_output(['nm','-n',str(binary)],text=True)
        address = int(next(line.split()[0] for line in symbols.splitlines() if line.endswith(' fixture_target')),16)
        before = hashlib.sha256(binary.read_bytes()).hexdigest()
        core = Core(root / 'store',timeout=180)
        try:
            case = core.investigate('lab','Selected static functions',str(root),'owner','Synthetic fixtures only')
            options = dict(ghidra_home=os.environ['CYBER_GHIDRA_HOME'],java_home=os.environ['JAVA_HOME'])
            first = analyze_functions(core,case,binary,names=['fixture_target'],**options)
            result = first['analysis']
            assert result['status'] == 'completed', result
            assert len(result['functions']) == 1, result
            function = result['functions'][0]
            assert function['name'] == 'fixture_target', function
            assert any(r['call'] and r['direction']=='outgoing' for r in function['references']), function
            assert any(not r['call'] and r['direction']=='outgoing' for r in function['references']), function
            assert function['pseudocode'] and 'pseudocode' in result['interpretation']
            second = analyze_functions(core,case,binary,addresses=[address],ranges=[[address,address+1]],**options)
            assert len(second['analysis']['functions']) == 1
            assert second['analysis']['functions'][0]['name'] == 'fixture_target'
            assert core.verify_audit(case)
            assert 'selected_functions' in core.report(case).read_text()
            assert hashlib.sha256(binary.read_bytes()).hexdigest() == before
        finally:
            core.close()
        print('Selected Ghidra: exact name, entry address/range, real calls/data references, CORE persistence; sample never executed')
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
