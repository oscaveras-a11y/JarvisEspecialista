"""Compile genuine Microsoft COFF C++ and inspect it without execution."""
import hashlib
from pathlib import Path
import subprocess
import tempfile
import sys
from cyber_core.service import Core

def main():
    from cyber_core.reverse_engineering.coff_operation import analyze_symbols
    with tempfile.TemporaryDirectory() as folder:
        root=Path(folder)
        source=root/'fixture.cpp'
        source.write_text('int uninitialized; namespace Lab { int selected(int x) { return x+7; } }\n')
        obj=root/'fixture.obj'
        subprocess.run(['/usr/bin/clang++-18','--target=x86_64-pc-windows-msvc','-g0','-O0',
                        '-c',str(source),'-o',str(obj)],check=True,timeout=30)
        digest=hashlib.sha256(obj.read_bytes()).hexdigest()
        core=Core(root/'store',timeout=120)
        try:
            case=core.investigate('lab','COFF static symbols',str(root),'owner','Synthetic fixtures only')
            operation=analyze_symbols(core,case,obj,llvm_bin='/usr/lib/llvm-18/bin')
            result=operation['analysis']
            assert result['status']=='completed',result
            matches=[s for s in result['symbols'] if s['name']=='?selected@Lab@@YAHH@Z']
            assert len(matches)==1,result
            symbol=matches[0]
            assert symbol['demangle_status']=='demangled',symbol
            assert 'Lab::selected(int)' in symbol['display_name'],symbol
            assert symbol['virtual_address'] is None and symbol['section_number']>0,symbol
            bss=[s for s in result['symbols'] if s['name']=='?uninitialized@@3HA']
            assert len(bss)==1 and bss[0]['file_offset'] is None,bss
            assert result['tools']['llvm-undname']['version'],result
            assert len(result['tools']['llvm-undname']['sha256'])==64,result
            assert operation['evidence']['sha256']==digest
            gnu=root/'fixture-gnu.obj'
            subprocess.run(['/usr/bin/clang++-18','--target=x86_64-w64-windows-gnu','-g0','-O0',
                            '-c',str(source),'-o',str(gnu)],check=True,timeout=30)
            gnu_result=analyze_symbols(core,case,gnu,llvm_bin='/usr/lib/llvm-18/bin')['analysis']
            assert gnu_result['status']=='completed',gnu_result
            gnu_matches=[s for s in gnu_result['symbols'] if s['name']=='_ZN3Lab8selectedEi']
            assert len(gnu_matches)==1 and gnu_matches[0]['display_name']=='Lab::selected(int)',gnu_result
            assert gnu_matches[0]['demangle_status']=='demangled',gnu_matches
            assert gnu_result['tools']['llvm-cxxfilt']['version'],gnu_result
            sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tests'))
            from test_coff_symbols import fixture
            malformed,_=fixture()
            strings=len(malformed)-len(b'?selected@Lab@@YAHH@Z')-1
            malformed[strings:-1]=b'?'+b'X'*(len(malformed)-strings-2)
            bad=root/'invalid-decorated-name.obj'
            bad.write_bytes(malformed)
            failed=analyze_symbols(core,case,bad,llvm_bin='/usr/lib/llvm-18/bin')['analysis']
            assert failed['status']=='partial',failed
            invalid=[s for s in failed['symbols'] if s['name'].startswith('?')]
            assert len(invalid)==1 and invalid[0]['demangle_status']=='failed',failed
            assert invalid[0]['display_name']==invalid[0]['name'],invalid
            assert core.verify_audit(case)
            assert 'coff_symbols' in core.report(case).read_text()
            assert hashlib.sha256(obj.read_bytes()).hexdigest()==digest
        finally:
            core.close()
        print('Real clang Microsoft COFF: symbol table, C++ demangling, CORE hashes/audit/report; object never executed')
    return 0

if __name__=='__main__':
    raise SystemExit(main())
