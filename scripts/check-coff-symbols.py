"""Compile genuine Microsoft COFF C++ and inspect it without execution."""
import hashlib
from pathlib import Path
import subprocess
import tempfile
from cyber_core.service import Core

def main():
    from cyber_core.reverse_engineering.coff_operation import analyze_symbols
    with tempfile.TemporaryDirectory() as folder:
        root=Path(folder)
        source=root/'fixture.cpp'
        source.write_text('namespace Lab { int selected(int x) { return x+7; } }\n')
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
            assert result['tools']['llvm-undname']['version'],result
            assert len(result['tools']['llvm-undname']['sha256'])==64,result
            assert operation['evidence']['sha256']==digest
            assert core.verify_audit(case)
            assert 'coff_symbols' in core.report(case).read_text()
            assert hashlib.sha256(obj.read_bytes()).hexdigest()==digest
        finally:
            core.close()
        print('Real clang Microsoft COFF: symbol table, C++ demangling, CORE hashes/audit/report; object never executed')
    return 0

if __name__=='__main__':
    raise SystemExit(main())
