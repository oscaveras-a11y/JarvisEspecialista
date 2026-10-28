"""Generate real Qt 6.8.3 RCC/QML fixtures; never execute the compiled QML."""
import hashlib
import importlib
import os
from pathlib import Path
import struct
import subprocess
import tempfile
from cyber_core.service import Core

def main():
    sdk=Path(os.environ['QT_FIXTURE_ROOT'])
    rcc=next(sdk.rglob('rcc'))
    cachegen=next(sdk.rglob('qmlcachegen'))
    env=dict(os.environ)
    env['LD_LIBRARY_PATH']=str(cachegen.parent.parent/'lib')
    with tempfile.TemporaryDirectory() as folder:
        root=Path(folder)
        qml=root/'fixture.qml'
        qml.write_text('import QtQml\nQtObject {\n'
                       ' property int value: 37\n'
                       ' property real ratio: 1.25\n'
                       ' property string mode: "synthetic-mode"\n'
                       ' property string label: qsTr("Laboratory only")\n'
                       ' property bool enabled: true\n}\n')
        compiled=root/'fixture.qmlc'
        subprocess.run([str(cachegen),'--only-bytecode','-o',str(compiled),str(qml)],
                       env=env,check=True,timeout=60)
        qrc=root/'fixture.qrc'
        qrc.write_text('<RCC><qresource prefix="/lab"><file>fixture.qmlc</file></qresource></RCC>')
        binary=root/'fixture.rcc'
        subprocess.run([str(rcc),'--binary','--format-version','3','--compress-algo','zlib',
                        '--compress','9','--threshold','0','-o',str(binary),str(qrc)],
                       env=env,check=True,timeout=60)
        data=compiled.read_bytes()
        version,qt=struct.unpack_from('<II',data,8)
        print('Qt fixture generated: unit_version=%#x qt_version=%#x unit_bytes=%d RCC_bytes=%d' %
              (version,qt,len(data),binary.stat().st_size),flush=True)
        assert data[:8]==b'qv4cdata' and qt==0x060803
        try:
            api=importlib.import_module('cyber_core.reverse_engineering.qt')
        except ImportError:
            raise AssertionError('Static Qt resource reader is not implemented') from None
        unit=api.inspect_qml_unit(data)
        assert unit['status'] in ('completed','partial'),unit
        assert any(s['value']=='synthetic-mode' for s in unit['strings']),unit
        assert any(t['text']=='Laboratory only' for t in unit['translations']),unit
        bindings=[b for obj in unit['objects'] for b in obj['bindings']]
        assert any(b['property']=='value' and b.get('value')==37 for b in bindings),unit
        assert any(b['property']=='ratio' and b.get('value')==1.25 for b in bindings),unit
        assert any(b['property']=='enabled' and b.get('value') is True for b in bindings),unit
        resource=api.inspect_rcc(binary.read_bytes())
        selected=[r for r in resource['resources'] if r['path']=='/lab/fixture.qmlc']
        assert len(selected)==1,resource
        assert selected[0]['sha256']==hashlib.sha256(data).hexdigest(),resource
        assert selected[0]['compression']=='zlib',resource
        from cyber_core.reverse_engineering.qt_operation import analyze_qt
        core=Core(root/'store',timeout=120,max_bytes=104857600)
        try:
            case=core.investigate('lab','Static Qt resources',str(root),'owner','Synthetic fixtures only')
            operation=analyze_qt(core,case,binary)
            assert operation['analysis']['rcc'][0]['resources'][0]['sha256']==hashlib.sha256(data).hexdigest()
            large=root/'large-synthetic-qt.bin'
            with large.open('wb') as stream:
                stream.seek(80*1024*1024)
                stream.write(binary.read_bytes())
            large_result=analyze_qt(core,case,large)['analysis']
            assert large_result['rcc'][0]['offset']==80*1024*1024,large_result
            assert large_result['rcc'][0]['resources'][0]['sha256']==hashlib.sha256(data).hexdigest()
            assert core.verify_audit(case)
            assert 'qt_resources' in core.report(case).read_text()
        finally:
            core.close()
        print('Qt real rcc/qmlcachegen: strings constants translations objects bindings compressed resource hash and CORE; QML never executed')
    return 0

if __name__=='__main__':
    raise SystemExit(main())
