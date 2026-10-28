"""Trusted static Qt worker under CORE lifecycle containment."""
import json
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[2]))
from cyber_core.reverse_engineering.qt_operation import _inspect,_encode

def main():
    try:
        data=sys.stdin.buffer.read(16385)
        if len(data)>16384:
            raise ValueError()
        request=json.loads(data)
        result=_inspect(**request)
        print(_encode(result,output_bytes=request['options']['output_bytes']))
        return 0
    except Exception:
        print('{"error":"qt_analysis_failed"}')
        return 2

if __name__=='__main__':
    raise SystemExit(main())
