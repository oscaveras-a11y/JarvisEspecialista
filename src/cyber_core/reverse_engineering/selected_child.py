"""Trusted selected-analysis entrypoint under CORE process-tree containment."""
import json
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[2]))
from cyber_core.firmware import analyze_firmware
from cyber_core.reverse_engineering.external import analyze_external
from cyber_core.reverse_engineering.selected import encode_result

def main():
    try:
        request = sys.stdin.buffer.read(16385)
        if len(request)>16384:
            raise ValueError()
        data = json.loads(request)
        metadata = analyze_firmware(data['source'],max_bytes=data['max_bytes'])
        if metadata['sha256'] != data['sha256']:
            raise ValueError()
        output = analyze_external(data['source'],{'format':metadata['format']},
                                  data['config'],data['timeout'],function_selection=data['selection'])['ghidra']
        print(encode_result(output,output_bytes=data['selection']['output_bytes']))
        return 0
    except Exception:
        print('{"error":"selected_analysis_failed"}')
        return 2
if __name__ == '__main__':
    raise SystemExit(main())
