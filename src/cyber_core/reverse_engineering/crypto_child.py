"""Trusted worker under CORE process-tree supervision. No specimen code runs."""
import json
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[2]))
from cyber_core.reverse_engineering.crypto_inspect import inspect_file,encode_result
def main():
    try:
        raw=sys.stdin.buffer.read(16385)
        if len(raw)>16384:raise ValueError()
        request=json.loads(raw)
        output=request.pop('output_bytes')
        print(encode_result(inspect_file(**request),output))
        return 0
    except Exception:
        print('{"error":"crypto_inspection_failed"}')
        return 2
if __name__=='__main__':raise SystemExit(main())
