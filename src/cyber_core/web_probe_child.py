"""Trusted supervised HTTPS worker. Never print response bodies or raw errors."""
import json
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from cyber_core.web_probe import probe

def main():
    try:
        raw=sys.stdin.buffer.read(16385)
        if len(raw)>16384:
            raise ValueError()
        request=json.loads(raw)
        result=probe(**request)
        encoded=json.dumps(result,ensure_ascii=True)
        if len(encoded.encode())+1>65536:
            raise ValueError()
        print(encoded)
        return 0
    except Exception:
        print('{"error":"https_probe_failed"}')
        return 2

if __name__=='__main__':
    raise SystemExit(main())
