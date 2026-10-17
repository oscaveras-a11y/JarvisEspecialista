"""Fixed key metadata parser; no input execution or private serialization."""
import hashlib
import json
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[2]))
from cyber_core.cryptanalysis.keys import inspect_data
from cyber_core.permissions import local_path

def main():
    try:
        request = json.loads(sys.stdin.buffer.read(16385))
        with local_path(request["source"]).open("rb") as handle:
            raw = handle.read(request["max_bytes"]+1)
        if len(raw) > request["max_bytes"] or hashlib.sha256(raw).hexdigest() != request["sha256"]:
            raise ValueError()
        print(json.dumps(inspect_data(raw),ensure_ascii=True))
        return 0
    except BaseException:
        print('{"error":"key_metadata_failed"}')
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
