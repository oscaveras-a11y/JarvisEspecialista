"""Fixed local recovery trial. Receives one secret by stdin; emits metadata only."""
import hashlib
import json
import os
from pathlib import Path
import sys
from cryptography.exceptions import InvalidTag, UnsupportedAlgorithm
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization

def main():
    output = None
    try:
        data = json.loads(sys.stdin.buffer.read(16385))
        mode = data["mode"]
        source = Path(data["source"])
        with source.open("rb") as handle:
            raw = handle.read(8 * 1024 * 1024 + 1)
        if len(raw) > 8 * 1024 * 1024:
            raise ValueError()
        if hashlib.sha256(raw).hexdigest() != data["source_sha256"]:
            raise ValueError()
        candidate = bytes.fromhex(data["candidate"])
        if not 1 <= len(candidate) <= 1024:
            raise ValueError()
        result = {"matched": False}
        if mode == "ccaes1":
            if len(candidate) != 32 or len(raw) < 34 or not raw.startswith(b"CCAES1"):
                raise ValueError()
            try:
                plain = AESGCM(candidate).decrypt(raw[6:18], raw[18:], b"CCAES1")
            except InvalidTag:
                plain = None
            if plain is not None:
                output = Path(data["output"])
                with output.open("xb") as handle:
                    handle.write(plain)
                    handle.flush()
                    os.fsync(handle.fileno())
                result = {"matched": True, "authenticated": True, "sha256": hashlib.sha256(plain).hexdigest(),
                          "size": len(plain), "algorithm": "AES-256-GCM"}
        elif mode == "ssh-private":
            try:
                if raw.startswith(b"-----BEGIN OPENSSH PRIVATE KEY-----"):
                    key = serialization.load_ssh_private_key(raw, candidate)
                else:
                    key = serialization.load_pem_private_key(raw, candidate)
            except (ValueError, TypeError):
                key = None
            if key is not None:
                result = {"matched": True, "private_material_validated": True,
                          "algorithm": type(key).__name__.lstrip("_")}
        else:
            raise ValueError()
        print(json.dumps(result, ensure_ascii=True))
        return 0
    except BaseException:
        if output is not None:
            output.unlink(missing_ok=True)
        # Never emit exception text, credentials, candidate or key material.
        print('{"error":"trial_failed"}')
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
