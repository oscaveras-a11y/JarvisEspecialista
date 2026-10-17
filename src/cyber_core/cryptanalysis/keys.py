"""Bounded key/certificate metadata. Never returns serialized private material."""
import base64
import datetime
import hashlib
import os
import stat
import sys
import json
import math
from pathlib import Path
from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cyber_core.errors import CoreError
from cyber_core.permissions import local_path

MAX_BYTES = 1024 * 1024

def _ssh_encrypted(data):
    try:
        lines = data.strip().splitlines()
        blob = base64.b64decode(b"".join(lines[1:-1]), validate=True)
        magic = b"openssh-key-v1\0"
        if not blob.startswith(magic):
            return None
        pos = len(magic)
        fields = []
        for _ in range(3):
            if pos + 4 > len(blob):
                return None
            size = int.from_bytes(blob[pos:pos+4], "big")
            pos += 4
            if size > len(blob) - pos:
                return None
            fields.append(blob[pos:pos+size])
            pos += size
        if pos + 4 > len(blob) or int.from_bytes(blob[pos:pos+4], "big") != 1:
            return None
        pos += 4
        for _ in range(2):
            if pos + 4 > len(blob):
                return None
            size = int.from_bytes(blob[pos:pos+4], "big")
            pos += 4
            if not size or size > len(blob) - pos:
                return None
            pos += size
        if pos != len(blob):
            return None
        return fields[0] != b"none"
    except (ValueError, IndexError):
        return None

def inspect_data(data, *, complete=True):
    if not isinstance(data, bytes) or len(data) > MAX_BYTES:
        raise CoreError("Key inspection byte limit exceeded")
    raw = data.lstrip(b" \t\r\n")
    result = {"material_kind": "unknown", "format_id": "unknown", "password_protected": None,
              "structural_status": "unknown", "private_material_validated": False,
              "chain_validated": False, "coverage": "first_recognized_object_only",
              "limitations": ["Metadata only; no private serialization or passphrase returned.",
                              "A certificate date check is not chain, revocation or trust validation.",
                              "A public key cannot replace a missing private key."]}
    kind, loader = None, None
    if raw.startswith(b"-----BEGIN CERTIFICATE-----"):
        kind, loader = "certificate", x509.load_pem_x509_certificate
        result["format_id"] = "pem-certificate"
    elif raw.startswith(b"-----BEGIN OPENSSH PRIVATE KEY-----"):
        kind, loader = "private_key", lambda value: serialization.load_ssh_private_key(value, None)
        result["format_id"] = "openssh-private"
        result["password_protected"] = _ssh_encrypted(raw) if complete else None
    elif raw.startswith((b"-----BEGIN PRIVATE KEY-----", b"-----BEGIN ENCRYPTED PRIVATE KEY-----",
                         b"-----BEGIN RSA PRIVATE KEY-----", b"-----BEGIN EC PRIVATE KEY-----",
                         b"-----BEGIN DSA PRIVATE KEY-----")):
        kind, loader = "private_key", lambda value: serialization.load_pem_private_key(value, None)
        result["format_id"] = "pem-private"
        result["password_protected"] = (raw.startswith(b"-----BEGIN ENCRYPTED PRIVATE KEY-----") or
                                       b"Proc-Type: 4,ENCRYPTED" in raw[:512])
    elif raw.startswith((b"-----BEGIN PUBLIC KEY-----", b"-----BEGIN RSA PUBLIC KEY-----")):
        kind, loader = "public_key", serialization.load_pem_public_key
        result["format_id"] = "pem-public"
    elif raw.startswith((b"ssh-", b"ecdsa-sha2-")):
        kind, loader = "public_key", serialization.load_ssh_public_key
        result["format_id"] = "openssh-public"
    elif raw.startswith(b"0") and complete:
        for candidate_kind, candidate_loader in (
            ("certificate", x509.load_der_x509_certificate),
            ("public_key", serialization.load_der_public_key),
            ("private_key", lambda value: serialization.load_der_private_key(value, None))):
            try:
                candidate_loader(data)
            except TypeError:
                result.update(material_kind="private_key", format_id="der-private",
                              password_protected=True, structural_status="password_required")
                return result
            except (ValueError, UnsupportedAlgorithm):
                continue
            kind, loader = candidate_kind, candidate_loader
            result["format_id"] = "der-" + candidate_kind.replace("_", "-")
            break
    if kind is None:
        return result
    result["material_kind"] = kind
    if not complete:
        result["structural_status"] = "sample_truncated"
        return result
    try:
        obj = loader(data)
    except TypeError:
        result.update(password_protected=True, structural_status="password_required")
        return result
    except UnsupportedAlgorithm:
        result["structural_status"] = "unsupported"
        return result
    except ValueError:
        result["structural_status"] = "malformed"
        return result
    result.update(structural_status="valid", password_protected=False,
                  private_material_validated=kind == "private_key")
    key = obj.public_key() if kind in ("private_key", "certificate") else obj
    result["algorithm"] = type(key).__name__.lstrip("_")
    if isinstance(getattr(key, "key_size", None), int):
        result["key_bits"] = key.key_size
    if kind == "certificate":
        before, after = obj.not_valid_before_utc, obj.not_valid_after_utc
        now = datetime.datetime.now(datetime.timezone.utc)
        result.update(not_valid_before=before.isoformat(), not_valid_after=after.isoformat(),
                      certificate_currently_valid=before <= now <= after)
    return result

def inspect_key(path, *, max_bytes=MAX_BYTES, timeout=30, should_stop=None):
    if type(timeout) not in (int,float) or not math.isfinite(timeout) or not 0 < timeout <= 3600:
        raise CoreError("Invalid key inspection timeout")
    if type(max_bytes) is not int or not 1 <= max_bytes <= MAX_BYTES:
        raise CoreError("Invalid key inspection byte limit")
    source = local_path(path)
    with source.open("rb") as handle:
        before = os.fstat(handle.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size > max_bytes:
            raise CoreError("Key input is not a bounded regular file")
        data = handle.read(max_bytes + 1)
        after = os.fstat(handle.fileno())
    if (len(data) > max_bytes or len(data) != before.st_size or
            (before.st_ino, before.st_size, before.st_mtime_ns) !=
            (after.st_ino, after.st_size, after.st_mtime_ns)):
        raise CoreError("Key input changed or exceeds byte limit")
    from cyber_core.agents.runner import run_bounded
    digest = hashlib.sha256(data).hexdigest()
    response = run_bounded([sys.executable,"-I",str(Path(__file__).with_name("keys_child.py"))],
                           json.dumps({"source":str(source),"sha256":digest,"max_bytes":max_bytes}),
                           cwd=source.parent,timeout=timeout,max_output=16384,should_stop=should_stop)
    result = json.loads(response["stdout"])
    if not isinstance(result,dict) or "material_kind" not in result:
        raise CoreError("Invalid key metadata response")
    return {**result,"sha256":digest,"size":len(data)}
