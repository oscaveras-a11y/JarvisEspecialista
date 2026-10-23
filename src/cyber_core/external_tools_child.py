"""Fixed isolated external-tool operations. Invoked only under run_bounded."""
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import tempfile
from cyber_core.errors import CoreError
from cyber_core.external_tool_runtime import Runner, MODES, VALIDATION, binary_digest, executable, version

MAX_INPUT = 8 * 1024 * 1024

def private_file(root, name, data):
    path = root / name
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)
    return path

def read_small(path, maximum=262144):
    if path.is_symlink() or not path.is_file():
        raise CoreError("External result missing")
    with path.open("rb") as stream:
        value = stream.read(maximum + 1)
    if len(value) > maximum:
        raise CoreError("External result exceeds limit")
    return value

def validate_config(config, tool, *, converter=False, rar_converter=False):
    if not isinstance(config, dict) or set(config) - {"executable", "converter", "rar_converter"}:
        raise CoreError("Invalid external configuration")
    result = {"executable": executable(config.get("executable"))}
    if converter:
        result["converter"] = executable(config.get("converter"))
    if rar_converter:
        result["converter"] = executable(config.get("rar_converter"))
    return result

def trial(mode, raw, candidate, config, *, timeout=60, scratch_parent=None):
    if mode not in MODES or not isinstance(raw, bytes) or not 0 < len(raw) <= MAX_INPUT:
        raise CoreError("Unsupported external trial")
    maximum = 64 if mode.startswith(("john-", "hashcat-")) else 1024
    if not isinstance(candidate, bytes) or not 1 <= len(candidate) <= maximum or any(c in candidate for c in (b"\r", b"\n", b"\0")):
        raise CoreError("External candidate is unsupported")
    tool = MODES[mode]
    config = validate_config(config, tool, converter=mode in ("john-zip", "hashcat-zip-aes"), rar_converter=mode == "john-rar5")
    with tempfile.TemporaryDirectory(prefix="external-", dir=scratch_parent) as directory:
        root = Path(directory)
        runner = Runner(root, timeout)
        path = config["executable"]
        backend_version = version(runner, tool, path)
        digest = binary_digest(path)
        source = private_file(root, "target", raw)
        wordlist = private_file(root, "candidate", candidate + b"\n")
        matched = False
        from cyber_core.cryptanalysis.formats import validate_password
        if mode == "qpdf-pdf":
            # QPDF reads the password from the private file, never argv.
            code, _, _ = runner.run([path, "--password-file=" + str(wordlist), "--check", source], allowed=(0, 2, 3))
            independently = validate_password("pdf", raw, candidate)["matched"]
            matched = code in (0, 3) and independently
            if independently and not matched:
                raise CoreError("QPDF failed to validate the protected PDF")
        elif mode == "openssl-pkcs12":
            code, _, _ = runner.run([path, "pkcs12", "-in", source, "-noout", "-passin", "stdin"],
                                    data=candidate + b"\n", allowed=(0, 1))
            independently = validate_password("pkcs12", raw, candidate)["matched"]
            matched = code == 0 and independently
            if independently and not matched:
                raise CoreError("OpenSSL failed to validate PKCS12")
        else:
            if mode.endswith("sha256"):
                target = raw.strip()
                if not re.fullmatch(rb"[0-9a-fA-F]{64}", target):
                    raise CoreError("Expected one explicit SHA256 digest")
                hashes = private_file(root, "hashes", target.lower() + b"\n")
                independently = hashlib.sha256(candidate).hexdigest().encode() == target.lower()
                format_name, hash_mode = "Raw-SHA256", "1400"
            elif mode == "john-rar5":
                from cyber_core.cryptanalysis.rar5 import password_records, converter_hashes, verify_records
                records = password_records(raw)
                _, converted, _ = runner.run([config["converter"], source])
                rar_hashes = converter_hashes(converted, records)
                hashes = private_file(root, "hashes", b"\n".join(rar_hashes) + b"\n")
                independently = verify_records(records, candidate)
                format_name, hash_mode = "RAR5", None
            else:
                _, converted, _ = runner.run([config["converter"], source])
                # One bounded WinZip AES verifier; archive names never become options.
                matches = re.findall(rb"\$zip2\$[^\r\n]*?\$/zip2\$", converted)
                if len(matches) != 1:
                    raise CoreError("Unsupported ZIP converter output")
                hashes = private_file(root, "hashes", matches[0] + b"\n")
                independently = validate_password("zip", raw, candidate)["matched"]
                format_name, hash_mode = "ZIP", "13600"
            if tool == "john":
                pot = root / "matches.pot"
                runner.run([path, "--format=" + format_name, "--wordlist=" + str(wordlist),
                            "--pot=" + str(pot), "--session=" + str(root / "session"), hashes], allowed=(0, 1))
                found = pot.exists() and bool(read_small(pot))
                if mode == "john-rar5":
                    from cyber_core.cryptanalysis.rar5 import pot_matches
                    found = pot.exists() and pot_matches(read_small(pot), rar_hashes)
            else:
                output = root / "matches"
                code, _, _ = runner.run([path, "--quiet", "--potfile-disable", "--logfile-disable",
                    "--restore-disable", "--wordlist-autohex-disable", "--session=cyber", "-a", "0", "-m", hash_mode,
                    "--outfile", output, "--outfile-format", "2", hashes, wordlist], allowed=(0, 1))
                found = code == 0 and output.exists() and bool(read_small(output))
            if found != independently:
                raise CoreError("External match differs from independent validation")
            matched = found and independently
        if source.read_bytes() != raw:
            raise CoreError("External input changed")
        if not matched:
            return {"matched": False}
        result = {"matched": True, "password_validated": True, "format": mode,
                  "validation": VALIDATION[mode], "backend_version": backend_version,
                  "backend_sha256": digest}
        if mode == "john-rar5":
            result["payload_integrity_verified"] = False
        if "converter" in config:
            result["converter_sha256"] = binary_digest(config["converter"])
        return result

def normalize_die(data):
    if not isinstance(data, dict) or not isinstance(data.get("detects"), list):
        raise CoreError("Invalid DIE JSON")
    records = data["detects"]
    if not records or len(records) > 128:
        raise CoreError("Invalid DIE detections")
    # Return only recognized format identifiers, never source-derived names.
    types = []
    for item in records:
        if not isinstance(item, dict) or not isinstance(item.get("filetype"), str):
            raise CoreError("Invalid DIE detection")
        kind = item["filetype"]
        if kind in ("ELF", "ELF64", "ELF32", "PE", "PE32", "PE64", "MSDOS", "Mach-O", "Binary"):
            types.append(kind)
    return {"identified": bool(types), "formats": sorted(set(types)),
            "detections_total": len(records), "truncated": False, "extraction_enabled": False}

def normalize_unblob(data, source, size):
    if not isinstance(data, list) or len(data) != 1:
        raise CoreError("Invalid Unblob envelope")
    item = data[0]
    if not isinstance(item, dict) or item.get("task", {}).get("path") != str(source) or item.get("subtasks"):
        raise CoreError("Unexpected Unblob task")
    reports = item.get("reports")
    if not isinstance(reports, list) or len(reports) > 1024:
        raise CoreError("Invalid Unblob reports")
    chunks = []
    for report in reports:
        if not isinstance(report, dict):
            raise CoreError("Invalid Unblob report")
        kind = report.get("__typename__", "")
        if "Error" in kind:
            raise CoreError("Unblob reported an error")
        if kind != "ChunkReport":
            continue
        start, end = report.get("start_offset"), report.get("end_offset")
        name = report.get("handler_name")
        if (type(start) is not int or type(end) is not int or not 0 <= start < end <= size
                or not isinstance(name, str) or not re.fullmatch(r"[a-zA-Z0-9_ -]{1,64}", name)
                or report.get("extraction_reports")):
            raise CoreError("Invalid Unblob chunk")
        chunks.append({"offset": start, "size": end-start, "handler": name})
    return {"identified": bool(chunks), "chunks": chunks[:128], "chunks_total": len(chunks),
            "truncated": len(chunks) > 128, "extraction_enabled": False}

def analyze(tool, raw, config, *, timeout, scratch_parent):
    if tool not in ("die", "unblob") or not 0 < len(raw) <= MAX_INPUT:
        raise CoreError("Unsupported external analysis")
    config = validate_config(config, tool)
    with tempfile.TemporaryDirectory(prefix="external-", dir=scratch_parent) as directory:
        root = Path(directory)
        runner = Runner(root, timeout)
        path = config["executable"]
        backend_version = version(runner, tool, path)
        source = private_file(root, "target", raw)
        if tool == "die":
            _, output, _ = runner.run([path, "--json", source])
            result = normalize_die(json.loads(output))
        else:
            report = root / "report.json"
            runner.run([path, "--skip-extraction", "--depth", "1", "--process-num", "1",
                        "--randomness-depth", "0", "--report", report, "--log", root / "unblob.log",
                        "--extract-dir", root / "carved", source])
            result = normalize_unblob(json.loads(read_small(report)), source, len(raw))
        if source.read_bytes() != raw:
            raise CoreError("External analysis changed input")
        return {"backend": tool, "backend_version": backend_version, "backend_sha256": binary_digest(path),
                "input_sha256": hashlib.sha256(raw).hexdigest(), "input_bytes": len(raw), **result}

def main():
    try:
        data = json.loads(sys.stdin.buffer.read(16385))
        source = Path(data["source"])
        with source.open("rb") as stream:
            raw = stream.read(MAX_INPUT + 1)
        if not 0 < len(raw) <= MAX_INPUT or hashlib.sha256(raw).hexdigest() != data["source_sha256"]:
            raise CoreError("External verified source changed")
        result = analyze(data["tool"], raw, data["config"], timeout=data["timeout"], scratch_parent=data["scratch"])
        print(json.dumps(result, ensure_ascii=True))
        return 0
    except BaseException:
        print('{"error":"external_operation_failed"}')
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
