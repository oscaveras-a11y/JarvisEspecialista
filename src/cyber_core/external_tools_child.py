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
# die/unblob identify and decompose real firmware/program images, which can
# exceed 5 GiB; the owner confirmed this blocking a real OpenWrt image during
# section-6 testing. Matches the MAX_INPUT_BYTES/run_bounded RAM ceiling raised
# for the same reason. The other analyze() tools (semgrep/detect-secrets/
# pip-audit) are source/text-oriented and keep the smaller MAX_INPUT.
MAX_FIRMWARE_INPUT = 8 * 1024 * 1024 * 1024
# unblob's own default is effectively unbounded recursion; a firmware/archive
# crafted as a decompression bomb could otherwise exhaust scratch disk before
# the byte/entry limits below even get checked between files. 10 covers every
# real nested-firmware case seen so far (bootloader > kernel > initramfs >
# squashfs > files) with headroom, while still bounding the recursion itself.
UNBLOB_MAX_DEPTH = 10
# Real firmware extracts into far more than a password-recovery scratch dir
# ever needs: validated against a real 126 MB OpenWrt image (1314 files, ~170
# MB extracted). Generous headroom for larger images, still bounded.
FIRMWARE_SCRATCH_MAX_BYTES = 16 * 1024 * 1024 * 1024
FIRMWARE_SCRATCH_MAX_ENTRIES = 200_000

def private_file(root, name, data):
    path = root / name
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)
    return path

def _read_bounded(stream, maximum):
    # A single stream.read(n) with a large explicit n asks the interpreter to
    # pre-allocate a buffer of that size before any bytes arrive — harmless at
    # the old 256 KiB/8 MiB scale, but an 8 GiB limit against a 126 MB real
    # file raised MemoryError under RLIMIT_AS before a single real byte was
    # read. Reading in fixed chunks bounds memory by what is actually there.
    chunks = bytearray()
    while len(chunks) <= maximum:
        block = stream.read(min(1048576, maximum + 1 - len(chunks)))
        if not block:
            break
        chunks += block
    return bytes(chunks)

def read_small(path, maximum=262144):
    if path.is_symlink() or not path.is_file():
        raise CoreError("External result missing")
    with path.open("rb") as stream:
        value = _read_bounded(stream, maximum)
    if len(value) > maximum:
        raise CoreError("External result exceeds limit")
    return value

def validate_config(config, tool, *, converter=False, rar_converter=False, rules_path=False):
    if not isinstance(config, dict) or set(config) - {"executable", "converter", "rar_converter", "rules_path"}:
        raise CoreError("Invalid external configuration")
    result = {"executable": executable(config.get("executable"))}
    if converter:
        result["converter"] = executable(config.get("converter"))
    if rar_converter:
        result["converter"] = executable(config.get("rar_converter"))
    if rules_path:
        from cyber_core.external_tool_runtime import semgrep_rules_path
        result["rules_path"] = semgrep_rules_path(config.get("rules_path"))
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

MAX_UNBLOB_TASKS = 200_000
MAX_UNBLOB_CHUNKS = 4096

def normalize_unblob(data, source, size):
    """Walk unblob's real recursive task tree (a flat list; each task's
    "subtasks" are {path,...} references resolved against the same list, not
    nested objects) and collect only the structural chunk/container records
    at every depth. Deliberately drops everything else a task can carry
    (StatReport/FileMagicReport/HashReport for ordinary extracted files,
    CarveDirectoryReport's local scratch path) — those describe the ephemeral
    scratch tree itself, which is never exposed or persisted, only the
    container/format boundaries unblob found inside it.
    """
    if not isinstance(data, list) or not data or len(data) > MAX_UNBLOB_TASKS:
        raise CoreError("Invalid Unblob envelope")
    by_path = {}
    for item in data:
        if not isinstance(item, dict) or set(item) != {"task", "reports", "subtasks"}:
            raise CoreError("Invalid Unblob task")
        task = item["task"]
        if (not isinstance(task, dict) or not isinstance(task.get("path"), str)
                or type(task.get("depth")) is not int or task["depth"] < 0
                or not isinstance(item["reports"], list) or len(item["reports"]) > 1024
                or not isinstance(item["subtasks"], list) or len(item["subtasks"]) > 1024):
            raise CoreError("Invalid Unblob task")
        by_path[task["path"]] = item
    root = by_path.get(str(source))
    if root is None or root["task"]["depth"] != 0:
        raise CoreError("Unexpected Unblob task root")
    chunks, total, visited = [], [0], set()
    def walk(item):
        if id(item) in visited:
            return
        visited.add(item["task"]["path"])
        for report in item["reports"]:
            if not isinstance(report, dict):
                raise CoreError("Invalid Unblob report")
            kind = report.get("__typename__", "")
            if kind not in ("ChunkReport", "UnknownChunkReport"):
                # unblob's own ErrorReport base class is the one with a
                # severity field; a plain StatReport/HashReport/FileMagicReport
                # for an ordinary extracted file never carries one. This is the
                # actual signal, not the report's class name.
                if report.get("severity") == "ERROR":
                    raise CoreError("Unblob reported an error")
                continue
            start, end = report.get("start_offset"), report.get("end_offset")
            if type(start) is not int or type(end) is not int or not 0 <= start < end <= size:
                raise CoreError("Invalid Unblob chunk")
            if kind == "UnknownChunkReport":
                record = {"offset": start, "size": end - start, "handler": "unknown",
                          "depth": item["task"]["depth"], "encrypted": False, "extractor_available": True}
            else:
                name = report.get("handler_name")
                encrypted = report.get("is_encrypted")
                extraction_reports = report.get("extraction_reports")
                if (not isinstance(name, str) or not re.fullmatch(r"[a-zA-Z0-9_ -]{1,64}", name)
                        or type(encrypted) is not bool
                        or not isinstance(extraction_reports, list) or len(extraction_reports) > 16):
                    raise CoreError("Invalid Unblob chunk")
                # A missing extractor (e.g. a format this environment has no
                # decoder for) narrows what was decomposed; it never aborts
                # the whole analysis the way a malformed report does.
                missing = any(isinstance(r, dict) and r.get("__typename__") == "ExtractorDependencyNotFoundReport"
                              for r in extraction_reports)
                record = {"offset": start, "size": end - start, "handler": name,
                          "depth": item["task"]["depth"], "encrypted": encrypted,
                          "extractor_available": not missing}
            total[0] += 1
            if len(chunks) < MAX_UNBLOB_CHUNKS:
                chunks.append(record)
        for ref in item["subtasks"]:
            if not isinstance(ref, dict) or not isinstance(ref.get("path"), str):
                raise CoreError("Invalid Unblob subtask reference")
            child = by_path.get(ref["path"])
            if child is None:
                raise CoreError("Unblob subtask reference not found")
            walk(child)
    walk(root)
    return {"identified": bool(chunks), "chunks": chunks, "chunks_total": total[0],
            "truncated": total[0] > len(chunks), "extraction_enabled": False,
            "max_depth": max((c["depth"] for c in chunks), default=0)}

MAX_FINDINGS = 256

def normalize_semgrep(data, source):
    if not isinstance(data, dict) or not isinstance(data.get("results"), list) or not isinstance(data.get("errors"), list):
        raise CoreError("Invalid Semgrep JSON")
    if data["errors"]:
        raise CoreError("Semgrep reported a scan error")
    records = data["results"]
    if len(records) > 4096:
        raise CoreError("Invalid Semgrep result count")
    findings = []
    for item in records:
        if (not isinstance(item, dict) or item.get("path") != str(source)
                or not isinstance(item.get("check_id"), str) or not isinstance(item.get("extra"), dict)):
            raise CoreError("Invalid Semgrep finding")
        start, end = item.get("start"), item.get("end")
        severity = item["extra"].get("severity")
        if (not isinstance(start, dict) or not isinstance(end, dict)
                or type(start.get("line")) is not int or type(end.get("line")) is not int
                or severity not in ("ERROR", "WARNING", "INFO")):
            raise CoreError("Invalid Semgrep finding location")
        if len(findings) < MAX_FINDINGS:
            # The rule's own message (operator-authored) is kept; the matched
            # "lines" excerpt is dropped since it may echo sample secrets.
            findings.append({"rule_id": item["check_id"][:256], "severity": severity,
                              "line": start["line"], "end_line": end["line"],
                              "message": str(item["extra"].get("message", ""))[:512]})
    return {"identified": bool(findings), "findings": findings, "findings_total": len(records),
            "truncated": len(records) > len(findings), "extraction_enabled": False}

def normalize_detect_secrets(data, source):
    if not isinstance(data, dict) or not isinstance(data.get("results"), dict):
        raise CoreError("Invalid detect-secrets JSON")
    name = source.name
    records = data["results"].get(name, [])
    if set(data["results"]) - {name} or not isinstance(records, list) or len(records) > 4096:
        raise CoreError("Invalid detect-secrets results")
    findings = []
    for item in records:
        if (not isinstance(item, dict) or item.get("filename") != name
                or not isinstance(item.get("type"), str)
                or not isinstance(item.get("hashed_secret"), str)
                or re.fullmatch(r"[0-9a-f]{40}", item["hashed_secret"]) is None
                or type(item.get("line_number")) is not int):
            raise CoreError("Invalid detect-secrets finding")
        if len(findings) < MAX_FINDINGS:
            # Only the detector's own identifier, line number and the secret's
            # SHA1 (never the secret value itself) ever leave this function.
            findings.append({"detector": item["type"][:128], "line": item["line_number"],
                              "secret_sha1": item["hashed_secret"]})
    return {"identified": bool(findings), "findings": findings, "findings_total": len(records),
            "truncated": len(records) > len(findings), "extraction_enabled": False}

MAX_REQUIREMENT_LINES = 128

def normalize_pip_audit(data):
    if not isinstance(data, dict) or not isinstance(data.get("dependencies"), list):
        raise CoreError("Invalid pip-audit JSON")
    deps = data["dependencies"]
    if len(deps) > MAX_REQUIREMENT_LINES:
        raise CoreError("Invalid pip-audit dependency count")
    findings, total = [], 0
    for dep in deps:
        if (not isinstance(dep, dict) or not isinstance(dep.get("name"), str)
                or not isinstance(dep.get("version"), str) or not isinstance(dep.get("vulns"), list)
                or len(dep["vulns"]) > 64):
            raise CoreError("Invalid pip-audit dependency")
        for vuln in dep["vulns"]:
            if (not isinstance(vuln, dict) or not isinstance(vuln.get("id"), str)
                    or not isinstance(vuln.get("fix_versions"), list)
                    or not all(isinstance(v, str) for v in vuln["fix_versions"])
                    or not isinstance(vuln.get("aliases"), list)
                    or not all(isinstance(v, str) for v in vuln["aliases"])):
                raise CoreError("Invalid pip-audit vulnerability")
            total += 1
            if len(findings) < MAX_FINDINGS:
                # The vulnerability database's own identifiers and fix versions are
                # kept; its free-text description is bounded, never raw/unbounded.
                findings.append({"package": dep["name"][:256], "installed_version": dep["version"][:64],
                                  "vuln_id": vuln["id"][:64], "fix_versions": [v[:32] for v in vuln["fix_versions"]][:16],
                                  "aliases": [v[:64] for v in vuln["aliases"]][:16],
                                  "description": str(vuln.get("description", ""))[:500]})
    return {"identified": bool(findings), "findings": findings, "findings_total": total,
            "truncated": total > len(findings), "extraction_enabled": False}

def analyze(tool, raw, config, *, timeout, scratch_parent):
    limit = MAX_FIRMWARE_INPUT if tool in ("die", "unblob") else MAX_INPUT
    if tool not in ("die", "unblob", "semgrep", "detect-secrets", "pip-audit") or not 0 < len(raw) <= limit:
        raise CoreError("Unsupported external analysis")
    if tool == "pip-audit":
        try:
            text = raw.decode("utf-8", "strict")
        except UnicodeDecodeError:
            raise CoreError("Requirements file must be UTF-8 text") from None
        lines = [line for line in text.splitlines() if line.strip() and not line.strip().startswith("#")]
        if not lines or len(lines) > MAX_REQUIREMENT_LINES:
            raise CoreError("Invalid pip-audit requirements line count")
    config = validate_config(config, tool, rules_path=tool == "semgrep")
    with tempfile.TemporaryDirectory(prefix="external-", dir=scratch_parent) as directory:
        root = Path(directory)
        if tool in ("die", "unblob"):
            # unblob actually extracts into this throwaway scratch dir now (see
            # below), and a real filesystem tree ordinarily contains symlinks
            # (busybox applets, /bin -> usr/bin); die never extracts anything,
            # so it keeps the strict default.
            runner = Runner(root, timeout, max_scratch_bytes=FIRMWARE_SCRATCH_MAX_BYTES,
                            max_scratch_entries=FIRMWARE_SCRATCH_MAX_ENTRIES,
                            max_file_bytes=MAX_FIRMWARE_INPUT, allow_symlinks=tool == "unblob")
        else:
            runner = Runner(root, timeout)
        path = config["executable"]
        backend_version = version(runner, tool, path)
        source = private_file(root, "target", raw)
        if tool == "die":
            _, output, _ = runner.run([path, "--json", source])
            result = normalize_die(json.loads(output))
        elif tool == "unblob":
            report = root / "report.json"
            # Real (not --skip-extraction) extraction into this throwaway scratch
            # dir is required for unblob to look inside a chunk and recurse — the
            # report it writes still only ever carries offset/size/handler/depth,
            # never extracted content, so normalize_unblob's output contract is
            # unchanged. --depth bounds the recursion itself (decompression-bomb
            # protection); the scratch byte/entry limits above are the real
            # backstop against a bomb's actual disk usage.
            # unblob exits 1 (not 0) whenever any single chunk couldn't be
            # fully extracted (e.g. one missing optional extractor dependency)
            # even though the run itself completed and wrote a valid report;
            # normalize_unblob already surfaces that per-chunk, never silently.
            runner.run([path, "--depth", str(UNBLOB_MAX_DEPTH), "--process-num", "1",
                        "--randomness-depth", "0", "--report", report, "--log", root / "unblob.log",
                        "--extract-dir", root / "carved", source], allowed=(0, 1))
            result = normalize_unblob(json.loads(read_small(report, maximum=268435456)), source, len(raw))
        elif tool == "semgrep":
            output = root / "semgrep.json"
            # --no-trace is required even with --metrics=off: Semgrep's OpenTelemetry
            # tracing is a separate code path that otherwise retries a DNS/connect to
            # telemetry.semgrep.dev with ~100s of exponential backoff before giving up.
            runner.run([path, "--config", config["rules_path"], "--json", "--quiet", "--metrics=off",
                        "--no-trace", "--oss-only", "--disable-version-check", "--scan-unknown-extensions",
                        "--output", output, source], allowed=(0, 1))
            result = normalize_semgrep(json.loads(read_small(output, maximum=4194304)), source)
        elif tool == "detect-secrets":
            _, stdout, _ = runner.run([path, "scan", source], allowed=(0,))
            result = normalize_detect_secrets(json.loads(stdout), source)
        else:
            # The only call in this module that ever runs with network access
            # (see NETWORK_TOOLS in external_tool_runtime.py): --no-deps and
            # --disable-pip mean it looks up only the exact pinned name/version
            # pairs already in the acquired requirements file, against the
            # package index itself — never anything derived from its content
            # beyond those pins, and never the sample under investigation.
            _, stdout, _ = runner.run([path, "-r", source, "--no-deps", "--disable-pip",
                                        "-s", "pypi", "--timeout", str(min(int(timeout), 60)),
                                        "-f", "json"], allowed=(0, 1), network=True)
            result = normalize_pip_audit(json.loads(stdout))
        input_sha256 = hashlib.sha256(raw).hexdigest()
        # Stream-hash rather than reading a second copy into memory and
        # comparing bytes: for a multi-GB firmware, re-reading the whole file
        # into a second buffer would momentarily double peak memory right at
        # the finish line. SHA-256 equality is exactly as rigorous here as the
        # byte-for-byte compare it replaces, and matches how every other
        # evidence-integrity check in this project already compares digests.
        check = hashlib.sha256()
        with source.open("rb") as stream:
            while block := stream.read(1048576):
                check.update(block)
        if check.hexdigest() != input_sha256:
            raise CoreError("External analysis changed input")
        return {"backend": tool, "backend_version": backend_version, "backend_sha256": binary_digest(path),
                "input_sha256": input_sha256, "input_bytes": len(raw), **result}

def main():
    try:
        data = json.loads(sys.stdin.buffer.read(16385))
        source = Path(data["source"])
        limit = MAX_FIRMWARE_INPUT if data.get("tool") in ("die", "unblob") else MAX_INPUT
        with source.open("rb") as stream:
            raw = _read_bounded(stream, limit)
        if not 0 < len(raw) <= limit or hashlib.sha256(raw).hexdigest() != data["source_sha256"]:
            raise CoreError("External verified source changed")
        result = analyze(data["tool"], raw, data["config"], timeout=data["timeout"], scratch_parent=data["scratch"])
        print(json.dumps(result, ensure_ascii=True))
        return 0
    except BaseException:
        print('{"error":"external_operation_failed"}')
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
