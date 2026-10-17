"""Optional static tools. Caller must supervise this process and its descendants.

Linux first. No shell command supplied by evidence or configuration is accepted.
The outer supervisor owns final descendant cleanup, including on cancellation.
"""
import hashlib
import json
import math
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time

from cyber_core.errors import CoreError

MAX_INPUT = 64 * 1024 * 1024
MAX_JSON = 2 * 1024 * 1024
MAX_SCRATCH = 64 * 1024 * 1024
MAX_STDIO = 256 * 1024
GHIDRA_VERSION = "12.1.4"
BINWALK_VERSION = "3.1.0"
LIMITS = {"input_bytes": MAX_INPUT, "json_bytes": MAX_JSON, "stdio_bytes": MAX_STDIO,
          "scratch_bytes_monitored": MAX_SCRATCH, "file_bytes_hard": 16 * 1024 * 1024,
          "findings": 128, "functions": 8, "pseudocode_chars_per_function": 8192}
LIMITATION = "Static third-party interpretation; not execution or proof of safety. Outer process-tree supervision required."


def _path(value):
    if not isinstance(value, (str, os.PathLike)) or not Path(value).is_absolute():
        raise CoreError("External backend paths must be absolute trusted paths")
    return Path(value).resolve()


def _config(config):
    if config is None:
        return {}
    if not isinstance(config, dict) or set(config) - {"ghidra", "binwalk"}:
        raise CoreError("Unknown external backend configuration")
    result = {}
    for name, fields in config.items():
        allowed = {"home", "java_home"} if name == "ghidra" else {"executable"}
        if not isinstance(fields, dict) or set(fields) != allowed:
            raise CoreError("Invalid external backend configuration")
        result[name] = {k: _path(v) for k, v in fields.items()}
    return result


def _disk_size(root):
    total, count = 0, 0
    for path in root.rglob("*"):
        count += 1
        if count > 2048 or path.is_symlink():
            raise CoreError("External backend scratch entry limit exceeded")
        if path.is_file():
            total += path.stat().st_size
            if total > MAX_SCRATCH:
                raise CoreError("External backend scratch byte limit exceeded")
    return total


def _run(command, cwd, env, deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise CoreError("External analysis shared deadline exceeded")
    if sys.platform != "linux":
        raise CoreError("External execution currently requires Linux")
    launcher = Path(__file__).with_name("_limit_exec.py")
    process = subprocess.Popen([sys.executable, "-I", str(launcher), str(remaining), *map(str, command)],
                               cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               shell=False, close_fds=True, bufsize=0)
    buffers = [bytearray(), bytearray()]
    overflow = threading.Event()
    lock = threading.Lock()
    def read(stream, target):
        try:
            while block := stream.read(4096):
                with lock:
                    if sum(map(len, buffers)) + len(block) > MAX_STDIO:
                        overflow.set()
                        return
                    target.extend(block)
        except (OSError, ValueError):
            pass
    readers = [threading.Thread(target=read, args=(stream, target), daemon=True)
               for stream, target in zip((process.stdout, process.stderr), buffers)]
    for reader in readers:
        reader.start()
    try:
        while process.poll() is None:
            if time.monotonic() >= deadline:
                raise CoreError("External analysis shared deadline exceeded")
            if overflow.is_set():
                raise CoreError("External backend output limit exceeded")
            _disk_size(cwd)
            time.sleep(.02)
        for reader in readers:
            reader.join(timeout=.5)
        if any(reader.is_alive() for reader in readers):
            raise CoreError("External backend descendants retained output streams")
        if overflow.is_set():
            raise CoreError("External backend output limit exceeded")
        _disk_size(cwd)
        if time.monotonic() >= deadline:
            raise CoreError("External analysis shared deadline exceeded")
        if process.returncode:
            raise CoreError("External backend exited unsuccessfully")
        return bytes(buffers[0]).decode("utf-8", errors="replace")
    finally:
        if process.poll() is None:
            process.kill()
        process.wait(timeout=2)
        for stream in (process.stdout, process.stderr):
            stream.close()


def _read_json(path):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_JSON:
        raise CoreError("External backend JSON missing or oversized")
    try:
        return json.loads(path.read_bytes().decode("utf-8"))
    except (ValueError, UnicodeError) as exc:
        raise CoreError("Invalid external backend JSON") from exc


def normalize_binwalk(raw, path, size):
    if not isinstance(raw, list) or len(raw) != 1 or not isinstance(raw[0], dict):
        raise CoreError("Invalid Binwalk analysis envelope")
    analysis = raw[0].get("Analysis")
    if not isinstance(analysis, dict) or analysis.get("file_path") != str(path) or analysis.get("extractions") != {}:
        raise CoreError("Unexpected Binwalk path or extraction")
    findings = analysis.get("file_map")
    if not isinstance(findings, list):
        raise CoreError("Invalid Binwalk findings")
    result = []
    # Validate every reported range, even those omitted by the presentation cap.
    for record in findings:
        if not isinstance(record, dict):
            raise CoreError("Invalid Binwalk finding")
        at, length = record.get("offset"), record.get("size")
        if type(at) is not int or type(length) is not int or not 0 <= at < size or not 0 <= length <= size - at:
            raise CoreError("Binwalk finding outside verified input")
        if len(result) < LIMITS["findings"]:
            result.append({"offset": at, "size": length or None,
                           "name": str(record.get("name", ""))[:128],
                           "description": str(record.get("description", ""))[:1024],
                           "backend_confidence": record.get("confidence")})
    return {"findings": result, "findings_total": len(findings),
            "truncated": len(findings) > len(result), "extraction_enabled": False}


def _ghidra_result(raw):
    if not isinstance(raw, dict) or raw.get("backend_version") != GHIDRA_VERSION:
        raise CoreError("Unsupported Ghidra result schema or version")
    functions = raw.get("functions")
    if not isinstance(functions, list) or len(functions) > 8 or type(raw.get("analysis_timed_out")) is not bool:
        raise CoreError("Invalid Ghidra function results")
    for function in functions:
        if not isinstance(function, dict) or function.get("status") not in ("decompiled", "failed"):
            raise CoreError("Invalid Ghidra function")
        for field, maximum in (("address", 64), ("name", 256), ("pseudocode", 8192), ("error", 512)):
            if not isinstance(function.get(field), str) or len(function[field]) > maximum:
                raise CoreError("Invalid Ghidra text field")
    if not all(isinstance(raw.get(key), str) and len(raw[key]) <= 256
               for key in ("language_id", "compiler_spec", "image_base")):
        raise CoreError("Invalid Ghidra metadata")
    return raw


def analyze_external(verified_path, metadata, config, timeout):
    """Analyze a verified copy; config is trusted host configuration, never evidence.

    No tools run without explicit config. Does not acquire evidence, authorize a
    case, supervise its own process tree, persist results or claim CORE wiring.
    """
    if type(timeout) not in (int, float) or not math.isfinite(timeout) or not 0 < timeout <= 3600:
        raise CoreError("Invalid external analysis timeout")
    deadline = time.monotonic() + timeout
    configuration = _config(config)
    path = _path(verified_path)
    if not isinstance(metadata, dict):
        raise CoreError("Invalid firmware metadata")
    if not path.is_file() or not 0 < path.stat().st_size <= MAX_INPUT:
        raise CoreError("External input missing, empty or exceeds byte limit")
    size = path.stat().st_size
    digest = hashlib.sha256()
    read_bytes = 0
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(65536), b""):
            read_bytes += len(block)
            if read_bytes > MAX_INPUT:
                raise CoreError("External input grew beyond byte limit")
            digest.update(block)
            if time.monotonic() >= deadline:
                raise CoreError("External analysis shared deadline exceeded")
    if read_bytes != size:
        raise CoreError("External input changed while hashing")
    digest = digest.hexdigest()
    common = {"input_sha256": digest, "input_bytes": size,
              "limits": dict(LIMITS), "limitations": LIMITATION}
    results = {}
    for name in ("ghidra", "binwalk"):
        result = {"backend": name, "status": "not_requested", **common}
        results[name] = result
        if name not in configuration:
            continue
        fields = configuration[name]
        if name == "ghidra" and metadata.get("format") not in ("elf", "pe"):
            result["status"] = "unsupported_format"
            continue
        executable = fields["home"] / "support" / "analyzeHeadless" if name == "ghidra" else fields["executable"]
        if not executable.is_file():
            result["status"] = "dependency_unavailable"
            continue
        if name == "ghidra" and not (fields["java_home"] / "bin" / "java").is_file():
            result["status"] = "dependency_unavailable"
            continue
        if sys.platform != "linux":
            result["status"] = "unsupported_platform"
            continue
        try:
            if name == "ghidra":
                properties = fields["home"] / "Ghidra" / "application.properties"
                if not properties.is_file() or properties.stat().st_size > 65536 or ("application.version=" + GHIDRA_VERSION) not in properties.read_text().splitlines():
                    raise CoreError("Unsupported Ghidra installation version")
            with tempfile.TemporaryDirectory(prefix="cyber-external-") as directory:
                scratch = Path(directory)
                home = scratch / "home"
                home.mkdir()
                env = {"PATH": "/usr/bin:/bin", "HOME": str(home), "TMPDIR": str(scratch),
                       "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"}
                output = scratch / "result.json"
                if name == "binwalk":
                    version = _run([executable, "--version"], scratch, env, deadline).strip()
                    if version != "binwalk " + BINWALK_VERSION:
                        raise CoreError("Unsupported Binwalk version")
                    result["backend_version"] = BINWALK_VERSION
                    _run([executable, "--quiet", "--threads", "1", "--log", output, path], scratch, env, deadline)
                    result.update(normalize_binwalk(_read_json(output), path, common["input_bytes"]))
                    result["status"] = "completed"
                else:
                    env.update(JAVA_HOME=str(fields["java_home"]),
                               GHIDRA_HEADLESS_MAXMEM="1G")
                    scripts = Path(__file__).with_name("ghidra_scripts")
                    loader = "ElfLoader" if metadata["format"] == "elf" else "PeLoader"
                    analysis_seconds = max(1, min(30, int(deadline - time.monotonic()) - 3))
                    command = [executable, scratch, "Preview", "-import", path,
                               "-loader", loader, "-loader-loadLibraries", "false",
                               "-loader-applyRelocations", "false", "-readOnly",
                               "-scriptPath", scripts, "-postScript", "ExportPreview.java", output,
                               "-analysisTimeoutPerFile", str(analysis_seconds), "-max-cpu", "1",
                               "-log", scratch / "application.log", "-scriptlog", scratch / "script.log"]
                    _run(command, scratch, env, deadline)
                    raw = _ghidra_result(_read_json(output))
                    result.update(raw)
                    result["status"] = ("partial" if raw["analysis_timed_out"] or
                                        any(f["status"] == "failed" for f in raw["functions"])
                                        else "completed" if raw["functions"] else "no_functions")
        except (CoreError, OSError) as exc:
            result["status"] = "failed"
            result["error"] = str(exc)[:512] if isinstance(exc, CoreError) else "External backend could not run"
    final_digest = hashlib.sha256()
    final_size = 0
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(65536), b""):
            final_size += len(block)
            if final_size > size:
                raise CoreError("Verified input changed during external analysis")
            final_digest.update(block)
    if final_size != size or final_digest.hexdigest() != digest:
        raise CoreError("Verified input changed during external analysis")
    return results
