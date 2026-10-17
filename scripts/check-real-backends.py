"""Real Linux backend acceptance under a process-group supervisor.

Builds an ELF fixture with gcc but NEVER executes it. No mocks, no providers.
"""
import gzip
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile

def worker():
    from cyber_core.reverse_engineering.external import analyze_external
    from cyber_core.firmware import analyze_firmware
    data = json.loads(Path(sys.argv[2]).read_text())
    result = analyze_external(Path(data["input"]), {"format": data["format"]}, data["config"], 120)
    Path(data["output"]).write_text(json.dumps(result))
    return 0

def supervised(request, root):
    config = root / "request.json"
    config.write_text(json.dumps(request))
    process = subprocess.Popen([sys.executable, str(Path(__file__).resolve()), "--worker", str(config)],
                               start_new_session=True)
    try:
        if process.wait(timeout=140) != 0:
            raise AssertionError("Real adapter worker failed")
    finally:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    return json.loads(Path(request["output"]).read_text())

def main():
    if sys.platform != "linux":
        raise RuntimeError("Real backend acceptance currently requires Linux")
    with tempfile.TemporaryDirectory(prefix="cyber-real-backends-") as temp:
        root = Path(temp)
        cfile = root / "synthetic.c"
        cfile.write_text("__attribute__((noinline)) int fixture_entry(void) { return 42; }\n")
        binary = root / "synthetic.elf"
        subprocess.run(["gcc", "-O0", "-fno-pie", "-no-pie", "-nostdlib",
                        "-Wl,-e,fixture_entry", "-o", str(binary), str(cfile)], check=True, timeout=30)
        original = hashlib.sha256(binary.read_bytes()).hexdigest()
        ghidra = {"ghidra": {"home": os.environ["CYBER_GHIDRA_HOME"], "java_home": os.environ["JAVA_HOME"]}}
        result = supervised({"input": str(binary), "format": "elf", "config": ghidra,
                             "output": str(root / "ghidra.json")}, root)
        output = result["ghidra"]
        assert output["status"] == "completed", output
        assert output["backend_version"] == "12.1.4", output
        assert any(f["status"] == "decompiled" and "42" in f["pseudocode"]
                   for f in output["functions"]), output
        assert output["input_sha256"] == original
        assert hashlib.sha256(binary.read_bytes()).hexdigest() == original

        firmware = root / "synthetic.bin"
        firmware.write_bytes(b"Z" * 256 + gzip.compress(b"synthetic authorized firmware\n" * 16, mtime=0))
        original = hashlib.sha256(firmware.read_bytes()).hexdigest()
        config = {"binwalk": {"executable": os.environ["CYBER_BINWALK"]}}
        result = supervised({"input": str(firmware), "format": "bin", "config": config,
                             "output": str(root / "binwalk.json")}, root)
        output = result["binwalk"]
        assert output["status"] == "completed", output
        assert output["backend_version"] == "3.1.0", output
        assert any(f["offset"] == 256 and f["name"] == "gzip" for f in output["findings"]), output
        assert output["extraction_enabled"] is False
        assert output["input_sha256"] == original
        assert hashlib.sha256(firmware.read_bytes()).hexdigest() == original
        assert not (root / "extractions").exists()
        print(json.dumps({"real_backends": ["ghidra 12.1.4", "binwalk 3.1.0"],
                          "ghidra_constant": 42, "binwalk_gzip_offset": 256,
                          "samples_executed": False, "extraction_enabled": False,
                          "core_wiring": False}))
    return 0

if __name__ == "__main__":
    raise SystemExit(worker() if "--worker" in sys.argv else main())
