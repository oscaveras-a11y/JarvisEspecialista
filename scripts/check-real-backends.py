"""Real Ghidra/Binwalk via CORE/CLI and persisted reports. Synthetic files only."""
import gzip
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
from cyber_core.service import Core

def analyze(core, case, path):
    original = hashlib.sha256(path.read_bytes()).hexdigest()
    task = core.enqueue(case, path, tool="analyze-firmware")
    result = core.run_one(case, task)
    assert result["sha256"] == original and result["copy_verified"]
    assert hashlib.sha256(path.read_bytes()).hexdigest() == original
    assert result["firmware"]["external_analysis"] == core.results(case)[-1]["firmware"]["external_analysis"]
    assert any(e["event"] == "analysis_process_started" for e in core.audit(case))
    assert core.verify_audit(case)
    return result["firmware"]["external_analysis"]

def cli(common, *args):
    run = subprocess.run([sys.executable, "-m", "cyber_core", *common, *args],
                         capture_output=True, text=True, timeout=180)
    assert run.returncode == 0, "Synthetic CLI failed"
    return json.loads(run.stdout)

def main():
    if sys.platform != "linux":
        raise RuntimeError("Real pinned external tools are currently validated on Linux")
    with tempfile.TemporaryDirectory(prefix="cyber-core-tools-") as directory:
        root = Path(directory)
        scope = root / "inputs"
        scope.mkdir()
        source = scope / "synthetic.c"
        source.write_text("__attribute__((noinline)) int fixture_entry(void) { return 42; }\n")
        binary = scope / "synthetic.elf"
        subprocess.run(["gcc", "-O0", "-fno-pie", "-no-pie", "-nostdlib",
                        "-Wl,-e,fixture_entry", "-o", str(binary), str(source)], check=True, timeout=30)
        ghidra = {"ghidra": {"home": os.environ["CYBER_GHIDRA_HOME"], "java_home": os.environ["JAVA_HOME"]}}
        core = Core(root / "ghidra-store", timeout=180, external_tools=ghidra)
        try:
            case = core.investigate("synthetic", "Real tools on known bytes", str(scope), "owner", "Synthetic fixtures")
            elf = analyze(core, case, binary)["ghidra"]
            assert elf["status"] == "completed" and elf["backend_version"] == "12.1.4", elf
            assert any(f["status"] == "decompiled" and ("42" in f["pseudocode"] or "0x2a" in f["pseudocode"]) for f in elf["functions"])
            sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tests"))
            from test_binary_structure import pe_fixture
            pe = pe_fixture()
            pe[0x200:0x206] = bytes.fromhex("b82a000000c3")
            struct.pack_into("<I", pe, 88 + 224 + 8, 16)
            pe_file = scope / "synthetic.pe"
            pe_file.write_bytes(pe)
            result = analyze(core, case, pe_file)["ghidra"]
            assert result["status"] == "completed", result
            assert any(f["status"] == "decompiled" and ("42" in f["pseudocode"] or "0x2a" in f["pseudocode"]) for f in result["functions"])
            report = core.report(case).read_text()
            assert "external_analysis" in report and "12.1.4" in report
        finally:
            core.close()
        binary = scope / "synthetic.bin"
        binary.write_bytes(b"Z" * 256 + gzip.compress(b"synthetic authorized firmware\n" * 16, mtime=0))
        original = hashlib.sha256(binary.read_bytes()).hexdigest()
        common = ["--home", str(root / "binwalk-store"), "--timeout", "180",
                  "--binwalk-executable", os.environ["CYBER_BINWALK"]]
        case = cli(common, "investigate", "--project", "synthetic", "--objective", "Real Binwalk through CLI",
                   "--scope", str(scope), "--owner", "owner", "--authorization", "Synthetic fixture")["id"]
        result = cli(common, "analyze-firmware", case, str(binary))
        output = result["firmware"]["external_analysis"]["binwalk"]
        assert output["status"] == "completed" and output["backend_version"] == "3.1.0", output
        assert output["input_sha256"] == original
        assert any(f["offset"] == 256 and f["name"] == "gzip" for f in output["findings"])
        assert output["extraction_enabled"] is False
        report_path = cli(common, "report", case)["path"]
        assert "external_analysis" in Path(report_path).read_text()
        assert hashlib.sha256(binary.read_bytes()).hexdigest() == original
        print(json.dumps({"real_backends": ["ghidra 12.1.4", "binwalk 3.1.0"],
                          "elf_pe_constant": 42, "gzip_offset": 256,
                          "samples_executed": False, "extraction_enabled": False,
                          "verified_copy": True, "core_sqlite_report": True, "binwalk_cli": True}))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
