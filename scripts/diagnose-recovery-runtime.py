"""Synthetic integration diagnostics: fixed codes only, never argv/stdout/secrets."""
import io
import json
import os
from pathlib import Path
import runpy
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

if "--child" in sys.argv:
    from cyber_core.external_tool_runtime import Runner
    import cyber_core.external_tool_runtime as runtime
    request = sys.stdin.buffer.read()
    metadata = json.loads(request)
    marker = Path(metadata["scratch"]) / "diagnostic.json"
    original_run, original_popen = Runner.run, runtime.subprocess.Popen
    processes = []
    def popen(*args, **kwargs):
        process = original_popen(*args, **kwargs)
        processes.append(process)
        return process
    def traced(self, *args, **kwargs):
        before = len(processes)
        try:
            return original_run(self, *args, **kwargs)
        except BaseException as exc:
            # Values are fixed program categories and integers, never raw messages.
            messages = {
                "External output or time limit exceeded": "output_or_time",
                "External output or stream limit exceeded": "output_or_stream",
                "External tool execution failed": "tool_exit",
                "External shared timeout": "deadline",
                "External scratch entry limit": "scratch_entries",
                "External scratch byte limit": "scratch_bytes",
            }
            record = {"category": messages.get(str(exc), "other"),
                      "exception": type(exc).__name__ if type(exc).__name__ in
                          ("CoreError", "FileNotFoundError", "OSError", "PermissionError") else "other",
                      "errno": getattr(exc, "errno", None),
                      "returncode": processes[-1].returncode if len(processes) > before else None}
            marker.write_text(json.dumps(record))
            raise
    runtime.subprocess.Popen = popen
    Runner.run = traced
    sys.stdin = io.TextIOWrapper(io.BytesIO(request), encoding="utf-8")
    runpy.run_path(str(ROOT / "src/cyber_core/cryptanalysis/recovery_trial.py"), run_name="__main__")
else:
    import cyber_core.cryptanalysis.sessions as sessions
    original = sessions.run_bounded
    def traced(command, prompt, **kwargs):
        request = json.loads(prompt)
        if request.get("mode") in ("john-sha256", "hashcat-sha256", "hashcat-zip-aes", "john-zip"):
            command = [sys.executable, "-I", str(Path(__file__).resolve()), "--child"]
        try:
            return original(command, prompt, **kwargs)
        except BaseException:
            marker = Path(request.get("scratch", "")) / "diagnostic.json"
            if marker.is_file():
                record = json.loads(marker.read_text())
                # Schema/values supplied only by trusted diagnostic child above.
                print("SYNTHETIC_RUNTIME_DIAGNOSTIC " + json.dumps(record), flush=True)
            else:
                print("SYNTHETIC_RUNTIME_DIAGNOSTIC no_inner_runtime_error", flush=True)
            raise
    sessions.run_bounded = traced
    import test_external_recovery_tools as tests
    names = ("test_john_jumbo_sha256_wrong_and_correct",
             "test_hashcat_sha256_wrong_and_correct_using_real_cpu_backend",
             "test_hashcat_treats_hex_looking_candidate_as_literal_password",
             "test_hashcat_zip_aes_via_john_converter")
    suite = unittest.TestSuite(tests.RealExternalRecoveryTests(name) for _ in range(3) for name in names)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    raise SystemExit(not result.wasSuccessful())
