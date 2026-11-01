"""External adapter contracts. Dummies exercise failure handling, not real integration."""
import hashlib
import io
from types import SimpleNamespace
import json
import math
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
from cyber_core.errors import CoreError

class ExternalTests(unittest.TestCase):
    def setUp(self):
        from cyber_core.reverse_engineering import external
        self.api = external
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.input = self.root / "verified.evidence"
        self.input.write_bytes(b"synthetic input")

    def test_no_config_never_launches_tools(self):
        with patch("subprocess.Popen", side_effect=AssertionError("unexpected launch")):
            out = self.api.analyze_external(self.input, {}, None, 1)
        self.assertEqual({v["status"] for v in out.values()}, {"not_requested"})

    def test_digest_binds_results_to_bytes(self):
        out = self.api.analyze_external(self.input, {}, None, 1)
        self.assertEqual(out["binwalk"]["input_sha256"], hashlib.sha256(self.input.read_bytes()).hexdigest())

    def test_relative_executable_is_rejected(self):
        with self.assertRaises(CoreError):
            self.api.analyze_external(self.input, {}, {"binwalk": {"executable": "binwalk"}}, 1)

    def test_invalid_timeout_is_rejected(self):
        for value in (0, -1, True, float("nan"), float("inf"), 3601):
            with self.subTest(value=value), self.assertRaises(CoreError):
                self.api.analyze_external(self.input, {}, None, value)

    def test_config_cannot_supply_arbitrary_arguments(self):
        with self.assertRaises(CoreError):
            self.api.analyze_external(self.input, {}, {"binwalk": {"executable": sys.executable, "args": ["-e"]}}, 1)

    def test_missing_backend_is_explicit(self):
        out = self.api.analyze_external(self.input, {}, {"binwalk": {"executable": str(self.root / "missing")}}, 1)
        self.assertEqual(out["binwalk"]["status"], "dependency_unavailable")
        self.assertEqual(out["ghidra"]["status"], "not_requested")

    def test_unknown_ghidra_format_does_not_guess_loader(self):
        out = self.api.analyze_external(self.input, {}, {"ghidra": {"home": str(self.root), "java_home": str(self.root)}}, 1)
        self.assertEqual(out["ghidra"]["status"], "unsupported_format")

    def test_binwalk_normalizes_real_schema_and_unknown_size(self):
        raw = [{"Analysis": {"file_path": str(self.input), "file_map": [
            {"offset": 1, "size": 0, "name": "unknown", "confidence": 0, "description": "x"}],
            "extractions": {}}}]
        out = self.api.normalize_binwalk(raw, self.input, self.input.stat().st_size)
        self.assertIsNone(out["findings"][0]["size"])
        self.assertEqual(out["findings"][0]["offset"], 1)

    def test_binwalk_rejects_out_of_range_and_extractions(self):
        for finding, extra in (({"offset": 100, "size": 2}, {}), ({"offset": 0, "size": 1}, {"x": {}})):
            raw = [{"Analysis": {"file_path": str(self.input), "file_map": [finding], "extractions": extra}}]
            with self.assertRaises(CoreError):
                self.api.normalize_binwalk(raw, self.input, self.input.stat().st_size)

    def test_binwalk_rejects_wrong_input_path(self):
        raw = [{"Analysis": {"file_path": "/other", "file_map": [], "extractions": {}}}]
        with self.assertRaises(CoreError):
            self.api.normalize_binwalk(raw, self.input, self.input.stat().st_size)

    @unittest.skipUnless(sys.platform == "linux", "Linux runtime launcher")
    def test_process_output_is_bounded(self):
        with self.assertRaises(CoreError):
            self.api._run([sys.executable, "-c", "print('x'*300000)"], self.root, {}, time.monotonic()+5)

    @unittest.skipUnless(sys.platform == "linux", "Linux runtime launcher")
    def test_process_deadline_is_enforced(self):
        started = time.monotonic()
        with self.assertRaises(CoreError):
            self.api._run([sys.executable, "-c", "import time; time.sleep(10)"], self.root, {}, started+.15)
        self.assertLess(time.monotonic()-started, 3)

    def test_json_read_cannot_grow_past_budget_after_stat(self):
        oversized = bytes([34]) + b"x" * (self.api.MAX_JSON - 1) + bytes([34])
        fake = SimpleNamespace(is_symlink=lambda: False, is_file=lambda: True,
                               stat=lambda: SimpleNamespace(st_size=1),
                               open=lambda mode: io.BytesIO(oversized), read_bytes=lambda: oversized)
        with self.assertRaises(CoreError):
            self.api._read_json(fake)

    def test_binwalk_confidence_cannot_expand_normalized_output(self):
        raw = [{"Analysis": {"file_path": str(self.input), "file_map": [
            {"offset": 0, "size": 1, "confidence": ["untrusted"]}], "extractions": {}}}]
        with self.assertRaises(CoreError):
            self.api.normalize_binwalk(raw, self.input, self.input.stat().st_size)

    def test_ghidra_discards_unknown_backend_fields(self):
        raw = {"backend_version": "12.1.4", "functions": [], "analysis_timed_out": False,
               "language_id": "x86:LE:64:default", "compiler_spec": "gcc", "image_base": "00400000",
               "functions_truncated": False, "unexpected": "do not forward"}
        self.assertNotIn("unexpected", self.api._ghidra_result(raw))


class LimitExecCpuScalingTests(unittest.TestCase):
    """_limit_exec.py sets RLIMIT_CPU, which sums CPU time across every
    thread of the process, not wall-clock time. A caller that runs a
    multithreaded tool (e.g. OMP_NUM_THREADS=2 for a CPU OpenCL backend)
    must get a proportionally larger CPU budget, or the process gets
    killed well before its real wall-clock timeout."""

    def setUp(self):
        if sys.platform == "win32":
            self.skipTest("RLIMIT_CPU is POSIX-only")
        self.launcher = str(Path(__file__).resolve().parents[1]
                            / "src" / "cyber_core" / "reverse_engineering" / "_limit_exec.py")

    def _soft_limit(self, env_extra):
        probe = "import resource,sys;sys.stdout.write(str(resource.getrlimit(resource.RLIMIT_CPU)[0]))"
        env = {"PATH": __import__("os").environ.get("PATH", "")}
        env.update(env_extra)
        run = subprocess.run([sys.executable, "-I", self.launcher, "10", sys.executable, "-c", probe],
                             capture_output=True, text=True, timeout=10, env=env)
        return int(run.stdout)

    def test_default_thread_count_keeps_the_original_wall_clock_budget(self):
        self.assertEqual(self._soft_limit({}), 10)

    def test_omp_num_threads_scales_the_cpu_budget_proportionally(self):
        self.assertEqual(self._soft_limit({"OMP_NUM_THREADS": "4"}), 40)

    def test_malformed_thread_count_falls_back_to_one(self):
        self.assertEqual(self._soft_limit({"OMP_NUM_THREADS": "not-a-number"}), 10)
