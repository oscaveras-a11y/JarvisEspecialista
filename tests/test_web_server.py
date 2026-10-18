"""Real HTTP -> CORE -> SQLite/report contracts, synthetic inputs only."""
import base64
import hashlib
import json
import os
from pathlib import Path
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request

from cyber_core.web_server import create_server


class WebServerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name) / "state"
        self.web = Path(__file__).resolve().parents[1] / "web"
        self.start()
        self.addCleanup(self.stop)

    def start(self):
        self.server = create_server(self.home, self.web, port=0)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.url = "http://127.0.0.1:" + str(self.server.server_port)
        self.token = self.request("/api/health")[1]["token"]

    def stop(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)

    def request(self, path, data=None, headers=None, method=None):
        headers = {"X-Cyber-Request": getattr(self, "token", ""), **(headers or {})}
        if data is not None:
            headers["Content-Type"] = "application/json"
            data = json.dumps(data).encode()
        req = urllib.request.Request(self.url + path, data=data, headers=headers, method=method)
        try:
            response = urllib.request.urlopen(req, timeout=15)
        except urllib.error.HTTPError as exc:
            response = exc
        with response:
            raw = response.read()
            try:
                result = json.loads(raw)
            except ValueError:
                result = raw
            return response.status, result

    def case(self, **fields):
        body = dict(project="Synthetic HTTP case", objective="Known bytes", owner="owner",
                    authorization="Synthetic files authorized", allowRecovery=True, validHours=24)
        body.update(fields)
        code, result = self.request("/api/cases", body)
        self.assertEqual(code, 201, result)
        return result["id"]

    def upload(self, case, raw, tool="analyze-file", name="sample.bin", candidates=None):
        body = {"name": name, "content_base64": base64.b64encode(raw).decode(), "tool": tool}
        if candidates is not None:
            body["candidates"] = candidates
        return self.request("/api/cases/" + case + "/files", body)

    def settled(self):
        deadline = time.monotonic() + (210 if os.environ.get('CYBER_BETA_REAL_TOOLS') == '1' else 30)
        while time.monotonic() < deadline:
            code, state = self.request("/api/state")
            self.assertEqual(code, 200, state)
            if not state["busy"]:
                return state
            time.sleep(.05)
        self.fail("CORE job did not settle")

    def test_real_hash_audit_report_and_reopen(self):
        self.assertEqual(self.request("/api/state")[1]["cases"], [])
        case = self.case()
        raw = b"%PDF-1.7\nSynthetic authorized document\n"
        status, reply = self.upload(case, raw)
        self.assertEqual(status, 202, reply)
        state = self.settled()
        self.assertEqual(state["tasks"][0]["status"], "done")
        self.assertEqual(state["results"][case][0]["sha256"], hashlib.sha256(raw).hexdigest())
        self.assertTrue(state["audit_valid"][case])
        status, report = self.request("/api/cases/" + case + "/report", {})
        self.assertEqual(status, 200)
        self.assertIn(hashlib.sha256(raw).hexdigest(), report["text"])
        self.stop()
        self.start()
        reopened = self.request("/api/state")[1]
        self.assertEqual(reopened["cases"][0]["id"], case)
        self.assertEqual(reopened["tasks"][0]["status"], "done")
        self.assertTrue(reopened["audit_valid"][case])
        self.assertEqual(len(reopened["reports"]), 1)

    def test_pause_cancel_and_unknown_case_are_enforced_by_server(self):
        case = self.case()
        prefix = "/api/cases/" + case
        self.assertEqual(self.request(prefix + "/pause", {})[0], 200)
        self.assertEqual(self.upload(case, b"x")[0], 409)
        self.assertEqual(self.request(prefix + "/resume", {})[0], 200)
        self.assertEqual(self.request(prefix + "/cancel", {"reason": "Synthetic test complete"})[0], 200)
        self.assertEqual(self.upload(case, b"x")[0], 409)
        self.assertEqual(self.request(prefix + "/resume", {})[0], 409)
        self.assertEqual(self.upload("f" * 32, b"x")[0], 404)

    def test_nonce_origin_host_and_static_file_boundary(self):
        self.assertEqual(self.request("/api/cases", {}, headers={"X-Cyber-Request": ""})[0], 403)
        self.assertEqual(self.request("/api/cases", {}, headers={"Origin": "https://example.invalid"})[0], 403)
        self.assertEqual(self.request("/api/state", headers={"Host": "evil.invalid"})[0], 403)
        self.assertEqual(self.request("/src/cyber_core/service.py")[0], 404)
        self.assertEqual(self.request("/web/../../AGENTS.md")[0], 404)
        self.assertEqual(self.request("/")[0], 200)

    def test_rejects_paths_bad_base64_tools_and_oversized_inputs(self):
        case = self.case()
        self.assertEqual(self.upload(case, b"x", name="../escape.bin")[0], 400)
        self.assertEqual(self.upload(case, b"x", tool="shell")[0], 400)
        self.assertEqual(self.upload(case, b"x" * (4 * 1024 * 1024 + 1))[0], 413)
        self.assertEqual(self.request("/api/cases/" + case + "/files",
                                     {"name": "x.bin", "tool": "analyze-file", "content_base64": "!!!"})[0], 400)
        self.assertEqual(self.request("/api/cases", {"scope": "/etc"})[0], 400)
        self.assertEqual(self.request("/api/state")[1]["tasks"], [])

    def test_pcap_inventory_is_real_and_reportable(self):
        import struct
        raw = struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
        case = self.case()
        status, reply = self.upload(case, raw, tool="inventory-pcap", name="empty.pcap")
        self.assertEqual(status, 202, reply)
        state = self.settled()
        self.assertIsNone(state["last_error"])
        self.assertEqual(state["operations"][case][0]["kind"], "pcap_inventory")
        self.assertTrue(state["audit_valid"][case])

    def test_recovery_assessment_uses_core_without_claiming_decryption(self):
        case = self.case()
        raw = b"CCAES1" + bytes(range(12)) + b"x" * 32
        status, reply = self.upload(case, raw, tool="assess-recovery", name="sample.ccaes")
        self.assertEqual(status, 202, reply)
        state = self.settled()
        assessment = state["results"][case][0]["recovery_assessment"]
        self.assertEqual(assessment["format_id"], "ccaes1")
        self.assertFalse(assessment["recovery_demonstrated"])
        self.assertTrue(state["audit_valid"][case])

    def test_recover_password_finds_real_zip_password_without_auditing_it(self):
        import shutil, subprocess, tempfile
        if not shutil.which("zip"):
            self.skipTest("zip CLI not available in this environment")
        case = self.case()
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "doc.txt"
            source.write_bytes(b"conteudo autorizado de teste http")
            archive = Path(tmp) / "protected.zip"
            subprocess.run(["zip", "-q", "-e", "-P", "senha-via-painel", str(archive), "-j", str(source)],
                           check=True, capture_output=True)
            raw = archive.read_bytes()
        status, reply = self.upload(case, raw, tool="recover-password", name="protected.zip",
                                    candidates=["errada-1", "senha-via-painel", "errada-2"])
        self.assertEqual(status, 202, reply)
        state = self.settled()
        self.assertEqual(state["recovery_result"]["recovered"], True)
        self.assertEqual(state["recovery_result"]["password"], "senha-via-painel")
        self.assertEqual(state["recovery_result"]["format_id"], "zip")
        blob = json.dumps(state["audit"])
        self.assertNotIn("senha-via-painel", blob)
        self.assertTrue(state["audit_valid"][case])

    def test_recover_password_reports_unsupported_format_honestly(self):
        case = self.case()
        raw = b"Rar!\x1a\x07\x01\x00" + b"\x00" * 32
        status, reply = self.upload(case, raw, tool="recover-password", name="archive.rar", candidates=["x"])
        self.assertEqual(status, 202, reply)
        state = self.settled()
        self.assertEqual(state["recovery_result"]["recovered"], False)
        self.assertEqual(state["recovery_result"]["status"], "unsupported_format")

    def test_modified_result_or_evidence_is_not_presented_as_verified(self):
        from cyber_core.service import Core
        case = self.case()
        status, reply = self.upload(case, b"%PDF-1.7\nSynthetic integrity test\n")
        self.assertEqual(status, 202, reply)
        state = self.settled()
        result = state["results"][case][0]
        Path(result["copy"]).write_bytes(b"modified")
        changed = self.request("/api/state")[1]
        self.assertEqual(changed["results"][case], [])
        self.assertIn(case, changed["result_errors"])
        self.assertEqual(self.request("/api/cases/" + case + "/report", {})[0], 409)
        Path(result["copy"]).write_bytes(b"%PDF-1.7\nSynthetic integrity test\n")
        core = Core(self.home / "core")
        try:
            with core.db:
                altered = dict(result, sha256="0" * 64)
                core.db.execute("UPDATE results SET data=? WHERE case_id=?", (json.dumps(altered), case))
        finally:
            core.close()
        changed = self.request("/api/state")[1]
        self.assertEqual(changed["results"][case], [])
        self.assertIn(case, changed["result_errors"])

    @unittest.skipUnless(os.environ.get("CYBER_BETA_REAL_TOOLS") == "1", "Pinned tools run in the Linux tools job")
    def test_real_ghidra_and_binwalk_through_http(self):
        import gzip
        import subprocess
        root = Path(self.tmp.name)
        source, binary = root / "synthetic.c", root / "synthetic.elf"
        source.write_text("__attribute__((noinline)) int fixture_entry(void) { return 42; }\n")
        subprocess.run(["gcc", "-O0", "-fno-pie", "-no-pie", "-nostdlib", "-Wl,-e,fixture_entry",
                        "-o", str(binary), str(source)], check=True, timeout=30)
        case = self.case()
        status, reply = self.upload(case, binary.read_bytes(), tool="analyze-firmware", name="synthetic.elf")
        self.assertEqual(status, 202, reply)
        state = self.settled()
        self.assertIsNone(state["last_error"])
        ghidra = state["results"][case][0]["firmware"]["external_analysis"]["ghidra"]
        self.assertEqual(ghidra["status"], "completed")
        self.assertTrue(any(f["status"] == "decompiled" and ("42" in f["pseudocode"] or "0x2a" in f["pseudocode"]) for f in ghidra["functions"]))
        raw = b"Z" * 256 + gzip.compress(b"synthetic firmware\n" * 16, mtime=0)
        status, reply = self.upload(case, raw, tool="analyze-firmware", name="synthetic.bin")
        self.assertEqual(status, 202, reply)
        state = self.settled()
        self.assertIsNone(state["last_error"])
        scan = state["results"][case][-1]["firmware"]["external_analysis"]["binwalk"]
        self.assertEqual(scan["status"], "completed")
        self.assertTrue(any(f["offset"] == 256 and f["name"] == "gzip" for f in scan["findings"]))
        self.assertEqual(scan["input_sha256"], hashlib.sha256(raw).hexdigest())
