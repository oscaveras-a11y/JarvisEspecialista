"""Real HTTP -> CORE -> SQLite/report contracts, synthetic inputs only."""
import base64
import hashlib
import json
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

    def upload(self, case, raw, tool="analyze-file", name="sample.bin"):
        return self.request("/api/cases/" + case + "/files",
                            {"name": name, "content_base64": base64.b64encode(raw).decode(), "tool": tool})

    def settled(self):
        deadline = time.monotonic() + 30
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
        self.assertEqual(self.upload(case, raw)[0], 202)
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
        self.assertEqual(self.upload(case, raw, tool="inventory-pcap", name="empty.pcap")[0], 202)
        state = self.settled()
        self.assertIsNone(state["last_error"])
        self.assertEqual(state["operations"][case][0]["kind"], "pcap_inventory")
        self.assertTrue(state["audit_valid"][case])

    def test_recovery_assessment_uses_core_without_claiming_decryption(self):
        case = self.case()
        raw = b"CCAES1" + bytes(range(12)) + b"x" * 32
        self.assertEqual(self.upload(case, raw, tool="assess-recovery", name="sample.ccaes")[0], 202)
        state = self.settled()
        assessment = state["results"][case][0]["recovery_assessment"]
        self.assertEqual(assessment["format_id"], "ccaes1")
        self.assertFalse(assessment["recovery_demonstrated"])
        self.assertTrue(state["audit_valid"][case])
