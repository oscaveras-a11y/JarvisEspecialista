"""Explicit display of a successful synthetic candidate; never persisted."""
import json
import tempfile
import unittest
from pathlib import Path
from cyber_core.errors import CoreError
from cyber_core.service import Core
from cyber_core.cryptanalysis.sessions import RecoverySessions

class PasswordDisplayTests(unittest.TestCase):
    def setUp(self):
        from pypdf import PdfWriter
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.scope = root / "scope"
        self.scope.mkdir()
        self.core = Core(root / "state")
        self.addCleanup(self.core.close)
        self.case = self.core.investigate("synthetic", "display", str(self.scope),
            "owner", "synthetic only", recovery=True, valid_hours=24)
        self.source = self.scope / "locked.pdf"
        writer = PdfWriter()
        writer.add_blank_page(width=72, height=72)
        self.password = "synthetic-display-password"
        writer.encrypt(self.password, algorithm="AES-256")
        writer.write(self.source)
        self.material = self.scope / "candidates"
        self.material.write_text("wrong\n" + self.password + "\n", encoding="utf-8")
        self.manager = RecoverySessions(self.core)
        self.job = self.manager.start(self.case, self.source, self.material, mode="pdf")["id"]

    def test_explicit_display_and_default_redaction(self):
        with self.assertRaises(CoreError):
            self.manager.reveal_password(self.case, self.job)
        done = self.manager.work(self.case, self.job)
        self.assertEqual(done["status"], "succeeded")
        self.assertNotIn(self.password, json.dumps(done))
        revealed = self.manager.reveal_password(self.case, self.job)
        self.assertEqual(revealed["password"], self.password)
        self.assertEqual(revealed["password_encoding"], "utf-8")
        self.assertNotIn(self.password, json.dumps(self.manager.jobs(self.case)))
        self.assertNotIn(self.password, self.core.report(self.case).read_text(encoding="utf-8"))
        self.assertTrue(self.core.verify_audit(self.case))

    def test_changed_material_and_paused_case_cannot_reveal(self):
        self.manager.work(self.case, self.job)
        self.core.pause(self.case)
        with self.assertRaises(CoreError):
            self.manager.reveal_password(self.case, self.job)
        self.core.resume(self.case)
        self.material.write_text("wrong\nreplacement\n")
        with self.assertRaises(CoreError):
            self.manager.reveal_password(self.case, self.job)

    def test_cli_requires_explicit_display_flag(self):
        from cyber_core.cli import parser
        args = parser().parse_args(["recovery-session", "show", self.case, self.job, "--show-password"])
        self.assertTrue(args.show_password)
        plain = parser().parse_args(["recovery-session", "show", self.case, self.job])
        self.assertFalse(plain.show_password)

class ExternalLateResultTests(unittest.TestCase):
    @unittest.skipUnless(__import__("sys").platform == "linux", "Linux external profiles")
    def test_pause_and_cancel_during_external_trial_discard_late_success(self):
        import hashlib
        import sys
        from unittest.mock import patch
        from cyber_core.external_tool_runtime import VALIDATION
        for action in ("pause", "cancel"):
            with self.subTest(action=action), tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                scope = root / "scope"
                scope.mkdir()
                source = scope / "digest"
                source.write_text(hashlib.sha256(b"synthetic-password").hexdigest())
                material = scope / "candidates"
                material.write_bytes(b"synthetic-password\n")
                core = Core(root / "state")
                try:
                    case = core.investigate("synthetic", "late response", str(scope), "owner",
                                            "synthetic only", recovery=True, valid_hours=24)
                    manager = RecoverySessions(core)
                    with patch.dict(__import__("os").environ, {"CYBER_JOHN_EXECUTABLE": sys.executable}):
                        job = manager.start(case, source, material, mode="john-sha256")["id"]
                        def late(*args, **kwargs):
                            if action == "pause":
                                core.pause(case)
                            else:
                                manager.cancel(case, job)
                            return {"stdout": json.dumps({"matched": True, "password_validated": True,
                                "format": "john-sha256", "validation": VALIDATION["john-sha256"],
                                "backend_version": "1.2.3", "backend_sha256": "a"*64})}
                        with patch("cyber_core.cryptanalysis.sessions.run_bounded", side_effect=late):
                            result = manager.work(case, job)
                        self.assertIn(result["status"], ("paused", "cancelled"))
                        self.assertIsNone(result["result"])
                        self.assertEqual(result["attempts"], 0)
                finally:
                    core.close()
