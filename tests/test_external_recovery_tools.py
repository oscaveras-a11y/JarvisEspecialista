"""Synthetic, authorized external-tool integration. Real CLIs run only in Actions."""
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cyber_core.errors import CoreError
from cyber_core.service import Core
from cyber_core.cryptanalysis.sessions import RecoverySessions

class ToolInventoryContracts(unittest.TestCase):
    def test_six_backends_have_explicit_availability_without_executing_input(self):
        try:
            from cyber_core.external_tools import tool_inventory
        except ImportError:
            self.fail("External tool adapters have not been implemented")
        with patch.dict(os.environ, {}, clear=True):
            inventory = tool_inventory()
        self.assertEqual(set(inventory), {"hashcat", "john", "qpdf", "openssl", "die", "unblob"})
        for item in inventory.values():
            self.assertFalse(item["available"])
            self.assertIn("reason", item)

    def test_relative_executable_and_unknown_mode_are_rejected(self):
        try:
            from cyber_core.external_tools import external_configuration
        except ImportError:
            self.fail("Trusted executable validation has not been implemented")
        with patch.dict(os.environ, {"CYBER_QPDF_EXECUTABLE": "relative/qpdf"}, clear=True):
            with self.assertRaises(CoreError):
                external_configuration("qpdf")
        with self.assertRaises(CoreError):
            external_configuration("arbitrary-shell")

class ExternalFailureContracts(unittest.TestCase):
    def test_malformed_and_partial_analysis_is_rejected(self):
        from cyber_core.external_tools_child import normalize_die, normalize_unblob
        with self.assertRaises(CoreError):
            normalize_die({"detects": "truncated"})
        with self.assertRaises(CoreError):
            normalize_unblob([{"task": {"path": "/target"}, "reports": [
                {"__typename__": "ChunkReport", "start_offset": 0, "end_offset": 100,
                 "handler_name": "tar", "extraction_reports": []}], "subtasks": []}], Path("/target"), 10)
        with self.assertRaises(CoreError):
            normalize_unblob([{"task": {"path": "/target"}, "reports": [],
                              "subtasks": [{"path": "/unexpected"}]}], Path("/target"), 10)

    @unittest.skipUnless(sys.platform == "linux", "Linux CLI runtime")
    def test_raw_failure_output_and_environment_are_not_exposed(self):
        from cyber_core.external_tool_runtime import Runner
        with tempfile.TemporaryDirectory() as folder:
            with patch.dict(os.environ, {"GITHUB_TOKEN": "synthetic-private-token",
                                       "ANTHROPIC_API_KEY": "synthetic-private-key"}):
                runner = Runner(Path(folder), 5)
            self.assertNotIn("GITHUB_TOKEN", runner.env)
            self.assertNotIn("ANTHROPIC_API_KEY", runner.env)
            with self.assertRaises(CoreError) as caught:
                runner.run([sys.executable, "-c", "import sys; print('synthetic-secret'); sys.exit(2)"])
            self.assertNotIn("synthetic-secret", str(caught.exception))

    @unittest.skipUnless(sys.platform == "linux", "Linux CLI runtime")
    def test_output_limit_is_failure_instead_of_partial_success(self):
        from cyber_core.external_tool_runtime import Runner
        with tempfile.TemporaryDirectory() as folder:
            runner = Runner(Path(folder), 5)
            with self.assertRaises(CoreError):
                runner.run([sys.executable, "-c", "print('X'*8192)"], output_limit=32)

    @unittest.skipUnless(sys.platform == "linux", "Linux CLI runtime")
    def test_cli_success_without_password_match_is_not_success(self):
        from cyber_core.external_tools_child import trial
        from pypdf import PdfWriter
        writer = PdfWriter()
        writer.add_blank_page(width=72, height=72)
        writer.encrypt("synthetic-right", algorithm="AES-256")
        raw = io.BytesIO()
        writer.write(raw)
        with patch("cyber_core.external_tools_child.version", return_value="1.2.3"), \
             patch("cyber_core.external_tools_child.Runner.run", return_value=(0, b"", b"")):
            result = trial("qpdf-pdf", raw.getvalue(), b"synthetic-wrong",
                           {"executable": sys.executable})
        self.assertEqual(result, {"matched": False})

@unittest.skipUnless(os.environ.get("CYBER_REQUIRE_EXTERNAL_TOOLS") == "1",
                     "Real six-tool integration executes in its dedicated Linux Actions workflow")
class RealExternalRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.scope = self.root / "scope"
        self.scope.mkdir()
        self.core = Core(self.root / "state", timeout=180)
        self.addCleanup(self.core.close)
        self.case = self.core.investigate("synthetic", "external tools", str(self.scope),
            "owner", "Synthetic fixtures only", recovery=True, valid_hours=72)
        self.password = b"synthetic-owner-2026"
        self.material = self.scope / "candidates"
        self.material.write_bytes(b"synthetic-wrong\n" + self.password + b"\n")
        self.manager = RecoverySessions(self.core)

    def start(self, mode, source, **kwargs):
        try:
            return self.manager.start(self.case, source, self.material, mode=mode, **kwargs)
        except CoreError:
            self.fail("External recovery profile is not implemented: " + mode)

    def check_session(self, mode, source, *, output=False, **kwargs):
        job = self.start(mode, source, **kwargs)["id"]
        first = self.manager.work(self.case, job, max_attempts=1, max_seconds=180)
        self.assertEqual(first["status"], "pending", first)
        self.assertIsNone(first["result"])
        done = self.manager.work(self.case, job, max_attempts=1, max_seconds=180)
        self.assertEqual(done["status"], "succeeded", done)
        self.assertTrue(done["result"]["password_validated"])
        self.assertIn("backend_version", done["result"])
        self.assertNotIn(self.password.decode(), json.dumps(done))
        report = self.core.report(self.case).read_text(encoding="utf-8")
        self.assertNotIn(self.password.decode(), report)
        self.assertIn(job, report)
        self.assertTrue(self.core.verify_audit(self.case))
        self.assertEqual("output" in done["result"], output)
        self.assertEqual(self.manager.reveal_password(self.case, job)["password"], self.password.decode())
        self.assertNotIn(self.password.decode(), self.core.report(self.case).read_text(encoding="utf-8"))
        return done

    def test_all_six_real_tools_are_available(self):
        try:
            from cyber_core.external_tools import tool_inventory
        except ImportError:
            self.fail("External tool inventory is not implemented")
        inventory = tool_inventory()
        self.assertEqual(set(inventory), {"hashcat","john","qpdf","openssl","die","unblob"})
        self.assertTrue(all(item["available"] for item in inventory.values()), inventory)

    def test_qpdf_wrong_correct_without_plaintext_export(self):
        from pypdf import PdfWriter
        writer = PdfWriter()
        writer.add_blank_page(width=72, height=72)
        writer.encrypt(self.password.decode(), algorithm="AES-256")
        source = self.scope / "locked.pdf"
        writer.write(source)
        self.check_session("qpdf-pdf", source)

    def test_openssl_pkcs12_wrong_and_correct(self):
        source = self.scope / "certificate.p12"
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        source.write_bytes(pkcs12.serialize_key_and_certificates(b"synthetic", key, None, None,
            serialization.BestAvailableEncryption(self.password)))
        self.check_session("openssl-pkcs12", source)

    def test_openssl_aes_cbc_is_not_a_supported_profile(self):
        source = self.scope / "encrypted.openssl"
        source.write_bytes(b"Salted__" + b"synthetic" * 8)
        with self.assertRaises(CoreError):
            self.manager.start(self.case, source, self.material, mode="openssl-aes256cbc")

    def test_hashcat_sha256_wrong_and_correct_using_real_cpu_backend(self):
        source = self.scope / "sha256.txt"
        source.write_text(hashlib.sha256(self.password).hexdigest() + "\n")
        self.check_session("hashcat-sha256", source)

    def test_john_jumbo_sha256_wrong_and_correct(self):
        source = self.scope / "sha256.txt"
        source.write_text(hashlib.sha256(self.password).hexdigest() + "\n")
        self.check_session("john-sha256", source)

    def zip_fixture(self):
        import pyzipper
        source = self.scope / "locked.zip"
        with pyzipper.AESZipFile(source, "w", encryption=pyzipper.WZ_AES) as archive:
            archive.setpassword(self.password)
            archive.writestr("synthetic.txt", b"Synthetic encrypted ZIP payload")
        return source

    def test_john_jumbo_zip2john_on_a_real_encrypted_archive(self):
        self.check_session("john-zip", self.zip_fixture())

    def test_hashcat_zip_aes_via_john_converter(self):
        self.check_session("hashcat-zip-aes", self.zip_fixture())

    def test_die_and_unblob_acquire_and_persist_real_static_results(self):
        try:
            from cyber_core.external_tools import analyze_tool
        except ImportError:
            self.fail("External analysis integration is not implemented")
        # ELF is compiled in the runner but never executed.
        elf = self.scope / "synthetic.elf"
        cfile = self.root / "synthetic.c"
        cfile.write_text("int main(void){return 0;}")
        compiled = subprocess.run(["gcc", str(cfile), "-o", str(elf)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
        self.assertEqual(compiled.returncode, 0)
        die = analyze_tool(self.core, self.case, elf, tool="die")
        self.assertEqual(die["analysis"]["backend"], "die")
        self.assertTrue(die["analysis"]["identified"])
        archive = self.scope / "synthetic.tar"
        with tarfile.open(archive, "w", format=tarfile.USTAR_FORMAT) as tar:
            info = tarfile.TarInfo("synthetic.txt")
            info.size = 6
            tar.addfile(info, io.BytesIO(b"hello\n"))
        unblob = analyze_tool(self.core, self.case, archive, tool="unblob")
        self.assertEqual(unblob["analysis"]["backend"], "unblob")
        self.assertTrue(unblob["analysis"]["identified"])
        self.assertFalse(unblob["analysis"]["extraction_enabled"])
        self.assertTrue(self.core.verify_audit(self.case))
        report = self.core.report(self.case).read_text(encoding="utf-8")
        self.assertIn("external_analysis", report)
        self.core.pause(self.case)
        with self.assertRaises(CoreError):
            analyze_tool(self.core, self.case, elf, tool="die")

    def test_external_profile_rechecks_pause_and_cancel(self):
        source = self.scope / "sha256.txt"
        source.write_text(hashlib.sha256(self.password).hexdigest())
        job = self.start("john-sha256", source)["id"]
        self.core.pause(self.case)
        with self.assertRaises(CoreError):
            self.manager.work(self.case, job)
        self.assertEqual(self.manager.get(self.case, job)["attempts"], 0)
        self.core.resume(self.case)
        self.manager.cancel(self.case, job)
        self.assertEqual(self.manager.work(self.case, job)["status"], "cancelled")
