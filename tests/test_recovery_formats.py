"""Real synthetic encrypted fixtures; no client files or recovered secrets in logs."""
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import zipfile

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cyber_core.errors import CoreError
from cyber_core.service import Core
from cyber_core.cryptanalysis.sessions import RecoverySessions

OPTIONAL = ("pyzipper", "py7zr", "pypdf", "msoffcrypto")
AVAILABLE = all(importlib.util.find_spec(name) for name in OPTIONAL)

@unittest.skipUnless(AVAILABLE, "Install the recovery extra for multi-format fixtures")
class MultiFormatRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.scope = self.root / "scope"
        self.scope.mkdir()
        self.core = Core(self.root / "state", timeout=60)
        self.addCleanup(self.core.close)
        self.case = self.core.investigate("synthetic", "Formats", str(self.scope), "owner",
                                          "Synthetic encrypted fixtures", recovery=True, valid_hours=72)
        self.password = " synthetic-ç-owner "
        self.material = self.scope / "candidates.txt"
        self.material.write_text("wrong\n" + self.password + "\n", encoding="utf-8")
        self.manager = RecoverySessions(self.core)

    def fixture(self, mode, *, encrypted=True, variant=None):
        path = self.scope / (mode + ".bin")
        if mode == "zip":
            import pyzipper
            if encrypted:
                with pyzipper.AESZipFile(path, "w", encryption=pyzipper.WZ_AES) as archive:
                    archive.setpassword(self.password.encode())
                    archive.writestr("synthetic.txt", b"synthetic payload")
            else:
                with zipfile.ZipFile(path, "w") as archive:
                    archive.writestr("synthetic.txt", b"synthetic payload")
        elif mode == "7z":
            import py7zr
            with py7zr.SevenZipFile(path, "w", password=self.password if encrypted else None,
                                   header_encryption=variant == "headers") as archive:
                archive.writestr(b"synthetic payload", "synthetic.txt")
        elif mode == "pdf":
            from pypdf import PdfWriter
            writer = PdfWriter()
            writer.add_blank_page(width=72, height=72)
            if encrypted:
                writer.encrypt(self.password, algorithm=variant or "AES-256")
            writer.write(path)
        elif mode == "office":
            from msoffcrypto.format.ooxml import OOXMLFile
            plain = io.BytesIO()
            with zipfile.ZipFile(plain, "w") as archive:
                archive.writestr("[Content_Types].xml",
                    '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>')
                archive.writestr("word/document.xml",
                    '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"/>')
            if encrypted:
                plain.seek(0)
                with path.open("wb") as output:
                    OOXMLFile(plain).encrypt(self.password, output)
            else:
                path.write_bytes(plain.getvalue())
        elif mode == "pkcs12":
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            protection = (serialization.BestAvailableEncryption(self.password.encode()) if encrypted
                          else serialization.NoEncryption())
            path.write_bytes(pkcs12.serialize_key_and_certificates(b"synthetic", key, None, None, protection))
        return path

    def start(self, mode, source=None):
        try:
            return self.manager.start(self.case, source or self.fixture(mode), self.material, mode=mode)
        except CoreError:
            self.fail("The requested multi-format recovery mode is not implemented")

    def check_success(self, mode, variant=None):
        source = self.fixture(mode, variant=variant)
        job = self.start(mode, source)["id"]
        first = self.manager.work(self.case, job, max_attempts=1, max_seconds=60)
        self.assertEqual(first["status"], "pending", first)
        self.assertIsNone(first["result"])
        done = self.manager.work(self.case, job, max_attempts=1, max_seconds=60)
        self.assertEqual(done["status"], "succeeded", done)
        self.assertEqual(done["attempts"], 2)
        self.assertTrue(done["result"]["password_validated"])
        self.assertEqual(done["result"]["format"], mode)
        self.assertNotIn("output", done["result"])
        report = self.core.report(self.case).read_text(encoding="utf-8")
        self.assertIn(job, report)
        self.assertNotIn(self.password, report)
        self.assertNotIn(self.password, json.dumps(done))
        self.assertTrue(self.core.verify_audit(self.case))
        self.assertFalse(list((self.core.home / "cases").rglob("*.recovered")))

    def test_zip_aes_wrong_then_correct(self):
        self.check_success("zip")

    def test_7z_wrong_then_correct(self):
        self.check_success("7z")

    def test_7z_encrypted_headers(self):
        self.check_success("7z", "headers")

    def test_pdf_aes256_wrong_then_correct(self):
        self.check_success("pdf")

    def test_pdf_aes128_wrong_then_correct(self):
        self.check_success("pdf", "AES-128")

    def test_office_agile_wrong_then_correct(self):
        self.check_success("office")

    def test_pkcs12_wrong_then_correct(self):
        self.check_success("pkcs12")

    def test_unencrypted_files_never_match_an_arbitrary_candidate(self):
        for mode in ("zip", "7z", "pdf", "office", "pkcs12"):
            with self.subTest(mode=mode):
                source = self.fixture(mode, encrypted=False)
                try:
                    job = self.manager.start(self.case, source, self.material, mode=mode)["id"]
                except CoreError:
                    continue  # Plain OOXML has a ZIP signature, not encrypted Office.
                done = self.manager.work(self.case, job, max_attempts=2, max_seconds=60)
                self.assertNotEqual(done["status"], "succeeded")
                self.assertIsNone(done["result"])

    def test_case_scope_and_pause_still_apply_to_new_formats(self):
        source = self.fixture("pdf")
        job = self.start("pdf", source)["id"]
        self.core.pause(self.case)
        with self.assertRaises(CoreError):
            self.manager.work(self.case, job)
        self.assertEqual(self.manager.get(self.case, job)["attempts"], 0)
        self.core.resume(self.case)
        self.manager.cancel(self.case, job)
        self.assertEqual(self.manager.work(self.case, job)["status"], "cancelled")

    def test_auto_mode_uses_bytes_not_extension(self):
        source = self.fixture("pdf")
        job = self.start("auto", source)
        self.assertEqual(job["mode"], "pdf")

    def test_cli_accepts_new_mode_and_reports_missing_dependencies_separately(self):
        result = subprocess.run([sys.executable, "-m", "cyber_core", "--home", str(self.core.home),
            "recovery-session", "start", self.case, str(self.fixture("zip")), "--candidates",
            str(self.material), "--mode", "zip"], capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 0, result.stderr)
        formats = subprocess.run([sys.executable, "-m", "cyber_core", "--home", str(self.core.home),
            "recovery-formats"], capture_output=True, text=True, timeout=30)
        self.assertEqual(formats.returncode, 0, formats.stderr)
        inventory = json.loads(formats.stdout)
        self.assertTrue(inventory["zip"]["available"])
        self.assertFalse(inventory["rar"]["available"])
        self.assertIn("reason", inventory["rar"])

    def test_malformed_payload_cannot_be_reported_as_recovered(self):
        for mode, header in (("zip", b"PK\x03\x04"), ("7z", b"7z\xbc\xaf\x27\x1c"),
                             ("pdf", b"%PDF-1.7"), ("office", bytes.fromhex("d0cf11e0a1b11ae1")),
                             ("pkcs12", b"0")):
            with self.subTest(mode=mode):
                source = self.scope / "bad"
                source.write_bytes(header + b"synthetic broken data")
                job = self.start(mode, source)["id"]
                done = self.manager.work(self.case, job, max_attempts=2, max_seconds=60)
                self.assertNotEqual(done["status"], "succeeded")
                self.assertIsNone(done["result"])
