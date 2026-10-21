"""Real synthetic encrypted fixtures; no client files or recovered secrets in logs."""
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import struct
import zlib
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

    def test_office_fixture_password_and_integrity_are_valid(self):
        import msoffcrypto
        source = self.fixture("office")
        office = msoffcrypto.OfficeFile(io.BytesIO(source.read_bytes()))
        try:
            office.load_key(password=self.password, verify_password=True)
        except Exception as error:
            self.fail("Synthetic Office password verifier failed: " + type(error).__name__)
        try:
            office.decrypt(io.BytesIO(), verify_integrity=True)
        except Exception as error:
            self.fail("Synthetic Office payload integrity failed: " + type(error).__name__)

    def test_header_encrypted_7z_wrong_password_is_a_normal_failed_trial(self):
        import py7zr
        source = self.fixture("7z", variant="headers")
        try:
            py7zr.SevenZipFile(io.BytesIO(source.read_bytes()), password="wrong")
        except Exception as error:
            # Report only the exception class; never candidate text or exception messages.
            print("Synthetic 7z wrong-password exception class:", type(error).__name__)
        done = self.manager.work(self.case, self.start("7z", source)["id"], max_attempts=1, max_seconds=60)
        self.assertEqual(done["status"], "pending")

    def test_zipcrypto_false_header_match_does_not_block_later_correct_password(self):
        # Build a small ZipCrypto fixture in memory; no password goes to argv.
        password = self.password.encode()
        plain = b"synthetic zipcrypto deflated payload" * 4
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("synthetic.txt", plain)
        raw = bytearray(stream.getvalue())
        crc, compressed = struct.unpack_from("<II", raw, 14)
        name_len, extra_len = struct.unpack_from("<HH", raw, 26)
        offset = 30 + name_len + extra_len
        header = bytes(range(11)) + bytes([crc >> 24])
        def crc_byte(value, byte):
            value ^= byte
            for _ in range(8):
                value = (value >> 1) ^ (0xedb88320 if value & 1 else 0)
            return value
        keys = [0x12345678, 0x23456789, 0x34567890]
        def update(byte):
            keys[0] = crc_byte(keys[0], byte)
            keys[1] = ((keys[1] + (keys[0] & 255)) * 134775813 + 1) & 0xffffffff
            keys[2] = crc_byte(keys[2], keys[1] >> 24)
        for byte in password:
            update(byte)
        encrypted = bytearray()
        for byte in header + raw[offset:offset+compressed]:
            temp = keys[2] | 2
            encrypted.append(byte ^ (((temp * (temp ^ 1)) >> 8) & 255))
            update(byte)
        raw[offset:offset+compressed] = encrypted
        struct.pack_into("<H", raw, 6, 1)
        struct.pack_into("<I", raw, 18, compressed + 12)
        central = raw.index(b"PK\x01\x02", offset + len(encrypted))
        struct.pack_into("<H", raw, central + 8, 1)
        struct.pack_into("<I", raw, central + 20, compressed + 12)
        end = raw.index(b"PK\x05\x06", central)
        struct.pack_into("<I", raw, end + 16, central)
        source = self.scope / "legacy.zip"
        source.write_bytes(raw)
        wrong = None
        for number in range(10000):
            candidate = ("synthetic-wrong-" + str(number)).encode()
            decrypt = zipfile._ZipDecrypter(candidate)
            if decrypt(encrypted[:12])[-1] != crc >> 24:
                continue
            try:
                zlib.decompress(decrypt(encrypted[12:]), -15)
            except zlib.error:
                wrong = candidate
                break
        self.assertIsNotNone(wrong, "Synthetic header collision not found within deterministic bound")
        self.material.write_bytes(wrong + b"\n" + password + b"\n")
        job = self.start("zip", source)["id"]
        done = self.manager.work(self.case, job, max_attempts=2, max_seconds=60)
        self.assertEqual(done["status"], "succeeded")
        self.assertEqual(done["attempts"], 2)
