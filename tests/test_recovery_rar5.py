"""RAR5 password checks: structural negatives and real synthetic archives in Actions."""
import hashlib
import io
import json
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest
import zlib
from unittest.mock import patch
from cyber_core.errors import CoreError

MAGIC = b"Rar!\x1a\x07\x01\x00"

def vint(number):
    result = bytearray()
    while number >= 128:
        result.append((number & 127) | 128)
        number >>= 7
    return bytes(result + bytes([number]))

def block(kind, flags, body):
    data = vint(kind) + vint(flags) + body
    encoded = vint(len(data)) + data
    return struct.pack("<I", zlib.crc32(encoded)) + encoded

def encrypted_header(password=b"synthetic-password", *, kdf=5, flags=1, bad_check=False):
    salt = bytes(range(16))
    derived = hashlib.pbkdf2_hmac("sha256", password, salt, (1 << kdf) + 32, 32)
    check = bytes(derived[i] ^ derived[i+8] ^ derived[i+16] ^ derived[i+24] for i in range(8))
    checksum = hashlib.sha256(check).digest()[:4]
    if bad_check:
        checksum = b"BAD!"
    crypt = vint(0) + vint(flags) + bytes([kdf]) + salt
    if flags & 1:
        crypt += check + checksum
    # Synthetic header-only vector: it tests the verifier, not payload validity.
    return MAGIC + block(4, 0, crypt) + bytes(range(16)) + b"\0" * 32

class Rar5StructuralContracts(unittest.TestCase):
    def test_native_password_check_and_integrity_scope(self):
        from cyber_core.cryptanalysis.formats import validate_password, select_mode
        raw = encrypted_header()
        self.assertEqual(select_mode("auto", raw[:64]), "rar5")
        self.assertEqual(validate_password("rar5", raw, b"wrong"), {"matched": False})
        correct = validate_password("rar5", raw, b"synthetic-password")
        self.assertTrue(correct["password_validated"])
        self.assertFalse(correct["payload_integrity_verified"])
        self.assertEqual(correct["format"], "rar5")

    def test_corrupted_crc_and_check_checksum_are_not_wrong_passwords(self):
        from cyber_core.cryptanalysis.formats import validate_password
        broken = bytearray(encrypted_header())
        broken[8] ^= 1
        for raw in (bytes(broken), encrypted_header(bad_check=True)):
            with self.subTest(raw_size=len(raw)), self.assertRaises((CoreError, ValueError)):
                validate_password("rar5", raw, b"synthetic-password")

    def test_absent_verifier_and_truncated_header_are_rejected(self):
        from cyber_core.cryptanalysis.formats import validate_password
        for raw in (encrypted_header(flags=0), encrypted_header()[:18], MAGIC + b"\0"*4 + b"\x80"*4):
            with self.subTest(size=len(raw)), self.assertRaises((CoreError, ValueError)):
                validate_password("rar5", raw, b"synthetic-password")

    def test_kdf_and_volume_limits_fail_before_expensive_work(self):
        from cyber_core.cryptanalysis.formats import validate_password
        # Excessive KDF record contains no expensive test-side derivation.
        crypt = b"\0\x01\x1f" + bytes(16) + bytes(12)
        volume = MAGIC + block(1, 0, b"\x01") + block(5, 0, b"\0")
        for raw in (MAGIC + block(4, 0, crypt) + bytes(48), volume):
            with self.assertRaises((CoreError, ValueError)):
                validate_password("rar5", raw, b"synthetic-password")

    def test_rar4_and_unencrypted_rar5_do_not_claim_password_success(self):
        from cyber_core.cryptanalysis.formats import validate_password
        for raw in (b"Rar!\x1a\x07\0" + bytes(80), MAGIC + block(1, 0, b"\0") + block(5, 0, b"\0")):
            with self.assertRaises((CoreError, ValueError)):
                validate_password("rar5", raw, b"synthetic-password")

    def test_external_profile_requires_its_rar_converter(self):
        import sys
        from cyber_core.external_tools import select_external_mode
        with patch.dict(os.environ, {"CYBER_JOHN_EXECUTABLE": sys.executable}, clear=True):
            with self.assertRaises(CoreError):
                select_external_mode("john-rar5", MAGIC)

@unittest.skipUnless(os.environ.get("CYBER_REQUIRE_RAR5") == "1", "Real RAR5 fixtures run only in dedicated Linux Actions")
class RealRar5RecoveryTests(unittest.TestCase):
    def setUp(self):
        from cyber_core.service import Core
        from cyber_core.cryptanalysis.sessions import RecoverySessions
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.scope = self.root / "scope"
        self.scope.mkdir()
        self.core = Core(self.root / "state", timeout=120)
        self.addCleanup(self.core.close)
        self.case = self.core.investigate("synthetic", "RAR5", str(self.scope), "owner",
            "Synthetic RAR5 fixtures only", recovery=True, valid_hours=24)
        self.manager = RecoverySessions(self.core)
        self.password = b"synthetic-rar5-2026"
        self.material = self.scope / "candidates"
        self.material.write_bytes(b"wrong\n" + self.password + b"\n")

    def fixture(self, *, headers=False, compressed=False, name="sample.rar", member="synthetic.txt", password=None):
        source = self.scope / name
        (self.scope / member).write_bytes(b"Synthetic payload only\n" * 40)
        secret = password or self.password
        # Password prompt and confirmation use stdin, never argv.
        command = [os.environ["CYBER_RAR_FIXTURE_EXECUTABLE"], "a", "-idq", "-m3" if compressed else "-m0",
                   "-hp" if headers else "-p", str(source), member]
        result = subprocess.run(command, input=secret + b"\n" + secret + b"\n",
            cwd=self.scope, env={"PATH": "/usr/bin:/bin", "HOME": str(self.root), "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"},
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
        self.assertEqual(result.returncode, 0, "Synthetic RAR generator failed")
        self.assertTrue(source.read_bytes().startswith(MAGIC))
        return source

    def check(self, source, mode):
        job = self.manager.start(self.case, source, self.material, mode=mode)["id"]
        wrong = self.manager.work(self.case, job, max_attempts=1, max_seconds=120)
        self.assertEqual(wrong["status"], "pending", wrong)
        done = self.manager.work(self.case, job, max_attempts=1, max_seconds=120)
        self.assertEqual(done["status"], "succeeded", done)
        self.assertTrue(done["result"]["password_validated"])
        self.assertFalse(done["result"]["payload_integrity_verified"])
        self.assertNotIn("output", done["result"])
        self.assertNotIn(self.password.decode(), json.dumps(done))
        self.assertEqual(self.manager.reveal_password(self.case, job)["password"], self.password.decode())
        self.assertNotIn(self.password.decode(), self.core.report(self.case).read_text(encoding="utf-8"))
        self.assertTrue(self.core.verify_audit(self.case))

    def test_real_native_and_john_headers_payload_compressed_and_stored(self):
        for headers in (False, True):
            for compressed in (False, True):
                source = self.fixture(headers=headers, compressed=compressed,
                                      name="case-%d-%d.rar" % (headers, compressed))
                for mode in ("rar5", "john-rar5"):
                    with self.subTest(headers=headers, compressed=compressed, mode=mode):
                        self.check(source, mode)

    def test_real_multiple_members_all_verifiers_must_match(self):
        source = self.fixture(member="one.txt")
        self.fixture(member="two.txt", password=b"different-synthetic")
        self.material.write_bytes(self.password + b"\n")
        for mode in ("rar5", "john-rar5"):
            with self.subTest(mode=mode):
                job = self.manager.start(self.case, source, self.material, mode=mode)["id"]
                result = self.manager.work(self.case, job, max_seconds=120)
                self.assertEqual(result["status"], "exhausted", result)
                self.assertIsNone(result["result"])

    def test_real_no_match_is_exhausted_and_plain_archive_is_rejected(self):
        source = self.fixture()
        self.material.write_bytes(b"wrong-one\nwrong-two\n")
        for mode in ("rar5", "john-rar5"):
            job = self.manager.start(self.case, source, self.material, mode=mode)["id"]
            result = self.manager.work(self.case, job, max_seconds=120)
            self.assertEqual(result["status"], "exhausted", result)

    def test_real_changed_evidence_and_pause_do_not_publish(self):
        from cyber_core.verification.artifacts import verified_result
        source = self.fixture()
        job = self.manager.start(self.case, source, self.material, mode="rar5")["id"]
        self.core.pause(self.case)
        with self.assertRaises(CoreError):
            self.manager.work(self.case, job)
        self.assertEqual(self.manager.get(self.case, job)["attempts"], 0)
        self.core.resume(self.case)
        artifact, _ = verified_result(self.core, self.case, self.manager._row(self.case, job)["task_id"])
        Path(artifact["copy"]).write_bytes(b"corrupted synthetic evidence")
        with self.assertRaises(CoreError):
            self.manager.work(self.case, job)
