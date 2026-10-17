"""Synthetic recovery/key metadata tests; secret material never enters fixtures in Git."""
import datetime
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.x509.oid import NameOID
from cyber_core.errors import CoreError

class KeyMetadataTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.key = ed25519.Ed25519PrivateKey.generate()

    def file(self, name, data):
        path = self.root / name
        path.write_bytes(data)
        return path

    def private(self, encrypted=False):
        encryption = serialization.BestAvailableEncryption(b"synthetic-passphrase") if encrypted else serialization.NoEncryption()
        return self.key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, encryption)

    def inspect(self, path, **kwargs):
        from cyber_core.recovery import inspect_key
        return inspect_key(path, **kwargs)

    def test_private_pem_is_validated_without_exporting_material(self):
        raw = self.private()
        report = self.inspect(self.file("key.pem", raw))
        self.assertEqual(report["material_kind"], "private_key")
        self.assertFalse(report["password_protected"])
        self.assertEqual(report["structural_status"], "valid")
        self.assertEqual(report["sha256"], hashlib.sha256(raw).hexdigest())
        self.assertNotIn(raw.decode().splitlines()[1], json.dumps(report))

    def test_encrypted_private_key_requires_password_and_keeps_integrity_unknown(self):
        raw = self.private(True)
        report = self.inspect(self.file("encrypted.pem", raw))
        self.assertTrue(report["password_protected"])
        self.assertEqual(report["structural_status"], "password_required")
        self.assertNotIn("synthetic-passphrase", json.dumps(report))
        self.assertFalse(report["private_material_validated"])

    def test_public_ssh_key_is_not_a_private_key(self):
        raw = self.key.public_key().public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH)
        report = self.inspect(self.file("key.pub", raw + b" private-looking-comment"))
        self.assertEqual(report["material_kind"], "public_key")
        self.assertEqual(report["structural_status"], "valid")
        self.assertNotIn("private-looking-comment", json.dumps(report))

    def test_unencrypted_openssh_private_key(self):
        raw = self.key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH, serialization.NoEncryption())
        report = self.inspect(self.file("id_ed25519", raw))
        self.assertEqual(report["material_kind"], "private_key")
        self.assertFalse(report["password_protected"])
        self.assertEqual(report["structural_status"], "valid")

    def test_certificate_reports_dates_but_does_not_claim_chain_validation(self):
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "synthetic.invalid")])
        cert = x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(self.key.public_key()).serial_number(7).not_valid_before(datetime.datetime(2020,1,1)).not_valid_after(datetime.datetime(2021,1,1)).sign(self.key, None)
        report = self.inspect(self.file("cert.pem", cert.public_bytes(serialization.Encoding.PEM)))
        self.assertEqual(report["material_kind"], "certificate")
        self.assertFalse(report["certificate_currently_valid"])
        self.assertFalse(report["chain_validated"])

    def test_random_32_bytes_are_not_declared_an_aes_key(self):
        report = self.inspect(self.file("raw.bin", bytes(range(32))))
        self.assertEqual(report["material_kind"], "unknown")

    def test_malformed_pem_is_not_validated(self):
        report = self.inspect(self.file("broken.pem", b"-----BEGIN PRIVATE KEY-----\nnot-base64\n-----END PRIVATE KEY-----"))
        self.assertEqual(report["structural_status"], "malformed")
        self.assertFalse(report["private_material_validated"])

    def test_oversized_input_is_rejected(self):
        with self.assertRaises(CoreError):
            self.inspect(self.file("big.pem", b"x" * 1025), max_bytes=1024)

    def test_symlink_is_rejected(self):
        target = self.file("key.pem", self.private())
        link = self.root / "link.pem"
        try:
            link.symlink_to(target)
        except OSError:
            self.skipTest("Symlink creation unavailable")
        with self.assertRaises(CoreError):
            self.inspect(link)

class ScopedScanTests(unittest.TestCase):
    def setUp(self):
        from cyber_core.service import Core
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.scope = self.root / "inputs"
        self.scope.mkdir()
        self.core = Core(self.root / "store")
        self.addCleanup(self.core.close)
        self.case = self.core.investigate("lab", "Recovery metadata", str(self.scope), "owner", "Own synthetic files", recovery=True)
        key = ed25519.Ed25519PrivateKey.generate()
        self.secret = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        (self.scope / "key.pem").write_bytes(self.secret)
        (self.scope / "ordinary.txt").write_text("Synthetic ordinary file")

    def scan(self, directory=None, **kwargs):
        from cyber_core.recovery import scan_keys
        return scan_keys(self.core, self.case, directory or self.scope, **kwargs)

    def test_scan_returns_only_candidate_metadata_and_persists_safely(self):
        report = self.scan()
        self.assertEqual(len(report["candidates"]), 1)
        self.assertEqual(report["candidates"][0]["material_kind"], "private_key")
        self.assertNotIn(self.secret.decode().splitlines()[1], json.dumps(report))
        self.assertTrue(self.core.verify_audit(self.case))

    def test_scan_rejects_outside_scope(self):
        outside = self.root / "outside"
        outside.mkdir()
        with self.assertRaises(CoreError):
            self.scan(outside)

    def test_scan_requires_explicit_recovery_permission(self):
        self.case = self.core.investigate("lab", "No recovery", str(self.scope), "owner", "Synthetic")
        with self.assertRaises(CoreError):
            self.scan()

    def test_scan_rejects_pause_and_cancel(self):
        self.core.pause(self.case)
        with self.assertRaises(CoreError):
            self.scan()
        self.core.resume(self.case)
        self.core.cancel(self.case, reason="Synthetic cancel")
        with self.assertRaises(CoreError):
            self.scan()

    def test_assessment_identifies_key_requirements(self):
        from cyber_core.cryptanalysis.assessment import assess
        report = assess(self.scope / "key.pem")
        self.assertEqual(report["family"], "key-material")
        self.assertIn("key_metadata", report["details"])

if __name__ == "__main__":
    unittest.main()
