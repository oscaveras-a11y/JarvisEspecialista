"""Recovery sessions use only owner-supplied material and synthetic fixtures."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from cyber_core.errors import CoreError
from cyber_core.service import Core

class RecoverySessionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.scope = self.root / "scope"
        self.scope.mkdir()
        self.core = Core(self.root / "state", timeout=30)
        self.addCleanup(lambda: self.core.close())
        self.case = self.core.investigate("synthetic", "Recovery", str(self.scope), "owner", "Synthetic owner material", recovery=True, valid_hours=72)
        self.key = bytes(range(32))
        self.plain = b"%PDF-1.7\nSynthetic recovery.\n"
        self.source = self.scope / "input.ccaes"
        nonce = bytes(range(12))
        self.source.write_bytes(b"CCAES1" + nonce + AESGCM(self.key).encrypt(nonce, self.plain, b"CCAES1"))
        self.material = self.scope / "candidates.txt"
        self.material.write_text((b"x"*32).hex()+"\n"+self.key.hex()+"\n")

    def sessions(self):
        from cyber_core.cryptanalysis.sessions import RecoverySessions
        return RecoverySessions(self.core)

    def start(self, **kw):
        return self.sessions().start(self.case, self.source, self.material, **kw)

    def test_default_is_24_hour_window_with_explicit_material_and_no_secret_export(self):
        before = time.time()
        item = self.start()
        self.assertAlmostEqual(item["deadline"] - before, 86400, delta=10)
        self.assertEqual(item["status"], "pending")
        self.assertNotIn(self.key.hex(), json.dumps(item))
        self.assertNotIn("material_commitment", item)

    def test_progress_survives_new_process_and_authenticated_result_reaches_report(self):
        job = self.start()["id"]
        one = self.sessions().work(self.case, job, max_attempts=1, max_seconds=20)
        self.assertEqual(one["attempts"], 1)
        self.assertEqual(one["status"], "pending")
        run = subprocess.run([sys.executable, "-m", "cyber_core", "--home", str(self.core.home),
                              "recovery-session", "work", self.case, job, "--max-attempts", "1"],
                             capture_output=True, text=True, timeout=60)
        self.assertEqual(run.returncode, 0, run.stderr)
        done = json.loads(run.stdout)
        self.assertEqual(done["status"], "succeeded")
        self.assertEqual(done["attempts"], 2)
        self.assertEqual(Path(done["result"]["output"]).read_bytes(), self.plain)
        report = self.core.report(self.case).read_text()
        self.assertIn(job, report)
        self.assertNotIn(self.key.hex(), report)
        self.assertTrue(self.core.verify_audit(self.case))

    def test_no_match_is_exhausted_not_success(self):
        self.material.write_text((b"x"*32).hex()+"\n")
        job = self.start()["id"]
        item = self.sessions().work(self.case, job, max_attempts=10)
        self.assertEqual(item["status"], "exhausted")
        self.assertIsNone(item["result"])

    def test_scope_and_recovery_authorization_are_required(self):
        outside = self.root / "outside"
        outside.write_text(self.key.hex())
        with self.assertRaises(CoreError):
            self.sessions().start(self.case, self.source, outside)
        case = self.core.investigate("synthetic", "x", str(self.scope), "owner", "No recovery")
        with self.assertRaises(CoreError):
            self.sessions().start(case, self.source, self.material)

    def test_session_pause_resume_and_cancel_are_durable(self):
        manager = self.sessions()
        job = self.start()["id"]
        manager.pause(self.case, job)
        self.assertEqual(manager.work(self.case, job)["status"], "paused")
        manager.resume(self.case, job)
        manager.cancel(self.case, job)
        self.assertEqual(manager.work(self.case, job)["status"], "cancelled")
        with self.assertRaises(CoreError):
            manager.resume(self.case, job)

    def test_case_pause_revoke_cancel_stop_new_attempts(self):
        manager = self.sessions()
        job = self.start()["id"]
        self.core.pause(self.case)
        with self.assertRaises(CoreError):
            manager.work(self.case, job)
        self.core.resume(self.case)
        self.core.revoke(self.case)
        with self.assertRaises(CoreError):
            manager.work(self.case, job)
        self.assertEqual(manager.get(self.case, job)["attempts"], 0)

    def test_changed_material_cannot_silently_change_session_plan(self):
        manager = self.sessions()
        job = self.start()["id"]
        self.material.write_text(self.key.hex()+"\n")
        with self.assertRaises(CoreError):
            manager.work(self.case, job)
        self.assertEqual(manager.get(self.case, job)["attempts"], 0)

    def test_priority_extension_requires_reason_and_is_audited(self):
        manager = self.sessions()
        job = self.start()["id"]
        with self.assertRaises(CoreError):
            manager.extend(self.case, job, hours=24, reason="", priority=True)
        with self.assertRaises(CoreError):
            manager.extend(self.case, job, hours=24, reason="Priority synthetic", priority=False)
        before = manager.get(self.case, job)["deadline"]
        item = manager.extend(self.case, job, hours=24, reason="Priority synthetic", priority=True)
        self.assertEqual(item["deadline"], before + 86400)
        self.assertTrue(any(r["event"] == "recovery_session_extended" for r in self.core.audit(self.case)))

    def test_live_lease_prevents_duplicate_worker(self):
        manager = self.sessions()
        job = self.start()["id"]
        with self.core.db:
            self.core.db.execute("UPDATE recovery_sessions SET status='running',token='peer',lease_until=? WHERE id=?",
                                 (time.time()+120, job))
        with self.assertRaises(CoreError):
            manager.work(self.case, job)
        self.assertEqual(manager.get(self.case, job)["attempts"], 0)

    def test_expired_lease_recovers_checkpoint_without_skipping_candidate(self):
        manager = self.sessions()
        job = self.start()["id"]
        with self.core.db:
            self.core.db.execute("UPDATE recovery_sessions SET status='running',token='old',lease_until=0 WHERE id=?", (job,))
        item = manager.work(self.case, job, max_attempts=1)
        self.assertEqual(item["attempts"], 1)
        self.assertEqual(item["status"], "pending")

    def test_encrypted_ssh_passphrase_is_validated_without_exporting_private_key(self):
        key = ed25519.Ed25519PrivateKey.generate()
        secret = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH,
                                   serialization.BestAvailableEncryption(b"synthetic-owner-passphrase"))
        self.source.write_bytes(secret)
        self.material.write_text("incorrect\nsynthetic-owner-passphrase\n")
        job = self.start(mode="ssh-private")["id"]
        result = self.sessions().work(self.case, job, max_attempts=4)
        self.assertEqual(result["status"], "succeeded")
        self.assertTrue(result["result"]["private_material_validated"])
        report = self.core.report(self.case).read_text()
        self.assertNotIn("synthetic-owner-passphrase", report)
        self.assertNotIn(secret.decode().splitlines()[1], report)
        self.assertNotIn("output", result["result"])

    def test_invalid_mode_limits_and_oversized_material_are_rejected(self):
        for kw in ({"mode":"zip"}, {"hours":0}, {"hours":float("nan")}, {"max_candidates":0}):
            with self.subTest(kw=kw), self.assertRaises(CoreError):
                self.start(**kw)
        self.material.write_bytes(b"x"*(8*1024*1024+1))
        with self.assertRaises(CoreError):
            self.start()

    def test_deadline_stops_before_trying_another_candidate(self):
        manager = self.sessions()
        job = self.start()["id"]
        future = time.time() + 86410
        with patch("cyber_core.cryptanalysis.sessions.time.time", return_value=future):
            item = manager.work(self.case, job)
        self.assertEqual(item["status"], "deadline")
        self.assertEqual(item["attempts"], 0)

    def test_tampered_evidence_or_plan_is_not_used(self):
        manager = self.sessions()
        job = self.start()["id"]
        with self.core.db:
            self.core.db.execute("UPDATE recovery_sessions SET mode='ssh-private' WHERE id=?", (job,))
        with self.assertRaises(CoreError):
            manager.work(self.case, job)
        self.assertFalse(list(self.core.home.rglob("*.recovered")))

if __name__ == "__main__":
    unittest.main()
