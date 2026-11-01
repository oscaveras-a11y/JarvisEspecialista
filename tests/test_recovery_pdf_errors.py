"""Real pypdf regressions using synthetic files on ephemeral CI runners."""
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from cyber_core.cryptanalysis.formats import validate_password
from cyber_core.cryptanalysis.sessions import RecoverySessions
from cyber_core.service import Core


@unittest.skipUnless(importlib.util.find_spec("pypdf"), "Install recovery extra")
class PdfErrorRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.scope = self.root / "scope"
        self.scope.mkdir()
        self.source = self.scope / "synthetic.pdf"

    def encrypted(self):
        from pypdf import PdfWriter
        writer = PdfWriter()
        writer.add_blank_page(width=72, height=72)
        writer.encrypt("synthetic-owner", algorithm="AES-256")
        output = io.BytesIO()
        writer.write(output)
        return output.getvalue()

    def test_installed_exception_contract(self):
        import pypdf
        from pypdf.errors import (DependencyError, FileNotDecryptedError,
                                 LimitReachedError, ParseError, PdfReadError, PyPdfError)
        print("Synthetic PDF exception contracts; pypdf", pypdf.__version__)
        self.assertTrue(issubclass(ParseError, PyPdfError))
        self.assertTrue(issubclass(FileNotDecryptedError, PdfReadError))
        self.assertFalse(issubclass(DependencyError, PyPdfError))
        self.assertFalse(issubclass(LimitReachedError, PdfReadError))

    def test_malformed_reader_input_is_an_unmatched_candidate(self):
        from pypdf import PdfReader
        from pypdf.errors import PdfReadError
        raw = b"%PDF-1.7\nsynthetic malformed PDF\n"
        with self.assertRaises(PdfReadError):
            PdfReader(io.BytesIO(raw), strict=True)
        self.assertEqual(validate_password("pdf", raw, b"synthetic-wrong"), {"matched": False})

    def test_encrypted_wrong_then_correct_candidate(self):
        raw = self.encrypted()
        self.assertEqual(validate_password("pdf", raw, b"synthetic-wrong"), {"matched": False})
        result = validate_password("pdf", raw, b"synthetic-owner")
        self.assertTrue(result["matched"])
        self.assertTrue(result["password_validated"])

    def test_unsupported_encryption_remains_an_operational_failure(self):
        from pypdf import PdfReader
        from pypdf.generic import NumberObject, NameObject
        # Write a valid encrypted PDF with an unsupported algorithm version.
        # clone_document_from_reader would decrypt it, so change the writer's
        # encryption dictionary before serialization instead.
        from pypdf import PdfWriter
        writer = PdfWriter()
        writer.add_blank_page(width=72, height=72)
        writer.encrypt("synthetic-owner", algorithm="AES-256")
        writer._encrypt_entry[NameObject("/V")] = NumberObject(99)
        stream = io.BytesIO()
        writer.write(stream)
        raw = stream.getvalue()
        with self.assertRaises(NotImplementedError):
            PdfReader(io.BytesIO(raw), strict=True)
        with self.assertRaises(NotImplementedError):
            validate_password("pdf", raw, b"synthetic-owner")

    def test_malformed_pdf_trial_returns_only_unmatched_metadata(self):
        self.source.write_bytes(b"%PDF-1.7\nsynthetic malformed PDF\n")
        request = {"mode": "pdf", "source": str(self.source),
                   "source_sha256": hashlib.sha256(self.source.read_bytes()).hexdigest(),
                   "candidate": b"synthetic-wrong".hex()}
        run = subprocess.run([sys.executable, "-I", "-m",
                              "cyber_core.cryptanalysis.recovery_trial"],
                             input=json.dumps(request), capture_output=True,
                             text=True, timeout=30)
        self.assertEqual(run.returncode, 0)
        self.assertEqual(json.loads(run.stdout), {"matched": False})
        self.assertEqual(run.stderr, "")

    def test_malformed_pdf_session_consumes_candidates_without_resource_failure(self):
        self.source.write_bytes(b"%PDF-1.7\nsynthetic malformed PDF\n")
        material = self.scope / "candidates.txt"
        material.write_bytes(b"synthetic-first\nsynthetic-second\n")
        core = Core(self.root / "state", timeout=60)
        self.addCleanup(core.close)
        case = core.investigate("synthetic", "Malformed PDF", str(self.scope), "owner",
                                "Synthetic issue 35 regression", recovery=True, valid_hours=72)
        manager = RecoverySessions(core)
        job = manager.start(case, self.source, material, mode="pdf")["id"]
        first = manager.work(case, job, max_attempts=1, max_seconds=60)
        self.assertEqual(first["status"], "pending")
        self.assertEqual(first["attempts"], 1)
        done = manager.work(case, job, max_attempts=1, max_seconds=60)
        self.assertEqual(done["status"], "exhausted")
        self.assertEqual(done["attempts"], 2)
        self.assertIsNone(done["result"])
        self.assertTrue(core.verify_audit(case))
        self.assertEqual(manager.get(case, job)["status"], "exhausted")
        self.assertFalse(list(core.home.rglob("*.recovered")))
