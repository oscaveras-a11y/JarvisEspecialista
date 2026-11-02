"""Synthetic, authorized external-tool integration. Real CLIs run only in Actions."""
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
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
    def test_fourteen_backends_have_explicit_availability_without_executing_input(self):
        try:
            from cyber_core.external_tools import tool_inventory
        except ImportError:
            self.fail("External tool adapters have not been implemented")
        with patch.dict(os.environ, {}, clear=True):
            inventory = tool_inventory()
        self.assertEqual(set(inventory), {"hashcat", "john", "qpdf", "openssl", "die", "unblob",
                                           "semgrep", "detect-secrets", "pip-audit",
                                           "mmls", "fls", "icat", "fsstat", "npm-audit"})
        for item in inventory.values():
            self.assertFalse(item["available"])
            self.assertIn("reason", item)

    @unittest.skipUnless(sys.platform == "linux", "Linux applet symlinks")
    def test_applet_symlink_keeps_its_invocation_name(self):
        from cyber_core.external_tool_runtime import executable
        with tempfile.TemporaryDirectory() as folder:
            applet = Path(folder) / "zip2john"
            applet.symlink_to(sys.executable)
            self.assertEqual(executable(str(applet)), str(applet))
            self.assertNotEqual(executable(str(applet)), str(applet.resolve()))

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
    def test_hashcat_version_keeps_the_major_version_after_v_prefix(self):
        from cyber_core.external_tool_runtime import version
        from unittest.mock import Mock
        runner = Mock()
        runner.run.return_value = (0, b"v6.2.6\n", b"")
        self.assertEqual(version(runner, "hashcat", "/trusted/hashcat"), "6.2.6")

    def test_malformed_and_partial_analysis_is_rejected(self):
        from cyber_core.external_tools_child import normalize_die, normalize_unblob
        with self.assertRaises(CoreError):
            normalize_die({"detects": "truncated"})

        def task(path, depth, reports=(), subtasks=()):
            return {"task": {"path": path, "depth": depth, "blob_id": "x", "is_multi_file": False},
                    "reports": list(reports), "subtasks": list(subtasks)}

        def chunk(start, end, handler="tar", encrypted=False, extraction_reports=()):
            return {"__typename__": "ChunkReport", "start_offset": start, "end_offset": end,
                    "handler_name": handler, "is_encrypted": encrypted,
                    "extraction_reports": list(extraction_reports)}

        # A real two-level tree: root has one chunk and one subtask, the
        # subtask (the squashfs it points to) has a chunk of its own.
        child_path = "/scratch/image.img_extract/0-100.tar_extract"
        valid = [
            task("/target", 0, reports=[chunk(0, 100)],
                 subtasks=[{"path": child_path, "depth": 1}]),
            task(child_path, 1, reports=[chunk(0, 10, handler="squashfs")]),
        ]
        result = normalize_unblob(valid, Path("/target"), 100)
        self.assertEqual(result["chunks_total"], 2)
        self.assertEqual(sorted(c["depth"] for c in result["chunks"]), [0, 1])
        self.assertFalse(result["truncated"])

        # Chunk extends past the verified input size.
        with self.assertRaises(CoreError):
            normalize_unblob([task("/target", 0, reports=[chunk(0, 100)])], Path("/target"), 10)
        # Root task missing from the report entirely.
        with self.assertRaises(CoreError):
            normalize_unblob([task("/other", 0)], Path("/target"), 100)
        # Root task not actually at depth 0.
        with self.assertRaises(CoreError):
            normalize_unblob([task("/target", 1)], Path("/target"), 100)
        # Subtask reference that doesn't resolve to any task in the report.
        with self.assertRaises(CoreError):
            normalize_unblob([task("/target", 0, subtasks=[{"path": "/unexpected", "depth": 1}])],
                              Path("/target"), 100)
        # A genuine top-level failure report (not a per-chunk missing extractor).
        with self.assertRaises(CoreError):
            normalize_unblob([task("/target", 0, reports=[
                {"__typename__": "ExtractCommandFailedReport", "severity": "ERROR"}])],
                              Path("/target"), 100)
        # A missing extractor on one chunk degrades that chunk, never aborts.
        degraded = normalize_unblob(
            [task("/target", 0, reports=[chunk(0, 10, extraction_reports=[
                {"__typename__": "ExtractorDependencyNotFoundReport", "dependencies": ["sasquatch"]}])])],
            Path("/target"), 100)
        self.assertFalse(degraded["chunks"][0]["extractor_available"])

    def test_malformed_semgrep_and_detect_secrets_analysis_is_rejected(self):
        from cyber_core.external_tools_child import normalize_semgrep, normalize_detect_secrets
        source = Path("/target")
        with self.assertRaises(CoreError):
            normalize_semgrep({"results": "truncated", "errors": []}, source)
        with self.assertRaises(CoreError):
            normalize_semgrep({"results": [], "errors": [{"message": "scan failed"}]}, source)
        with self.assertRaises(CoreError):
            # A finding for a different path than the one that was scanned.
            normalize_semgrep({"results": [{"path": "/other", "check_id": "r", "start": {"line": 1},
                                             "end": {"line": 1}, "extra": {"severity": "INFO"}}], "errors": []}, source)
        with self.assertRaises(CoreError):
            normalize_detect_secrets({"results": {"target": [{"filename": "target", "type": "x",
                                                                "hashed_secret": "not-a-hash", "line_number": 1}]}}, source)
        with self.assertRaises(CoreError):
            # Results keyed to a file other than the one that was scanned.
            normalize_detect_secrets({"results": {"other": []}}, source)
        clean = normalize_semgrep({"results": [], "errors": []}, source)
        self.assertEqual(clean, {"identified": False, "findings": [], "findings_total": 0,
                                  "truncated": False, "extraction_enabled": False})

    def test_malformed_pip_audit_analysis_is_rejected(self):
        from cyber_core.external_tools_child import normalize_pip_audit
        with self.assertRaises(CoreError):
            normalize_pip_audit({"dependencies": "truncated"})
        with self.assertRaises(CoreError):
            # Missing fix_versions/aliases on a reported vulnerability.
            normalize_pip_audit({"dependencies": [{"name": "x", "version": "1", "vulns": [{"id": "V"}]}]})
        clean = normalize_pip_audit({"dependencies": [{"name": "x", "version": "1", "vulns": []}]})
        self.assertEqual(clean, {"identified": False, "findings": [], "findings_total": 0,
                                  "truncated": False, "extraction_enabled": False})

    def test_malformed_npm_audit_analysis_is_rejected(self):
        from cyber_core.external_tools_child import normalize_npm_audit
        with self.assertRaises(CoreError):
            normalize_npm_audit({"vulnerabilities": "truncated"})
        with self.assertRaises(CoreError):
            # Missing title/url/severity on an advisory inside "via".
            normalize_npm_audit({"vulnerabilities": {"lodash": {"severity": "high", "via": [{}]}}})
        # A "via" entry that is just a package-name string (a transitive
        # reference, not its own advisory) is skipped, never fatal.
        transitive_only = normalize_npm_audit({"vulnerabilities": {"a": {"severity": "high", "via": ["b"]}}})
        self.assertEqual(transitive_only, {"identified": False, "findings": [], "findings_total": 0,
                                           "truncated": False, "extraction_enabled": False})
        clean = normalize_npm_audit({"vulnerabilities": {"lodash": {"severity": "high", "via": [
            {"title": "t", "url": "u", "severity": "high", "range": "<1.0.0"}]}}})
        self.assertEqual(clean["findings"], [{"package": "lodash", "severity": "high", "title": "t",
                                              "url": "u", "range": "<1.0.0"}])

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

    @unittest.skipUnless(sys.platform == "linux" and importlib.util.find_spec("pypdf"), "Linux and recovery extra")
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

    def test_all_fourteen_real_tools_are_available(self):
        try:
            from cyber_core.external_tools import tool_inventory
        except ImportError:
            self.fail("External tool inventory is not implemented")
        inventory = tool_inventory()
        self.assertEqual(set(inventory), {"hashcat","john","qpdf","openssl","die","unblob",
                                           "semgrep","detect-secrets","pip-audit",
                                           "mmls","fls","icat","fsstat","npm-audit"})
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

    def test_hashcat_treats_hex_looking_candidate_as_literal_password(self):
        self.password = b"$HEX[6162]"
        self.material.write_bytes(b"synthetic-wrong\n" + self.password + b"\n")
        source = self.scope / "literal-sha256.txt"
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

    @unittest.skipUnless(os.environ.get("CYBER_REAL_FIRMWARE_PATH"),
                         "Opt-in: set CYBER_REAL_FIRMWARE_PATH to a real firmware image "
                         "(e.g. an OpenWrt *-squashfs-combined.img, gunzipped) to validate "
                         "recursive decomposition against it; not fetched automatically.")
    def test_unblob_recursively_decomposes_a_real_firmware_image(self):
        try:
            from cyber_core.external_tools import analyze_tool
        except ImportError:
            self.fail("External analysis integration is not implemented")
        source = Path(os.environ["CYBER_REAL_FIRMWARE_PATH"])
        self.core.max_bytes = max(self.core.max_bytes, source.stat().st_size + 1)
        self.core.timeout = max(self.core.timeout, 600)
        shutil.copy(source, self.scope / source.name)
        result = analyze_tool(self.core, self.case, self.scope / source.name, tool="unblob")
        analysis = result["analysis"]
        self.assertEqual(analysis["backend"], "unblob")
        self.assertTrue(analysis["identified"])
        # A real nested firmware (bootloader > kernel > rootfs > files) always
        # decomposes past the top level; depth 0 alone would mean the old
        # --skip-extraction/--depth 1 regression came back.
        self.assertGreater(analysis["max_depth"], 0)
        self.assertGreater(analysis["chunks_total"], 1)
        self.assertFalse(analysis["extraction_enabled"])
        self.assertTrue(self.core.verify_audit(self.case))

    def test_semgrep_and_detect_secrets_find_real_synthetic_issues(self):
        try:
            from cyber_core.external_tools import analyze_tool
        except ImportError:
            self.fail("External analysis integration is not implemented")
        source = self.scope / "sample.py"
        secret = "synthetic-owner-secret-2026"
        source.write_text('import pickle\npickle.loads(b"x")\npassword = "%s"\n' % secret)
        rules = self.root / "semgrep-rules.yml"
        rules.write_text(
            "rules:\n"
            "  - id: insecure-pickle-loads\n"
            "    patterns:\n"
            "      - pattern: pickle.loads(...)\n"
            "    message: Insecure deserialization via pickle.loads\n"
            "    languages: [python]\n"
            "    severity: ERROR\n", encoding="utf-8")
        self.enterContext(patch.dict(os.environ, {"CYBER_SEMGREP_RULES_PATH": str(rules)}))

        semgrep = analyze_tool(self.core, self.case, source, tool="semgrep")
        analysis = semgrep["analysis"]
        self.assertEqual(analysis["backend"], "semgrep")
        self.assertTrue(analysis["identified"])
        self.assertTrue(any(f["rule_id"].endswith("insecure-pickle-loads") for f in analysis["findings"]))
        self.assertNotIn(secret, json.dumps(semgrep))

        detected = analyze_tool(self.core, self.case, source, tool="detect-secrets")
        analysis = detected["analysis"]
        self.assertEqual(analysis["backend"], "detect-secrets")
        self.assertTrue(analysis["identified"])
        self.assertTrue(all(len(f["secret_sha1"]) == 40 for f in analysis["findings"]))
        self.assertNotIn(secret, json.dumps(detected))

        self.assertTrue(self.core.verify_audit(self.case))
        report = self.core.report(self.case).read_text(encoding="utf-8")
        self.assertNotIn(secret, report)

    @unittest.skipUnless(os.environ.get("CYBER_REQUIRE_PIP_AUDIT_NETWORK") == "1",
                         "Requires outbound network to the package index; opt-in separately")
    def test_pip_audit_finds_a_real_known_vulnerable_pin(self):
        try:
            from cyber_core.external_tools import analyze_tool
        except ImportError:
            self.fail("External analysis integration is not implemented")
        source = self.scope / "requirements.txt"
        source.write_text("requests==2.6.0\n")
        result = analyze_tool(self.core, self.case, source, tool="pip-audit")
        analysis = result["analysis"]
        self.assertEqual(analysis["backend"], "pip-audit")
        self.assertTrue(analysis["identified"])
        self.assertTrue(any(f["package"] == "requests" for f in analysis["findings"]))
        self.assertTrue(self.core.verify_audit(self.case))

    @unittest.skipUnless(os.environ.get("CYBER_REQUIRE_PIP_AUDIT_NETWORK") == "1",
                         "Requires outbound network to the package index; opt-in separately "
                         "(same flag as pip-audit's own network opt-in)")
    def test_npm_audit_finds_a_real_known_vulnerable_pin(self):
        try:
            from cyber_core.external_tools import analyze_tool
        except ImportError:
            self.fail("External analysis integration is not implemented")
        source = self.scope / "package-lock.json"
        source.write_text(json.dumps({
            "name": "synthetic-audit-fixture", "version": "1.0.0", "lockfileVersion": 3, "requires": True,
            "packages": {
                "": {"name": "synthetic-audit-fixture", "version": "1.0.0",
                     "dependencies": {"lodash": "4.17.11"}},
                "node_modules/lodash": {
                    "version": "4.17.11",
                    "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.11.tgz",
                    "integrity": "sha512-cQKh8igo5QUhZ7lg38DYWAxMvjSAKG0A8wGSVimP07SIUEK2UO+arSRKbRZWtelMtN5V0Hkwh5ryOto/SshYIg==",
                    "license": "MIT"}}}))
        result = analyze_tool(self.core, self.case, source, tool="npm-audit")
        analysis = result["analysis"]
        self.assertEqual(analysis["backend"], "npm-audit")
        self.assertTrue(analysis["identified"])
        self.assertTrue(any(f["package"] == "lodash" for f in analysis["findings"]))
        self.assertTrue(self.core.verify_audit(self.case))

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
