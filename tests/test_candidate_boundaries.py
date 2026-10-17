"""Regressions for the five observed candidate gaps; synthetic input only."""
import json
import tempfile
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

from cyber_core.errors import CoreError
from cyber_core.service import Core
from cyber_core.vulnerability import audit_config
from cyber_core.research import classify_source
from cyber_core.protocol import analyze_capture, compare_captures


class BoundaryUnitTests(unittest.TestCase):
    def test_every_finding_omits_all_source_secrets(self):
        secrets = ["FIRST_SYNTHETIC_VALUE", "SECOND_SYNTHETIC_VALUE", "AKIAABCDEFGHIJKLMNOP"]
        text = 'password="' + secrets[0] + '" token=' + secrets[1] + ' DEBUG=true http://example.test/' + secrets[2]
        result = audit_config(text)
        self.assertTrue({"exposed_secret", "debug_enabled", "aws_access_key_id"} <= {f["kind"] for f in result["findings"]})
        for value in secrets:
            self.assertNotIn(value, json.dumps(result))
        self.assertTrue(all(f["line"] == 1 for f in result["findings"]))

    def test_unrecognized_secret_syntax_is_not_echoed_by_other_rules(self):
        result = audit_config('DEBUG=true opaque_key="SYNTHETIC_UNRECOGNIZED_VALUE"')
        self.assertEqual(result["summary"]["medium"], 1)
        self.assertNotIn("SYNTHETIC_UNRECOGNIZED_VALUE", json.dumps(result))

    def test_every_rule_omits_arbitrary_source_values(self):
        triggers = ("DEBUG=true", "verify=false", "PermitRootLogin yes",
                    "http://example.test", "md5", "AKIAABCDEFGHIJKLMNOP",
                    "-----BEGIN PRIVATE KEY-----")
        for trigger in triggers:
            with self.subTest(trigger=trigger):
                result = audit_config(trigger + ' unrelated="SYNTHETIC_PRIVATE_VALUE" password=x')
                self.assertTrue(result["findings"])
                self.assertNotIn("SYNTHETIC_PRIVATE_VALUE", json.dumps(result))
                self.assertNotIn(trigger, json.dumps([f["excerpt"] for f in result["findings"]]))

    def test_domain_matches_require_dns_boundaries(self):
        for host in ("unrelated-ietf.org", "fakegithub.com", "unrelatedarxiv.org", "ietf.org.example.test"):
            with self.subTest(host=host):
                self.assertEqual(classify_source("https://" + host)["category"], "unknown")
        for host in ("ietf.org", "www.ietf.org", "IETF.ORG."):
            with self.subTest(host=host):
                self.assertEqual(classify_source("https://" + host)["category"], "official")

    def test_saturated_ids_keep_counting_known_ids_and_signal_loss(self):
        with patch("cyber_core.protocol._MAX_DISTINCT", 2):
            result = analyze_capture("a#01\nb#02\nc#03\na#01\n")
        self.assertEqual(result["id_histogram"]["a"], 2)
        self.assertTrue(result.get("ids_truncated", False))
        self.assertTrue(result.get("payloads_truncated", False))

    def test_comparison_signals_limited_payload_sets(self):
        with patch("cyber_core.protocol._MAX_DISTINCT", 2):
            result = compare_captures("01\n02\n03\n", "01\n")
        self.assertTrue(result.get("comparison_truncated", False))


class ServiceBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.scope = self.root / "inputs"
        self.scope.mkdir()
        self.core = Core(self.root / "state")
        self.addCleanup(lambda: self.core.close())
        self.case = self.core.investigate("lab", "Synthetic boundaries", str(self.scope), "owner", "Synthetic own files")

    def file(self, name, content):
        path = self.scope / name
        path.write_bytes(content)
        return path

    def test_config_audit_persists_verified_result_and_safe_report(self):
        path = self.file("app.conf", b"password=SYNTHETIC_CONFIG_SECRET DEBUG=true\n")
        result = self.core.audit_config(self.case, path)
        self.assertGreaterEqual(len(result["findings"]), 2)
        tasks, results = self.core.tasks(self.case), self.core.results(self.case)
        self.assertEqual(len(tasks), 1)
        self.assertEqual(tasks[0]["status"], "done")
        self.assertEqual(len(results), 1)
        stored = results[0]
        self.assertTrue(stored["copy_verified"])
        self.assertEqual(stored["config_audit"]["findings"], result["findings"])
        from cyber_core.reporting import write_report
        report = write_report(self.core, self.case).read_text(encoding="utf-8")
        self.assertIn("config_audit", report)
        self.assertNotIn("SYNTHETIC_CONFIG_SECRET", report)
        self.assertTrue(self.core.verify_audit(self.case))
        self.assertTrue(any(e["event"] == "analysis_process_started" for e in self.core.audit(self.case)))

    def test_specialist_operations_reject_paused_cases_before_enqueue(self):
        path = self.file("sample.txt", b"01\nDEBUG=true\n")
        self.core.pause(self.case)
        methods = [lambda: self.core.audit_config(self.case, path),
                   lambda: self.core.analyze_capture(self.case, path),
                   lambda: self.core.extract_strings(self.case, path),
                   lambda: self.core.differentiate_content(self.case, path)]
        for call in methods:
            with self.subTest(call=call):
                with self.assertRaisesRegex(CoreError, "paused"):
                    call()
        self.assertEqual(self.core.tasks(self.case), [])

    def test_self_test_rejects_pause_before_reading(self):
        self.core.set_authorization_basis(self.case, kind="owner_consent", authority="owner",
            reference="synthetic", examiner="owner", scope_note="own synthetic file")
        path = self.file("lab.bin", b"not an envelope")
        self.core.pause(self.case)
        with self.assertRaisesRegex(CoreError, "paused"):
            self.core.self_test_recovery(self.case, path, ["synthetic"])

    def test_capture_sampling_never_uses_read_bytes(self):
        path = self.file("cap.txt", b"01\n02\n")
        with patch.object(Path, "read_bytes", side_effect=AssertionError("whole-file read forbidden")):
            result = self.core.analyze_capture(self.case, path, max_sample=3)
        self.assertEqual(result["messages"], 1)
        self.assertTrue(result.get("sample_truncated", False))
        self.assertEqual(len(self.core.results(self.case)), 1)

    def test_partial_record_is_not_promoted_to_complete_payload(self):
        path = self.file("cap.txt", b"010203\n")
        result = self.core.analyze_capture(self.case, path, max_sample=2)
        self.assertEqual(result["messages"], 0)
        self.assertTrue(result.get("partial_record_discarded", False))
        self.assertTrue(result.get("sample_truncated", False))

    def test_both_capture_samples_expose_truncation(self):
        first = self.file("first.txt", b"01\n02\n")
        second = self.file("second.txt", b"03\n04\n")
        result = self.core.analyze_capture(self.case, first, second_path=second, max_sample=3)
        self.assertTrue(result["first"].get("sample_truncated", False))
        self.assertTrue(result["second"].get("sample_truncated", False))
        self.assertEqual(result["first"]["messages"], 1)
        self.assertEqual(result["second"]["messages"], 1)
        stored = self.core.results(self.case)
        self.assertEqual(len(stored), 1)
        self.assertTrue(stored[0]["secondary"]["copy_verified"])

    def test_other_specialists_publish_reconstructible_results(self):
        path = self.file("sample.txt", b"SYNTHETIC CONTROL CONTENT")
        self.core.extract_strings(self.case, path)
        self.core.differentiate_content(self.case, path)
        results = self.core.results(self.case)
        self.assertEqual(len(results), 2)
        self.assertEqual({r["tool"] for r in results}, {"extract-strings", "differentiate-content"})

    def test_cancelled_specialist_has_no_new_task_or_result(self):
        path = self.file("config.txt", b"DEBUG=true")
        self.core.cancel(self.case, reason="Synthetic cancellation")
        with self.assertRaisesRegex(CoreError, "cancelled"):
            self.core.audit_config(self.case, path)
        self.assertEqual(self.core.tasks(self.case), [])
        self.assertEqual(self.core.results(self.case), [])

    def test_revoked_specialist_cannot_publish(self):
        path = self.file("config.txt", b"DEBUG=true")
        self.core.revoke(self.case)
        with self.assertRaisesRegex(CoreError, "revoked"):
            self.core.audit_config(self.case, path)
        self.assertEqual(self.core.results(self.case), [])

    def test_cli_does_not_echo_configuration_secrets(self):
        path = self.file("config.txt", b"DEBUG=true password=SYNTHETIC_CLI_SECRET")
        call = subprocess.run([sys.executable, "-m", "cyber_core", "--home", str(self.root / "state"),
            "audit-config", self.case, str(path)], capture_output=True, text=True, timeout=60)
        self.assertEqual(call.returncode, 0, call.stderr)
        self.assertTrue(json.loads(call.stdout)["findings"])
        self.assertNotIn("SYNTHETIC_CLI_SECRET", call.stdout + call.stderr)

    def test_late_cancel_discards_specialist_result_and_partial_copy(self):
        path = self.file("config.txt", b"DEBUG=true")
        from cyber_core.analysis_process import analyze_in_process as real_analysis
        def cancel_after_analysis(*args, **kwargs):
            result = real_analysis(*args, **kwargs)
            self.core.cancel(self.case, reason="Synthetic concurrent cancel")
            return result
        with patch("cyber_core.service.analyze_in_process", side_effect=cancel_after_analysis):
            with self.assertRaisesRegex(CoreError, "cancelled"):
                self.core.audit_config(self.case, path)
        self.assertEqual(self.core.results(self.case), [])
        self.assertEqual(self.core.tasks(self.case)[0]["status"], "cancelled")
        self.assertEqual(list((self.core.home / "cases" / self.case / "evidence").iterdir()), [])

    def test_queued_specialist_retains_sample_options_after_restart(self):
        path = self.file("cap.txt", b"01\n02\n")
        original = self.core.run_one
        def pause_before_claim(*args, **kwargs):
            self.core.pause(self.case)
            return original(*args, **kwargs)
        with patch.object(self.core, "run_one", side_effect=pause_before_claim):
            with self.assertRaisesRegex(CoreError, "paused"):
                self.core.analyze_capture(self.case, path, max_sample=3)
        self.core.close()
        self.core = Core(self.root / "state")
        self.core.resume(self.case)
        result = self.core.run_one(self.case)
        self.assertEqual(result["capture"]["messages"], 1)
        self.assertTrue(result["capture"]["sample_truncated"])
        self.assertEqual(len(self.core.results(self.case)), 1)

    def test_completed_specialist_survives_reopen(self):
        path = self.file("config.txt", b"DEBUG=true")
        self.core.audit_config(self.case, path)
        self.core.close()
        self.core = Core(self.root / "state")
        self.assertEqual(len(self.core.results(self.case)), 1)
        self.assertEqual(self.core.tasks(self.case)[0]["status"], "done")


if __name__ == "__main__":
    unittest.main()
