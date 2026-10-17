"""GitHub-only synthetic diagnostics for the project status review.

These probes report observations, not a release approval. They never contact a
provider or a target, and never use real credentials, evidence, or client data.
Run on the immutable candidate declared by the audit workflow.
"""
import json
import tempfile
from pathlib import Path

from cyber_core.errors import CoreError
from cyber_core.research import classify_source
from cyber_core.service import Core
from cyber_core.vulnerability import audit_config


def main():
    observations = {}
    marker = "SYNTHETIC_ONLY_AUDIT_MARKER"
    findings = audit_config("password=" + marker + " debug=true\n")
    observations["secret_visible_in_another_finding_excerpt"] = any(
        marker in entry["excerpt"] for entry in findings["findings"])
    observations["unrelated_domain_labeled_official"] = (
        classify_source("https://unrelated-ietf.org/spec")["category"] == "official")

    with tempfile.TemporaryDirectory(prefix="cyber-status-audit-") as folder:
        root = Path(folder)
        inputs = root / "inputs"
        inputs.mkdir()
        config = inputs / "synthetic.conf"
        config.write_text("debug=true\n", encoding="utf-8")
        capture = inputs / "capture.txt"
        capture.write_bytes(b"AA\nBB\n")
        core = Core(root / "state")
        try:
            case = core.investigate("synthetic audit", "Verify bounded beta contracts",
                                    inputs, "synthetic owner", "synthetic fixture only")
            result = core.audit_config(case, config)
            observations["config_findings_returned"] = len(result["findings"])
            observations["config_analysis_persisted_tasks"] = len(core.tasks(case))
            observations["config_analysis_persisted_results"] = len(core.results(case))
            cap = core.analyze_capture(case, capture, max_sample=3)
            observations["capture_messages_seen"] = cap["messages"]
            observations["capture_input_was_longer_than_sample"] = capture.stat().st_size > 3
            observations["capture_truncation_reported"] = bool(
                cap.get("sample_truncated") or cap.get("truncated"))
            core.pause(case)
            try:
                core.audit_config(case, config)
            except CoreError:
                observations["new_config_analysis_executes_while_paused"] = False
            else:
                observations["new_config_analysis_executes_while_paused"] = True
            observations["audit_chain_valid"] = core.verify_audit(case)
        finally:
            core.close()
    print(json.dumps({"synthetic_only": True, "release_approval": False,
                      "observations": observations}, sort_keys=True))
    # Exit zero means the diagnostic ran, NOT that its observations are acceptable.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
