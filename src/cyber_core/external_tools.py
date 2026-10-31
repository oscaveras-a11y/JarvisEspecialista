"""Authorized external-tool entrypoints; isolated children emit metadata only."""
import hashlib
import json
from pathlib import Path
import sys
import tempfile
from cyber_core.agents.runner import run_bounded
from cyber_core.errors import CoreError
from cyber_core.external_tool_runtime import (
    MODES, VALIDATION, SIGNATURES, external_configuration, tool_inventory)

def select_external_mode(mode, header):
    if mode not in MODES:
        raise CoreError("Unknown external recovery mode")
    signatures = SIGNATURES[mode]
    if signatures is not None and not header.startswith(signatures):
        raise CoreError("External mode does not match input")
    config = external_configuration(MODES[mode])
    if mode in ("john-zip", "hashcat-zip-aes") and "converter" not in config:
        raise CoreError("ZIP converter unavailable")
    if mode == "john-rar5" and "rar_converter" not in config:
        raise CoreError("RAR5 converter unavailable")
    return mode

def external_trial(mode, raw, candidate, config, *, timeout=60, scratch_parent=None):
    # This entrypoint runs inside the already supervised recovery_trial child.
    from cyber_core.external_tools_child import trial
    return trial(mode, raw, candidate, config, timeout=timeout, scratch_parent=scratch_parent)

def analyze_tool(core, case, path, *, tool):
    if tool not in ("die", "unblob"):
        raise CoreError("Unsupported external analysis tool")
    config = external_configuration(tool)
    from cyber_core.operations import _acquire, save_operation
    from cyber_core.verification.artifacts import verified_result
    raw, evidence = _acquire(core, case, path, min(core.max_bytes, 8*1024*1024))
    def stopped():
        try:
            return bool(core.authorize(case)["paused"])
        except CoreError:
            return True
    if stopped():
        raise CoreError("Investigation cannot run external analysis")
    with tempfile.TemporaryDirectory(prefix="cyber-analysis-") as scratch:
        request = {"tool": tool, "source": evidence["copy"], "source_sha256": evidence["sha256"],
                   "config": config, "scratch": scratch, "timeout": core.timeout}
        response = run_bounded([sys.executable, "-I", str(Path(__file__).with_name("external_tools_child.py"))],
            json.dumps(request), cwd=scratch, timeout=core.timeout, max_output=65536,
            should_stop=stopped, env={})
        analysis = json.loads(response["stdout"])
        if (analysis.get("backend") != tool or analysis.get("input_sha256") != evidence["sha256"]
                or analysis.get("input_bytes") != len(raw) or type(analysis.get("identified")) is not bool
                or analysis.get("extraction_enabled") is not False):
            raise CoreError("Invalid external analysis result")
        # Revalidate the acquired evidence after the entire process tree exits.
        verified_result(core, case, evidence["task_id"]) if "task_id" in evidence else None
        with open(evidence["copy"], "rb") as stream:
            final = stream.read(len(raw) + 1)
        if final != raw:
            raise CoreError("External analysis evidence changed")
        return save_operation(core, case, "external_analysis", {"evidence": evidence, "analysis": analysis})
