"""Authorized external-tool entrypoints; isolated children emit metadata only."""
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
from cyber_core.agents.runner import run_bounded
from cyber_core.errors import CoreError
from cyber_core.external_tool_runtime import (
    MODES, VALIDATION, SIGNATURES, NETWORK_TOOLS, NETWORK_ENV_NAMES, external_configuration, tool_inventory)

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
    if tool not in ("die", "unblob", "semgrep", "detect-secrets", "pip-audit", "npm-audit"):
        raise CoreError("Unsupported external analysis tool")
    config = external_configuration(tool)
    from cyber_core.operations import _acquire, save_operation
    from cyber_core.verification.artifacts import verified_result
    # die/unblob identify and decompose real firmware/program images, which can
    # exceed 5 GiB (confirmed blocking a real OpenWrt image during section-6
    # testing); they follow the operator's own core.max_bytes ceiling, up to
    # the system-wide MAX_INPUT_BYTES. semgrep/detect-secrets/pip-audit are
    # source/text-oriented and keep the smaller practical ceiling.
    acquire_limit = core.max_bytes if tool in ("die", "unblob") else min(core.max_bytes, 8*1024*1024)
    raw, evidence = _acquire(core, case, path, acquire_limit)
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
        # die/unblob run through external_tool_runtime.Runner (same path as
        # recovery's external backends in cryptanalysis/sessions.py) — same
        # RAM/CPU headroom needed for the same reason: _limit_exec.py raises
        # its own RLIMIT_CPU to timeout*OMP_NUM_THREADS, which fails if the
        # outer hard ceiling here isn't already at least that large.
        # pip-audit and npm-audit (NETWORK_TOOLS) are the only tools allowed to
        # reach their package index for a lookup; they need this process's own
        # proxy/CA variables (if any) to survive down to Runner.run(...,
        # network=True) two process layers below. Every other tool keeps
        # env={} (no inherited variables at all).
        child_env = ({name: os.environ[name] for name in NETWORK_ENV_NAMES if name in os.environ}
                     if tool in NETWORK_TOOLS else {})
        # die/unblob get the full 8 GiB RLIMIT_AS headroom (the run_bounded
        # ceiling) for real firmware/program evidence over 5 GiB; the other
        # three tools keep the existing 5 GiB, which was already generous for
        # source-code/text-scale input.
        analysis_memory_bytes = 8 * 1024 * 1024 * 1024 if tool in ("die", "unblob") else 5 * 1024 * 1024 * 1024
        response = run_bounded([sys.executable, "-I", str(Path(__file__).with_name("external_tools_child.py"))],
            json.dumps(request), cwd=scratch, timeout=core.timeout, max_output=65536,
            should_stop=stopped, env=child_env,
            max_memory_bytes=analysis_memory_bytes, max_cpu_seconds=min(core.timeout * 2 + 30, 3605))
        analysis = json.loads(response["stdout"])
        if (analysis.get("backend") != tool or analysis.get("input_sha256") != evidence["sha256"]
                or analysis.get("input_bytes") != len(raw) or type(analysis.get("identified")) is not bool
                or analysis.get("extraction_enabled") is not False):
            raise CoreError("Invalid external analysis result")
        if tool in ("semgrep", "detect-secrets", "pip-audit", "npm-audit"):
            findings = analysis.get("findings")
            if (not isinstance(findings, list) or len(findings) > 256
                    or type(analysis.get("findings_total")) is not int or analysis["findings_total"] < len(findings)
                    or type(analysis.get("truncated")) is not bool):
                raise CoreError("Invalid external analysis findings")
        # Revalidate the acquired evidence after the entire process tree exits.
        verified_result(core, case, evidence["task_id"]) if "task_id" in evidence else None
        # Stream-hash rather than reading a second copy of (possibly multi-GB)
        # evidence into memory to compare byte-for-byte; same reasoning as the
        # equivalent check in external_tools_child.py::analyze().
        final = hashlib.sha256()
        with open(evidence["copy"], "rb") as stream:
            while block := stream.read(1048576):
                final.update(block)
        if final.hexdigest() != evidence["sha256"]:
            raise CoreError("External analysis evidence changed")
        return save_operation(core, case, "external_analysis", {"evidence": evidence, "analysis": analysis})
