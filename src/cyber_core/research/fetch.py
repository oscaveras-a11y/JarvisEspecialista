"""Real, bounded, explicit-URL fetch for item 11 (technical research engine).

Owner decision (2026-11-02): network is allowed here, narrowly — only for the
exact URL the caller names. This module never searches, never crawls a page
for links, and never decides on its own what to fetch next; it fetches one
https URL, hashes the response, and registers it as a source with real
fetched metadata (not an operator-typed guess). Fetched content is never
executed, imported or evaluated — classify_source() and add_source() already
established in this module/investigation/workflow.py still apply unchanged.
"""
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
from cyber_core.agents.runner import run_bounded
from cyber_core.errors import CoreError
from cyber_core.external_tool_runtime import NETWORK_ENV_NAMES
from cyber_core.research import classify_source

MAX_FETCH_BYTES = 4 * 1024 * 1024


def fetch_source(core, case, url, *, provenance, author, title=None, max_bytes=MAX_FETCH_BYTES, timeout=30):
    from cyber_core.investigation.workflow import Workflow
    from cyber_core.operations import save_operation
    if not isinstance(url, str) or not url.lower().startswith("https://"):
        raise CoreError("Only an explicit https URL is fetched")
    if type(max_bytes) is not int or not 1 <= max_bytes <= MAX_FETCH_BYTES:
        raise CoreError("Invalid fetch byte limit")
    if type(timeout) not in (int, float) or not 0 < timeout <= 120:
        raise CoreError("Invalid fetch timeout")
    def stopped():
        try:
            return bool(core.authorize(case)["paused"])
        except CoreError:
            return True
    if stopped():
        raise CoreError("Investigation cannot run a research fetch")
    # The one narrow network exception for this module: proxy/CA variables (if
    # any) pass through so the isolated fetch can reach a real host, exactly
    # like pip-audit/npm-audit's own network=True path. The fetch itself still
    # runs in a separate, bounded child process — no network ever reaches the
    # Core process itself.
    child_env = {name: os.environ[name] for name in NETWORK_ENV_NAMES if name in os.environ}
    with tempfile.TemporaryDirectory(prefix="cyber-research-") as scratch:
        request = {"url": url, "max_bytes": max_bytes, "timeout": timeout}
        response = run_bounded(
            [sys.executable, "-I", str(Path(__file__).with_name("fetch_child.py"))],
            json.dumps(request), cwd=scratch, timeout=timeout + 15, max_output=1048576,
            should_stop=stopped, env=child_env,
            max_memory_bytes=256 * 1024 * 1024, max_cpu_seconds=min(timeout + 30, 150))
        result = json.loads(response["stdout"])
    if (type(result.get("status")) is not int or not 100 <= result["status"] <= 599
            or not isinstance(result.get("final_url"), str) or not result["final_url"].lower().startswith("https://")
            or not isinstance(result.get("sha256"), str) or len(result["sha256"]) != 64
            or type(result.get("bytes")) is not int or result["bytes"] > max_bytes
            or not isinstance(result.get("excerpt"), str) or type(result.get("excerpt_truncated")) is not bool):
        raise CoreError("Invalid research fetch result")
    classification = classify_source(result["final_url"])
    workflow = Workflow(core)
    version = result["last_modified"].strip() or ("sha256:" + result["sha256"][:16])
    source_id = workflow.add_source(case, title=(title or result["final_url"])[:500],
                                    url=result["final_url"], version=version,
                                    provenance=provenance, author=author)
    return save_operation(core, case, "research_fetch",
                          {"source_id": source_id, "fetch": result, "classification": classification})
