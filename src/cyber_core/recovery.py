"""Recovery facade; CLI only parses arguments and presents safe metadata."""
import time
from cyber_core.errors import CoreError
from cyber_core.memory import audit, encoded, utc
from uuid import uuid4
from cyber_core.cryptanalysis.keys import inspect_key

def assess_recovery(core, case, path, **limits):
    from cyber_core.cryptanalysis.intake import assess_recovery as intake
    return intake(core, case, path, **limits)

def scan_keys(core, case, directory, *, max_files=100, recursive=False,
              max_total_bytes=16 * 1024 * 1024):
    from cyber_core.cryptanalysis.intake import collect
    from cyber_core.permissions import local_path
    root = local_path(directory, directory=True)
    files, links_skipped, _ = collect(core, case, root, max_files=max_files,
                                    recursive=recursive, max_total_bytes=max_total_bytes)
    started = time.monotonic()
    candidates, skipped = [], links_skipped
    for path, size in files:
        row = core.authorize(case, path, recovery=True)
        if core.get(case)["paused"]:
            raise CoreError("Investigation is paused")
        if time.monotonic() - started >= core.timeout:
            raise CoreError("Key scan time budget exceeded")
        if size > 1024 * 1024:
            skipped += 1
            continue
        result = inspect_key(path,timeout=min(30,core.timeout-(time.monotonic()-started)),
                             should_stop=lambda: core.get(case)["paused"] or not core.authorize(case,recovery=True))
        if result["material_kind"] != "unknown":
            candidates.append({"path": str(path), **result})
    result = {"candidates": candidates, "files_examined": len(files), "skipped": skipped,
              "recovery_demonstrated": False,
              "limitations": ["Only the explicitly authorized directory was inspected.",
                              "No password manager, operating-system credential store or network was accessed.",
                              "Candidate metadata does not prove a match to an encrypted target.",
                              "Raw 32-byte files are not automatically classified as AES keys."]}
    with core.db:
        core.db.execute("BEGIN IMMEDIATE")
        row = core.authorize(case, recovery=True)
        current_root = local_path(root, directory=True)
        if not current_root.is_relative_to(local_path(row['scope'], directory=True)):
            raise CoreError("Key directory is outside the authorized scope")
        if core.get(case)["paused"]:
            raise CoreError("Investigation is paused")
    from cyber_core.operations import save_operation
    save_operation(core, case, "recovery_keys", result, recovery=True)
    return result
