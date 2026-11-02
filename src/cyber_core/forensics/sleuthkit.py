"""Real Sleuth Kit (mmls/fls/icat/fsstat) forensic operations for section 8.

Three explicit, separately authorized steps mirroring a real forensic
workflow: identify partitions, list a chosen partition's filesystem entries
(including deleted ones — this is the project's first real "recuperação de
dados" capability), and recover ONE named file by explicit inode. Nothing is
ever recovered automatically or in bulk; recover_file always names exactly
one inode the caller already saw in list_filesystem_entries' own output.
"""
import hashlib
import json
from pathlib import Path
import sys
import tempfile
from uuid import uuid4
from cyber_core.agents.runner import run_bounded
from cyber_core.errors import CoreError
from cyber_core.external_tool_runtime import external_configuration

_SECTOR_SIZES = (512, 4096)
# run_bounded's own stdout/JSON channel has a hard 1 MiB ceiling; the entry
# list stays well under that (see MAX_ENTRIES in sleuthkit_child.py).
_MAX_OUTPUT = 1048576


def _sector_size(value):
    if value not in _SECTOR_SIZES:
        raise CoreError("sector_size must be 512 or 4096")
    return value


def _stopped(core, case):
    def check():
        try:
            return bool(core.authorize(case)["paused"])
        except CoreError:
            return True
    return check


def _run(core, case, path, *, op, config, params, stopped, scratch):
    from cyber_core.operations import _acquire
    raw, evidence = _acquire(core, case, path, core.max_bytes)
    if stopped():
        raise CoreError("Investigation cannot run Sleuth Kit analysis")
    request = {"op": op, "source": evidence["copy"], "source_sha256": evidence["sha256"],
               "config": config, "params": params, "scratch": scratch, "timeout": core.timeout}
    response = run_bounded(
        [sys.executable, "-I", str(Path(__file__).with_name("sleuthkit_child.py"))],
        json.dumps(request), cwd=scratch, timeout=core.timeout, max_output=_MAX_OUTPUT,
        should_stop=stopped, env={},
        # Disk/firmware images get the same 8 GiB headroom as die/unblob, for
        # the same reason (section 6: real images can exceed 5 GiB).
        max_memory_bytes=8 * 1024 * 1024 * 1024, max_cpu_seconds=min(core.timeout * 2 + 30, 3605))
    result = json.loads(response["stdout"])
    if result.get("input_sha256") != evidence["sha256"] or result.get("backend") not in ("mmls", "fls", "icat"):
        raise CoreError("Invalid Sleuth Kit analysis result")
    return raw, evidence, result


def list_partitions(core, case, path, *, sector_size=512):
    from cyber_core.operations import save_operation
    sector_size = _sector_size(sector_size)
    config = {"mmls": external_configuration("mmls")}
    with tempfile.TemporaryDirectory(prefix="cyber-tsk-") as scratch:
        raw, evidence, result = _run(core, case, path, op="partitions", config=config,
                                     params={"sector_size": sector_size}, stopped=_stopped(core, case), scratch=scratch)
    if (not isinstance(result.get("partitions"), list) or len(result["partitions"]) > 256
            or type(result.get("partitions_total")) is not int or type(result.get("truncated")) is not bool):
        raise CoreError("Invalid Sleuth Kit partition result")
    return save_operation(core, case, "disk_partitions_tsk", {"evidence": evidence, "analysis": result})


def list_filesystem_entries(core, case, path, *, partition_offset_sectors, sector_size=512,
                            deleted_only=False, recursive=False):
    from cyber_core.operations import save_operation
    sector_size = _sector_size(sector_size)
    if type(partition_offset_sectors) is not int or partition_offset_sectors < 0:
        raise CoreError("Invalid partition offset")
    config = {"fls": external_configuration("fls"), "fsstat": external_configuration("fsstat")}
    params = {"sector_size": sector_size, "partition_offset_sectors": partition_offset_sectors,
              "deleted_only": bool(deleted_only), "recursive": bool(recursive)}
    with tempfile.TemporaryDirectory(prefix="cyber-tsk-") as scratch:
        raw, evidence, result = _run(core, case, path, op="entries", config=config, params=params,
                                     stopped=_stopped(core, case), scratch=scratch)
    if (not isinstance(result.get("entries"), list) or len(result["entries"]) > 3000
            or type(result.get("entries_total")) is not int or type(result.get("truncated")) is not bool
            or not isinstance(result.get("filesystem_info"), str)):
        raise CoreError("Invalid Sleuth Kit entry result")
    return save_operation(core, case, "disk_entries_tsk", {"evidence": evidence, "analysis": result})


def recover_file(core, case, path, *, partition_offset_sectors, inode, max_bytes=16 * 1024 * 1024, sector_size=512):
    """Recover exactly ONE file's bytes by the inode address the caller saw in
    list_filesystem_entries' own output — never bulk, never automatic.

    The recovered bytes are written to a durable file under this case's own
    "recovered" evidence directory (same convention cryptanalysis/sessions.py
    already uses for recovery output); only its path, size and hash are ever
    embedded in the saved operation/report — never the content itself."""
    from cyber_core.operations import save_operation
    from cyber_core.permissions import storage_root
    sector_size = _sector_size(sector_size)
    if type(partition_offset_sectors) is not int or partition_offset_sectors < 0:
        raise CoreError("Invalid partition offset")
    if not isinstance(inode, str) or not 1 <= len(inode) <= 32:
        raise CoreError("Invalid inode address")
    if type(max_bytes) is not int or not 1 <= max_bytes <= 128 * 1024 * 1024:
        raise CoreError("Invalid recovery byte limit")
    config = {"icat": external_configuration("icat")}
    params = {"sector_size": sector_size, "partition_offset_sectors": partition_offset_sectors,
              "inode": inode, "max_bytes": max_bytes}
    with tempfile.TemporaryDirectory(prefix="cyber-tsk-") as scratch:
        raw, evidence, result = _run(core, case, path, op="recover", config=config, params=params,
                                     stopped=_stopped(core, case), scratch=scratch)
        if (type(result.get("recovered_bytes")) is not int or result["recovered_bytes"] > max_bytes
                or not isinstance(result.get("recovered_sha256"), str)):
            raise CoreError("Invalid Sleuth Kit recovery result")
        recovered_path = Path(scratch) / "recovered.bin"
        if not recovered_path.is_file() or recovered_path.stat().st_size != result["recovered_bytes"]:
            raise CoreError("Recovered file missing or size mismatch")
        content = recovered_path.read_bytes()
        if (len(content) != result["recovered_bytes"]
                or hashlib.sha256(content).hexdigest() != result["recovered_sha256"]):
            raise CoreError("Recovered file integrity check failed")
        # Publish before the scratch dir (and recovered.bin with it) is removed.
        folder = storage_root(core.home / "cases" / case / "recovered")
        published_path = folder / (uuid4().hex + ".recovered")
        published_path.write_bytes(content)
    result = {k: result[k] for k in (
        "backend", "backend_version", "backend_sha256", "sector_size",
        "partition_offset_sectors", "inode", "recovered_bytes", "recovered_sha256")}
    result["output"] = str(published_path)
    return save_operation(core, case, "disk_recovered_file_tsk", {"evidence": evidence, "analysis": result})
