"""Isolated Sleuth Kit (TSK) operations. Invoked only under run_bounded.

Real mmls/fls/icat backends for section 8 (perícia digital): partition
identification, filesystem entry listing (including deleted entries), and
single-file recovery by explicit inode. Mirrors external_tools_child.py's
pattern (bounded Runner subprocess, strict output validation, never a raw
pass-through of backend text).
"""
import hashlib
import json
import re
import sys
import tempfile
from pathlib import Path
from cyber_core.errors import CoreError
from cyber_core.external_tool_runtime import Runner, executable, version, binary_digest
from cyber_core.external_tools_child import private_file, _read_bounded

MAX_INPUT = 8 * 1024 * 1024 * 1024  # disk/firmware images; matches the die/unblob ceiling
MAX_PARTITIONS = 256
MAX_ENTRIES = 3000  # the normalized entry list is returned through run_bounded's
# own small JSON/stdout channel (hard-capped at 1 MiB); unlike recovered file
# content below, it is never written to a file instead, so this stays small
# enough that even a maximal response fits comfortably under that ceiling.
MAX_RECOVER_BYTES = 128 * 1024 * 1024
DISK_SCRATCH_MAX_BYTES = 16 * 1024 * 1024 * 1024
DISK_SCRATCH_MAX_ENTRIES = 1024  # these tools never extract a tree; a handful of own temp files

_MMLS_ROW = re.compile(rb"^(\d{3}):\s+(\S+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(.*?)\s*$", re.MULTILINE)
_FLS_HEAD = re.compile(rb"^([a-zA-Z\-]+/[a-zA-Z\-]+) (?:(\*) )?(\d+(?:-\d+-\d+)?):$")
_INODE = re.compile(r"\A\d+(?:-\d+-\d+)?\Z")


def _tool_executable(config, tool):
    if not isinstance(config, dict) or tool not in config or set(config[tool]) != {"executable"}:
        raise CoreError("Invalid Sleuth Kit tool configuration")
    return executable(config[tool]["executable"])


def normalize_mmls(stdout):
    rows, total = [], 0
    for match in _MMLS_ROW.finditer(stdout):
        slot, kind, start, end, length, desc = match.groups()
        if kind == b"Meta":
            continue  # the partition table entry itself, not a volume
        total += 1
        if len(rows) >= MAX_PARTITIONS:
            continue
        rows.append({
            "slot": slot.decode("ascii"),
            "allocated": not kind.startswith(b"-"),
            "start_sector": int(start), "end_sector": int(end), "length_sectors": int(length),
            "description": desc.decode("utf-8", "replace")[:128],
        })
    if total == 0:
        raise CoreError("No partitions recognized by mmls")
    return {"partitions": rows, "partitions_total": total, "truncated": total > len(rows)}


def normalize_fls(stdout):
    rows, total = [], 0
    for raw_line in stdout.split(b"\n"):
        line = raw_line.rstrip(b"\r")
        if not line:
            continue
        parts = line.split(b"\t")
        if len(parts) < 2:
            continue
        head = _FLS_HEAD.match(parts[0])
        if head is None:
            continue
        kind, deleted, inode = head.groups()
        total += 1
        if len(rows) >= MAX_ENTRIES:
            continue
        name = parts[1].decode("utf-8", "replace")[:256]
        timestamps = [p.decode("ascii", "replace")[:40] for p in parts[2:6]]
        size = None
        if len(parts) > 6:
            try:
                size = int(parts[6])
            except ValueError:
                size = None
        rows.append({
            "inode": inode.decode("ascii"), "name": name,
            "kind": kind.decode("ascii"), "deleted": deleted is not None,
            "modified": timestamps[0] if len(timestamps) > 0 else None,
            "accessed": timestamps[1] if len(timestamps) > 1 else None,
            "changed": timestamps[2] if len(timestamps) > 2 else None,
            "created": timestamps[3] if len(timestamps) > 3 else None,
            "size": size,
        })
    return {"entries": rows, "entries_total": total, "truncated": total > len(rows)}


def partitions(raw, config, *, sector_size, timeout, scratch_parent):
    with tempfile.TemporaryDirectory(prefix="tsk-", dir=scratch_parent) as directory:
        root = Path(directory)
        runner = Runner(root, timeout, max_scratch_bytes=DISK_SCRATCH_MAX_BYTES,
                        max_scratch_entries=DISK_SCRATCH_MAX_ENTRIES, max_file_bytes=MAX_INPUT)
        path = _tool_executable(config, "mmls")
        backend_version = version(runner, "mmls", path)
        source = private_file(root, "target", raw)
        _, stdout, _ = runner.run([path, "-b", str(sector_size), source], allowed=(0, 1))
        result = normalize_mmls(stdout)
        return {"backend": "mmls", "backend_version": backend_version, "backend_sha256": binary_digest(path),
                "sector_size": sector_size, **result}


def entries(raw, config, *, sector_size, partition_offset_sectors, deleted_only, recursive, timeout, scratch_parent):
    with tempfile.TemporaryDirectory(prefix="tsk-", dir=scratch_parent) as directory:
        root = Path(directory)
        runner = Runner(root, timeout, max_scratch_bytes=DISK_SCRATCH_MAX_BYTES,
                        max_scratch_entries=DISK_SCRATCH_MAX_ENTRIES, max_file_bytes=MAX_INPUT)
        fls_path = _tool_executable(config, "fls")
        fsstat_path = _tool_executable(config, "fsstat")
        fls_version = version(runner, "fls", fls_path)
        source = private_file(root, "target", raw)
        offset_args = ["-b", str(sector_size), "-o", str(partition_offset_sectors)]
        # fsstat identifies the filesystem type/label; its text is bounded and
        # reported verbatim (truncated), not parsed — it is informational, the
        # entry listing below is the normalized/validated part of the result.
        _, fsstat_out, _ = runner.run([fsstat_path, *offset_args, source], allowed=(0, 1))
        fls_args = [fls_path, "-l", *offset_args]
        fls_args.append("-d" if deleted_only else "-a")
        if recursive:
            fls_args.append("-r")
        fls_args.append(source)
        _, fls_out, _ = runner.run(fls_args, allowed=(0, 1), output_limit=16 * 1024 * 1024)
        result = normalize_fls(fls_out)
        return {"backend": "fls", "backend_version": fls_version, "backend_sha256": binary_digest(fls_path),
                "sector_size": sector_size, "partition_offset_sectors": partition_offset_sectors,
                "deleted_only": bool(deleted_only), "recursive": bool(recursive),
                "filesystem_info": fsstat_out[:4096].decode("utf-8", "replace"), **result}


def recover(raw, config, *, sector_size, partition_offset_sectors, inode, max_bytes, timeout, scratch_parent):
    if not isinstance(inode, str) or _INODE.fullmatch(inode) is None:
        raise CoreError("Invalid inode address")
    if type(max_bytes) is not int or not 1 <= max_bytes <= MAX_RECOVER_BYTES:
        raise CoreError("Invalid recovery byte limit")
    with tempfile.TemporaryDirectory(prefix="tsk-", dir=scratch_parent) as directory:
        root = Path(directory)
        runner = Runner(root, timeout, max_scratch_bytes=DISK_SCRATCH_MAX_BYTES,
                        max_scratch_entries=DISK_SCRATCH_MAX_ENTRIES, max_file_bytes=MAX_INPUT)
        path = _tool_executable(config, "icat")
        backend_version = version(runner, "icat", path)
        source = private_file(root, "target", raw)
        _, stdout, _ = runner.run(
            [path, "-r", "-b", str(sector_size), "-o", str(partition_offset_sectors), source, inode],
            allowed=(0,), output_limit=max_bytes)
        if len(stdout) > max_bytes:
            raise CoreError("Recovered content exceeds byte limit")
        # Written directly into scratch_parent (the caller's own tempdir, which
        # outlives this function's own `directory` and is read back by
        # sleuthkit.py after run_bounded returns) — never through run_bounded's
        # own stdout/JSON channel, whose hard ceiling (1 MiB) real recovered
        # file content could easily exceed.
        output_path = Path(scratch_parent) / "recovered.bin"
        with open(output_path, "wb") as handle:
            handle.write(stdout)
        return {"backend": "icat", "backend_version": backend_version, "backend_sha256": binary_digest(path),
                "sector_size": sector_size, "partition_offset_sectors": partition_offset_sectors,
                "inode": inode, "recovered_bytes": len(stdout), "recovered_sha256": hashlib.sha256(stdout).hexdigest()}


def dispatch(op, raw, config, *, timeout, scratch_parent, **params):
    if op == "partitions":
        return partitions(raw, config, sector_size=params["sector_size"], timeout=timeout, scratch_parent=scratch_parent)
    if op == "entries":
        return entries(raw, config, sector_size=params["sector_size"],
                       partition_offset_sectors=params["partition_offset_sectors"],
                       deleted_only=bool(params.get("deleted_only")), recursive=bool(params.get("recursive")),
                       timeout=timeout, scratch_parent=scratch_parent)
    if op == "recover":
        return recover(raw, config, sector_size=params["sector_size"],
                       partition_offset_sectors=params["partition_offset_sectors"],
                       inode=params["inode"], max_bytes=params["max_bytes"],
                       timeout=timeout, scratch_parent=scratch_parent)
    raise CoreError("Unsupported Sleuth Kit operation")


def main():
    try:
        data = json.loads(sys.stdin.buffer.read(16385))
        source = Path(data["source"])
        with source.open("rb") as stream:
            raw = _read_bounded(stream, MAX_INPUT)
        if not 0 < len(raw) <= MAX_INPUT or hashlib.sha256(raw).hexdigest() != data["source_sha256"]:
            raise CoreError("Sleuth Kit verified source changed")
        result = dispatch(data["op"], raw, data["config"], timeout=data["timeout"],
                          scratch_parent=data["scratch"], **data.get("params", {}))
        check = hashlib.sha256()
        with source.open("rb") as stream:
            while block := stream.read(1048576):
                check.update(block)
        if check.hexdigest() != data["source_sha256"]:
            raise CoreError("Sleuth Kit evidence changed during analysis")
        print(json.dumps({"input_sha256": data["source_sha256"], "input_bytes": len(raw), **result},
                         ensure_ascii=True))
        return 0
    except BaseException:
        print('{"error":"sleuthkit_operation_failed"}')
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
