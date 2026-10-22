"""Offline, read-only integrity triage for authorized automotive firmware.

Reports exact repeated blocks as possible redundant copies. It does not
repair, decrypt, extract keys, or establish firmware authenticity.
"""
from collections import defaultdict
from hashlib import sha256
from pathlib import Path


def inspect_redundancy(path, *, block_size=4096, max_bytes=64 * 1024 * 1024,
                       max_groups=32):
    if not isinstance(block_size,int) or isinstance(block_size,bool) or not 256 <= block_size <= 65536:
        raise ValueError("block_size must be 256..65536")
    if not isinstance(max_bytes,int) or isinstance(max_bytes,bool) or not 1 <= max_bytes <= 64 * 1024 * 1024:
        raise ValueError("invalid max_bytes")
    if not isinstance(max_groups,int) or isinstance(max_groups,bool) or not 1 <= max_groups <= 256:
        raise ValueError("invalid max_groups")
    source=Path(path)
    if source.is_symlink() or not source.is_file():
        raise ValueError("input must be a regular non-symlink file")
    size=source.stat().st_size
    if not 0 < size <= max_bytes:
        raise ValueError("firmware empty or exceeds byte limit")
    digest=sha256()
    blocks=defaultdict(list)
    with source.open("rb") as stream:
        offset=0
        while True:
            chunk=stream.read(block_size)
            if not chunk:
                break
            digest.update(chunk)
            # Exclude partial, uniform and zero-filled blocks from redundancy
            # hypotheses: they frequently represent padding, not backups.
            if len(chunk)==block_size and len(set(chunk))>1:
                blocks[sha256(chunk).hexdigest()].append(offset)
            offset+=len(chunk)
    if source.stat().st_size!=size:
        raise ValueError("input changed during inspection")
    groups=[{"sha256":fingerprint,"offsets":positions,"block_size":block_size}
            for fingerprint,positions in blocks.items() if len(positions)>1]
    groups.sort(key=lambda x:(-len(x["offsets"]),x["offsets"][0]))
    return {
        "file_size":size,"sha256":digest.hexdigest(),
        "block_size":block_size,"repeated_block_groups":groups[:max_groups],
        "groups_total":len(groups),"groups_truncated":len(groups)>max_groups,
        "recovery_demonstrated":False,
        "interpretation":"Exact repeated nonuniform blocks only; redundancy may be code/data repetition, not a recoverable backup.",
        "next_steps":["Compare authorized known-good images and manufacturer documentation.",
                      "Validate checksums/signatures using documented format-specific procedures.",
                      "Preserve original evidence; never flash reconstructed data without independent validation."]
    }
