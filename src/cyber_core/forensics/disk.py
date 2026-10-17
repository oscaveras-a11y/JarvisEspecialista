"""Bounded, read-only inventory of raw MBR/GPT image bytes.

No filesystem parsing, mounting, writes, carving, or recovery is performed.
This validates only the primary GPT structures, never the backup GPT.
"""
from __future__ import annotations

import hashlib
import struct
import uuid
import zlib

DEFAULT_MAX_BYTES = 16 * 1024 * 1024
HARD_MAX_BYTES = 64 * 1024 * 1024
MAX_PARTITIONS = 1024
MAX_OVERLAP_RECORDS = 256


def _integer_limit(value: int, minimum: int, maximum: int, name: str) -> None:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError(f"{name} must be an integer in [{minimum}, {maximum}]")


def _range(first: int, count: int, sector_size: int, size: int) -> tuple[int, int]:
    offset, length = first * sector_size, count * sector_size
    if count <= 0 or offset > size or length > size - offset:
        raise ValueError("partition bounds exceed supplied image")
    return offset, length


def _overlaps(partitions: list[dict], metadata: list[dict]) -> dict:
    # Bound both input cardinality and exported diagnostics, including hostile
    # images whose every partition overlaps every other partition.
    regions = partitions + metadata
    overlaps, count = [], 0
    for i, left in enumerate(partitions):
        for right in regions[i + 1:]:
            start = max(left["offset"], right["offset"])
            end = min(left["offset"] + left["length"],
                      right["offset"] + right["length"])
            if start < end:
                count += 1
                if len(overlaps) < MAX_OVERLAP_RECORDS:
                    overlaps.append({"left": left["id"], "right": right["id"],
                                     "offset": start, "length": end - start})
    return {"overlaps": overlaps, "overlap_count": count,
            "overlaps_truncated": count > len(overlaps),
            "partition_ranges_disjoint": count == 0}


def inspect_disk_image(
    data: bytes, *, sector_size: int = 512,
    max_bytes: int = DEFAULT_MAX_BYTES, max_partitions: int = 256,
) -> dict:
    """Inventory immutable complete raw-image bytes within explicit budgets.

    Offsets are zero-based bytes; ranges are half-open [offset, offset+length).
    Invalid signatures, bounds, or primary GPT CRCs raise ValueError.
    Overlapping declared partitions are returned as observations, not repaired.
    The caller is responsible for authorization and verified-copy custody.
    """
    _integer_limit(max_bytes, 512, HARD_MAX_BYTES, "max_bytes")
    _integer_limit(max_partitions, 1, MAX_PARTITIONS, "partition limit")
    if type(sector_size) is not int or sector_size not in (512, 4096):
        raise ValueError("sector_size must be explicitly 512 or 4096")
    if not isinstance(data, bytes):
        raise ValueError("data must be immutable bytes from a verified copy")
    if len(data) > max_bytes:
        raise ValueError("image exceeds max_bytes")
    if len(data) < sector_size or len(data) % sector_size:
        raise ValueError("image bounds require complete logical sectors")
    if data[510:512] != b"\x55\xaa":
        raise ValueError("missing MBR signature at offset 510")

    size = len(data)
    mbr_entries = []
    for index in range(4):
        pos = 446 + 16 * index
        status, kind = data[pos], data[pos + 4]
        first, count = struct.unpack_from("<II", data, pos + 8)
        if kind == 0 and count == 0 and first == 0:
            continue
        if status not in (0, 0x80) or kind == 0:
            raise ValueError("invalid MBR partition entry")
        offset, length = _range(first, count, sector_size, size)
        mbr_entries.append({
            "id": f"mbr_partition_{index + 1}", "index": index + 1,
            "entry_offset": pos, "type_code": kind, "first_lba": first,
            "sector_count": count, "offset": offset, "length": length,
            "kind": ("protective" if kind == 0xEE else
                     "extended_container_unexpanded" if kind in (0x05, 0x0F, 0x85)
                     else "primary"),
        })
    metadata = [{"id": "mbr", "offset": 0, "length": sector_size}]
    result = {
        "schema_version": 1, "format": "mbr", "size_bytes": size,
        "sector_size": sector_size, "sha256": hashlib.sha256(data).hexdigest(),
        "partitions": mbr_entries, "metadata_regions": metadata,
        "limitations": ["inventory_only", "no_filesystem_validation",
                        "no_mount_write_or_recovery", "no_extended_partition_walk"],
    }
    protective = [p for p in mbr_entries if p["type_code"] == 0xEE]
    signature = data[sector_size:sector_size + 8] == b"EFI PART"
    if not signature and not protective:
        if len(mbr_entries) > max_partitions:
            raise ValueError("partition limit exceeded")
        result.update(_overlaps(mbr_entries, metadata))
        return result
    if not signature:
        raise ValueError("protective MBR without primary GPT signature")
    if len(data) < sector_size + 92:
        raise ValueError("primary GPT header bounds exceed image")

    (sig, revision, header_size, header_crc, reserved, current_lba,
     backup_lba, first_usable, last_usable, disk_guid, entries_lba,
     count, entry_size, entries_crc) = struct.unpack_from(
         "<8sIIIIQQQQ16sQIII", data, sector_size)
    if revision != 0x10000 or reserved != 0:
        raise ValueError("unsupported GPT revision or reserved header field")
    if not 92 <= header_size <= sector_size:
        raise ValueError("GPT header size bounds invalid")
    header = bytearray(data[sector_size:sector_size + header_size])
    header[16:20] = bytes(4)
    if zlib.crc32(header) != header_crc:
        raise ValueError("primary GPT header CRC mismatch")
    sectors = size // sector_size
    if current_lba != 1 or backup_lba != sectors - 1 or backup_lba <= 1:
        raise ValueError("GPT header LBA bounds inconsistent with supplied image")
    if not 2 <= first_usable <= last_usable < backup_lba:
        raise ValueError("GPT usable LBA bounds invalid")
    if not 1 <= count <= max_partitions:
        raise ValueError("GPT partition limit exceeded")
    if entry_size < 128 or entry_size % 128 or (entry_size // 128) & (entry_size // 128 - 1):
        raise ValueError("unsupported GPT entry size")
    array_offset, array_length = entries_lba * sector_size, count * entry_size
    if (entries_lba < 2 or array_offset > size
            or array_length > size - array_offset
            or array_offset + array_length > first_usable * sector_size):
        raise ValueError("GPT partition array bounds invalid")
    if array_length < 16384:
        raise ValueError("GPT partition array reserves less than 16384 bytes")
    array = memoryview(data)[array_offset:array_offset + array_length]
    if zlib.crc32(array) != entries_crc:
        raise ValueError("primary GPT partition array CRC mismatch")
    partitions = []
    for index in range(count):
        relative = index * entry_size
        if array[relative:relative + 16] == bytes(16):
            continue
        first, last = struct.unpack_from("<QQ", array, relative + 32)
        if not first_usable <= first <= last <= last_usable:
            raise ValueError("GPT partition bounds exceed usable range")
        offset, length = _range(first, last - first + 1, sector_size, size)
        partitions.append({
            "id": f"gpt_partition_{index + 1}", "index": index + 1,
            "entry_offset": array_offset + relative,
            "type_guid": str(uuid.UUID(bytes_le=bytes(array[relative:relative + 16]))),
            "first_lba": first, "last_lba": last,
            "offset": offset, "length": length, "kind": "gpt_declared",
        })
    metadata.extend([
        {"id": "gpt_primary_header", "offset": sector_size, "length": sector_size},
        {"id": "gpt_primary_entries", "offset": array_offset, "length": array_length},
    ])
    result.update({
        "format": "gpt_primary", "partitions": partitions, "mbr_entries": mbr_entries,
        "gpt": {"header_crc32_valid": True, "entries_crc32_valid": True,
                "header_offset": sector_size, "header_size": header_size,
                "entries_offset": array_offset, "entries_length": array_length,
                "entry_size": entry_size, "entry_count": count,
                "first_usable_lba": first_usable, "last_usable_lba": last_usable,
                "backup_header_lba": backup_lba, "backup_validated": False,
                "protective_mbr_present": bool(protective),
                "hybrid_mbr_present": any(p["type_code"] != 0xEE for p in mbr_entries)},
    })
    result["limitations"].append("backup_gpt_not_validated")
    result.update(_overlaps(partitions, metadata))
    return result
