"""Bounded structural metadata, not an executable loader or memory emulator."""
import struct

from cyber_core.errors import CoreError

_MAX_ENTRIES = 256
_MAX_NAME = 128
_ELF_ARCH = {2: "sparc", 3: "x86", 8: "mips", 20: "powerpc", 21: "powerpc64",
             22: "s390", 40: "arm", 62: "x86_64", 183: "aarch64", 243: "riscv"}
_PE_ARCH = {0x14c: "x86", 0x8664: "x86_64", 0x1c0: "arm", 0x1c2: "thumb",
            0x1c4: "thumb2", 0xaa64: "aarch64", 0xa641: "arm64ec", 0xa64e: "arm64x",
            0x5032: "riscv32", 0x5064: "riscv64"}


def _fail(message):
    raise CoreError("Firmware structure: " + message)


def _count(value):
    if value > _MAX_ENTRIES:
        _fail("table exceeds 256-entry structural metadata limit")


def _file_range(data, offset, size):
    if size and (offset > len(data) or size > len(data) - offset):
        _fail("payload outside input")


def _address(address, size, bits):
    if address >= 1 << bits or size > (1 << bits) - address:
        _fail("declared address range overflows its width")


def _alignment(value):
    if value and value & (value - 1):
        _fail("alignment is not zero or a power of two")


def _disjoint(ranges):
    previous_end = 0
    for start, end in sorted(ranges):
        if start < previous_end:
            _fail("overlapping section file ranges are unsupported")
        previous_end = end


def _section_name(data, table, index):
    if table is None:
        return ("", False) if index == 0 else (None, False)
    start, size = table
    if index >= size:
        _fail("section name outside string table")
    begin = start + index
    stop = min(start + size, begin + _MAX_NAME + 1)
    end = data.find(b"\0", begin, stop)
    truncated = end < 0
    if truncated:
        end = begin + _MAX_NAME
    return data[begin:end].decode("utf-8", errors="replace"), truncated


def elf_details(data, *, bits, endian, machine, phoff, phnum, shoff, shnum, shstr):
    """Called after the ELF header and complete header-table bounds are checked."""
    _count(phnum)
    _count(shnum)
    order = "<" if endian == "little" else ">"
    phsize, shsize = (56, 64) if bits == 64 else (32, 40)
    records = [struct.unpack_from(order + ("IIQQQQIIQQ" if bits == 64 else "IIIIIIIIII"),
                                  data, shoff + i * shsize) for i in range(shnum)]
    if records and records[0][1] != 0:
        _fail("first ELF section is not SHT_NULL")
    names = None
    if shstr:
        record = records[shstr]
        if record[1] != 3 or not record[5]:
            _fail("invalid section-name string table")
        _file_range(data, record[4], record[5])
        if data[record[4]] != 0 or data[record[4] + record[5] - 1] != 0:
            _fail("section-name string table must start and end with NUL")
        names = record[4], record[5]
    sections, ranges = [], []
    for index, record in enumerate(records):
        name_index, kind, flags, address, offset, size, link, info, align, entsize = record
        if kind == 0:
            sections.append({"index": index, "type": 0, "name": "", "ignored": True,
                             "file_size": 0, "memory_size": 0})
            continue
        _alignment(align)
        if align > 1 and address % align:
            _fail("unaligned ELF section address")
        if flags & 2:
            _address(address, size, bits)
        if link and link >= shnum:
            _fail("ELF section link outside section table")
        if entsize and size % entsize:
            _fail("ELF section size is not a multiple of its entry size")
        file_size = 0 if kind == 8 else size
        _file_range(data, offset, file_size)
        if file_size:
            ranges.append((offset, offset + file_size))
        name, truncated = _section_name(data, names, name_index)
        sections.append({"index": index, "type": kind, "name": name,
                         "name_truncated": truncated, "name_offset": name_index,
                         "flags": flags, "allocated": bool(flags & 2),
                         "writable": bool(flags & 1), "executable": bool(flags & 4),
                         "virtual_address": address, "file_offset": offset,
                         "file_size": file_size, "declared_size": size,
                         "memory_size": size if flags & 2 else 0,
                         "alignment": align, "entry_size": entsize, "link": link, "info": info})
    _disjoint(ranges)
    segments = []
    for index in range(phnum):
        record = struct.unpack_from(order + ("IIQQQQQQ" if bits == 64 else "IIIIIIII"),
                                    data, phoff + index * phsize)
        if bits == 64:
            kind, flags, offset, address, physical, file_size, memory_size, align = record
        else:
            kind, offset, address, physical, file_size, memory_size, flags, align = record
        if kind == 0:
            segments.append({"index": index, "type": 0, "ignored": True})
            continue
        _alignment(align)
        _file_range(data, offset, file_size)
        _address(address, memory_size, bits)
        if kind == 1:
            if file_size > memory_size:
                _fail("ELF load segment file size exceeds memory size")
            if align > 1 and address % align != offset % align:
                _fail("ELF load segment address/offset alignment mismatch")
        segments.append({"index": index, "type": kind, "file_offset": offset,
                         "file_size": file_size, "virtual_address": address,
                         "physical_address_declared": physical, "memory_size": memory_size,
                         "zero_fill_bytes": memory_size - file_size if kind == 1 else None,
                         "flags": flags, "readable": bool(flags & 4),
                         "writable": bool(flags & 2), "executable": bool(flags & 1),
                         "alignment": align})
    return {"architecture": _ELF_ARCH.get(machine, "unknown"),
            "architecture_basis": "ELF e_machine; declared, not execution-verified",
            "section_count": shnum, "program_header_count": phnum,
            "section_headers": sections, "segments": segments,
            "validation_scope": "ELF headers, table and payload bounds, names and declared ranges; not loader semantics"}


def pe_details(data, *, machine, optional, optional_size, sections, magic, characteristics):
    """Called after DOS/COFF/optional/section-table bounds are checked."""
    _count(sections)
    bits = 32 if magic == 0x10b else 64
    image_base = int.from_bytes(data[optional + (28 if bits == 32 else 24):
                                     optional + (32 if bits == 32 else 32)], "little")
    entry_rva = struct.unpack_from("<I", data, optional + 16)[0]
    _address(image_base + entry_rva, 0, bits)
    headers, ranges = [], []
    table = optional + optional_size
    for index in range(sections):
        at = table + index * 40
        name = data[at:at + 8].split(b"\0", 1)[0].decode("utf-8", errors="replace")
        memory_size, rva, file_size, offset = struct.unpack_from("<IIII", data, at + 8)
        flags = struct.unpack_from("<I", data, at + 36)[0]
        _address(rva, max(memory_size, file_size), 32)
        _address(image_base + rva, max(memory_size, file_size), bits)
        _file_range(data, offset, file_size)
        if file_size:
            ranges.append((offset, offset + file_size))
        headers.append({"index": index, "name": name, "virtual_address_rva": rva,
                        "virtual_address": image_base + rva, "memory_size": memory_size,
                        "file_offset": offset, "file_size": file_size, "characteristics": flags,
                        "readable": bool(flags & 0x40000000), "writable": bool(flags & 0x80000000),
                        "executable": bool(flags & 0x20000000)})
    _disjoint(ranges)
    return {"architecture": _PE_ARCH.get(machine, "unknown"),
            "architecture_basis": "PE Machine; declared, not execution-verified",
            "image_base": image_base, "entry_point_rva": entry_rva,
            "entry_point": image_base + entry_rva, "is_dll": bool(characteristics & 0x2000),
            "characteristics": characteristics, "section_count": sections,
            "section_headers": headers,
            "validation_scope": "PE headers, section file bounds and declared ranges; not loader semantics"}
