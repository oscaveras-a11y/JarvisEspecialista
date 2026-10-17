"""Optional, bounded decoding of declared executable bytes; never executes them."""
from importlib import import_module

from cyber_core.errors import CoreError

_MAX_BYTES = 4096
_MAX_INSTRUCTIONS = 128
_LIMITATION = "Static decoding under declared architecture; not execution, control-flow proof or decompilation."


def _empty(status, **fields):
    return {"status": status, "instructions": [], "limitations": _LIMITATION, **fields}


def _region(data, metadata):
    sections = metadata.get("section_headers", [])
    segments = metadata.get("segments", [])
    regions = [r for r in (*sections, *segments)
               if r.get("executable") and r.get("file_size", 0) > 0 and not r.get("compressed")]
    entry = metadata.get("entry_point")
    for region in regions:
        start = region["virtual_address"]
        size = min(region["file_size"], region.get("memory_size") or region["file_size"])
        if entry and start <= entry < start + size:
            delta = entry - start
            return region["file_offset"] + delta, entry, size - delta, "declared_entry_point"
    if entry:
        return None
    if regions:
        region = regions[0]
        size = min(region["file_size"], region.get("memory_size") or region["file_size"])
        return region["file_offset"], region["virtual_address"], size, "first_declared_executable_region"
    return None


def preview(data, metadata):
    """Decode at most 4 KiB/128 instructions from a previously validated layout."""
    architecture = metadata.get("architecture", "unknown")
    if architecture == "unknown":
        return _empty("architecture_not_declared")
    if architecture not in ("x86", "x86_64", "aarch64"):
        return _empty("unsupported_architecture", architecture=architecture)
    if metadata.get("endian", "little") != "little":
        return _empty("unsupported_encoding", architecture=architecture)
    chosen = _region(data, metadata)
    if chosen is None:
        return _empty("entry_not_file_backed" if metadata.get("entry_point") else
                      "no_executable_file_bytes", architecture=architecture)
    offset, address, available, basis = chosen
    if not 0 <= offset <= len(data) or available > len(data) - offset:
        raise CoreError("Disassembly range outside validated input")
    if architecture == "aarch64" and address % 4:
        return _empty("unaligned_entry_point", architecture=architecture)
    common = {"architecture": architecture, "source_file_offset": offset,
              "start_address": address, "selection_basis": basis,
              "address_basis": "Declared header addresses; relocations are not applied"}
    try:
        capstone = import_module("capstone")
    except (ImportError, OSError):
        return _empty("dependency_unavailable", backend="capstone", **common)
    configurations = {
        "x86": (capstone.CS_ARCH_X86, capstone.CS_MODE_32),
        "x86_64": (capstone.CS_ARCH_X86, capstone.CS_MODE_64),
        "aarch64": (capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM),
    }
    sample = data[offset:offset + min(available, _MAX_BYTES)]
    instructions, consumed = [], 0
    try:
        decoder = capstone.Cs(*configurations[architecture])
        # detail and skipdata remain disabled. Broken bytes stop decoding.
        for at, size, mnemonic, operands in decoder.disasm_lite(sample, address, count=_MAX_INSTRUCTIONS):
            if size <= 0 or consumed + size > len(sample) or at != address + consumed:
                raise CoreError("Invalid disassembler metadata")
            instructions.append({"address": at, "size": size,
                                 "bytes_hex": sample[consumed:consumed + size].hex(),
                                 "mnemonic": mnemonic[:64], "operands": operands[:256]})
            consumed += size
    except capstone.CsError:
        return _empty("decoder_failure", backend="capstone",
                      backend_version=capstone.__version__, **common)
    return {"status": "decoded" if instructions else "no_instructions_decoded", "backend": "capstone",
            "backend_version": capstone.__version__, "instructions": instructions,
            "sample_bytes": len(sample), "decoded_bytes": consumed,
            "undecoded_bytes": len(sample) - consumed,
            "sample_truncated": available > len(sample),
            "instruction_limit_reached": len(instructions) == _MAX_INSTRUCTIONS and consumed < len(sample),
            "limitations": _LIMITATION, **common}
