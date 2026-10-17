"""Optional, bounded decoding of declared executable bytes; never executes them."""
from importlib import import_module

from cyber_core.errors import CoreError

_MAX_BYTES = 4096
_MAX_INSTRUCTIONS = 128
_LIMITATION = "Static decoding under declared architecture; not execution, control-flow proof or decompilation."


def _empty(status, **fields):
    return {"status": status, "instructions": [], "limitations": _LIMITATION, **fields}


def _span(region):
    return region.get("memory_size") or region.get("file_size", 0)


def _file_span(region):
    return min(region.get("file_size", 0), _span(region))


def _choose(regions, entry):
    if entry:
        address, basis = entry, "declared_entry_point"
    else:
        candidates = [r for r in regions if r.get("executable") and
                      _file_span(r) and not r.get("compressed")]
        if not candidates:
            return None, "no_executable_file_bytes"
        first = min(candidates, key=lambda r: (r["virtual_address"], r["file_offset"]))
        address, basis = first["virtual_address"], "first_declared_executable_region"
    covering = [r for r in regions if r["virtual_address"] <= address <
                r["virtual_address"] + _span(r)]
    if not covering:
        return None, "entry_not_file_backed"
    if any(not r.get("executable") for r in covering):
        return None, "entry_not_executable"
    if any(r.get("compressed") for r in covering):
        return None, "compressed_code_unsupported"
    if any(address - r["virtual_address"] >= _file_span(r) for r in covering):
        return None, "entry_not_file_backed"
    offsets = {r["file_offset"] + address - r["virtual_address"] for r in covering}
    if len(offsets) != 1:
        return None, "ambiguous_entry_mapping"
    available = min(_file_span(r) - (address - r["virtual_address"]) for r in covering)
    original = available
    # Do not decode across a new mapping or permission boundary.
    for region in regions:
        if _span(region) and address < region["virtual_address"] < address + available:
            available = region["virtual_address"] - address
    return {"offset": offsets.pop(), "address": address, "available": available,
            "basis": basis, "mapping_truncated": available < original}, None


def _region(metadata):
    sections = [r for r in metadata.get("section_headers", []) if not r.get("ignored")]
    if "segments" in metadata:
        if metadata.get("type") == 1:
            # ET_REL addresses belong to individual sections, not one loaded image.
            executable = [r for r in sections if r.get("executable") and
                          _file_span(r) and not r.get("compressed")]
            if not executable:
                return None, "no_executable_file_bytes"
            choice, error = _choose([executable[0]], None)
            if choice:
                choice["basis"] = "first_executable_relocatable_section"
                choice["address_basis"] = "Section-relative declared address; relocations are not applied"
                choice["section_index"] = executable[0]["index"]
            return choice, error
        if metadata.get("type") not in (2, 3):
            return None, "unsupported_elf_object_type"
        loads = [r for r in metadata["segments"] if r.get("type") == 1]
        if loads:
            choice, error = _choose(loads, metadata.get("entry_point"))
            if error:
                return None, error
            address, offset = choice["address"], choice["offset"]
            original = choice["available"]
            for section in sections:
                if not section.get("allocated"):
                    continue
                start = section["virtual_address"]
                if start <= address < start + _span(section):
                    delta = address - start
                    if section.get("compressed") or delta >= _file_span(section) or (
                            section["file_offset"] + delta != offset):
                        return None, "conflicting_section_mapping"
                    choice["available"] = min(choice["available"], _file_span(section) - delta)
                elif address < start < address + choice["available"]:
                    choice["available"] = start - address
            choice["mapping_truncated"] |= choice["available"] < original
            return choice, None
        if metadata.get("type") in (2, 3):
            return None, "no_executable_load_map"
    return _choose(sections, metadata.get("entry_point"))


def preview(data, metadata):
    """Decode at most 4 KiB/128 instructions from a previously validated layout."""
    architecture = metadata.get("architecture", "unknown")
    if architecture == "unknown":
        return _empty("architecture_not_declared")
    if architecture not in ("x86", "x86_64", "aarch64"):
        return _empty("unsupported_architecture", architecture=architecture)
    if metadata.get("endian", "little") != "little":
        return _empty("unsupported_encoding", architecture=architecture)
    chosen, selection_error = _region(metadata)
    if selection_error:
        return _empty(selection_error, architecture=architecture)
    offset, address, available, basis = (chosen[k] for k in ("offset", "address", "available", "basis"))
    if not 0 <= offset <= len(data) or available > len(data) - offset:
        raise CoreError("Disassembly range outside validated input")
    if architecture == "aarch64" and address % 4:
        return _empty("unaligned_entry_point", architecture=architecture)
    common = {"architecture": architecture, "source_file_offset": offset,
              "start_address": address, "selection_basis": basis,
              "mapping_truncated": chosen["mapping_truncated"],
              "address_basis": chosen.get("address_basis", "Declared header addresses; relocations are not applied"),
              "source_section_index": chosen.get("section_index")}
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
