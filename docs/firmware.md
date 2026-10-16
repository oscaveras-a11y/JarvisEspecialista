# Offline firmware inspection

`cyber_core.firmware.analyze_firmware(path, *, max_bytes=67108864,
max_records=100000, max_decoded_bytes=1048576)` reads at most `max_bytes + 1` bytes and returns metadata.
Empty, oversized, corrupt recognized formats and invalid bounds raise `CoreError`.
No input code is executed; source files are never rewritten.

Detection uses bytes, not filename extensions. Intel HEX starts with `:`;
Motorola S-record starts with `S` and a digit; ELF uses its four-byte magic;
PE inspection starts with `MZ` and requires a valid PE signature. Other bytes
are opaque BIN. A recognized signature alone does not establish validity:
the parser must complete before `structure_validated` is true. BIN always
reports false and does not infer architecture or loading address.

- Intel HEX validates ASCII hex, byte counts, checksums, record types 00–05,
  address-window bounds, segment/linear address modes, start records and EOF.
- S19/S28/S37 validate counts, checksums, address widths, optional header/count
  records and matching termination. Mixed data address-width types are rejected.
- Both record formats reject duplicate addresses, including identical repeats,
  and require data plus a terminal record. Blank lines are permitted; comments,
  whitespace within records, multiple blocks and vendor extensions are rejected.
- ELF reports class, endian, numeric machine/type and entry point. Validation
  covers the header and program/section table bounds. Extended table numbering
  is explicitly unsupported. Section contents and executable semantics are not
  validated.
- PE reports class, numeric machine and section count. Validation covers DOS,
  COFF, optional-header/directory-table bounds and raw section bounds. This is
  not a Windows loader, authenticity check or complete executable validator.

`compare_firmware(first, second, *, max_bytes=67108864,
max_decoded_bytes=1048576)` compares decoded
absolute addresses for HEX/S-record, or file offsets for BIN/ELF/PE. Mixing
absolute addresses and file offsets raises `CoreError`. Cross-format HEX/S-record
comparison is supported. File SHA-256 hashes cover the original bytes, so record
ordering or line endings can change hashes without changing decoded data.

`differing_bytes` counts the union of changed addresses, including missing bytes.
`missing_from_first` and `missing_from_second` count absent addresses separately;
an absent byte differs from a stored zero or FF. Changed ranges use inclusive
`start` and exclusive `end_exclusive`, with at most 1,000 ranges returned;
`changed_ranges_total` and `ranges_truncated` expose truncation. Sparse gaps are
never expanded or filled. Memory use scales with input bytes and populated
addresses, not the highest absolute address. Decoded HEX/S-record populated
bytes have a hard ceiling of 1 MiB per input, checked before insertion into the
dictionary. `max_decoded_bytes` may lower this ceiling (positive integer up to
1,048,576); it cannot raise it. This constrains per-byte Python dictionary
memory and sparse comparison union/sort overhead independently of the 64 MiB
source-file limit. Raw BIN/ELF/PE keep their original byte limit and are not
subject to the decoded-record ceiling. Tests exercise rejection at a configured
four-byte cap, success at five bytes, comparison rejection and opaque BIN exemption.

The default limits are per file; comparison uses a 100,000 record limit per
input. This module does not establish ECU compatibility, firmware authenticity,
hardware safety, signatures, encryption details or a valid flash procedure.

Format references used during implementation:

- [Arm Keil Intel HEX description](https://www.keil.com/support/docs/1584/default.htm)
- [TASKING Motorola S-record reference](https://test-tasking.vadeo.de/online-doc/smartcode/cmcs/reference/objfmt_sre.html)
- [System V ELF ABI header](https://refspecs.linuxfoundation.org/elf/gabi4+/ch4.eheader.html)
- [Microsoft PE/COFF specification](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
