# Static crypto inspection

Run `crypto-inspect CASE FILE` through the CYBER CORE CLI after creating a scoped investigation. This acquires and verifies an evidence copy, supervises the static worker, checks authorization/pause/cancellation, and saves an audited `crypto_inspect` operation with a transactional evidence guard.

Options: `--max-findings 256 --seconds 300 --output-bytes 262144`; all are upper bounds and time/input remain limited by CORE. `--capstone` requests optional instruction evidence. `--crypto-ghidra-home /trusted/ghidra --crypto-java-home /trusted/jdk` requests pinned Ghidra 12.1.4 on Linux. Tools operate on static input; the inspected program is never executed.

Evidence layers are separate: full AES S-box, all 64 SHA-256 round constants in either byte order, ChaCha sigma; exact allowlisted PE imports/exports and ELF symbol table entries; weak technical names; optional file-backed executable instruction decoding; optional Ghidra incoming references and containing-function addresses. Generic crypto APIs do not identify a cipher/mode/key. Rule IDs are versioned; no keys, arbitrary strings, neighboring bytes or pseudocode are exported.

PE EXE/DLL and ELF have validated headers, payload bounds and unambiguous file-to-virtual mappings. Raw BIN has byte triage with unknown architecture and no invented load address. Intel HEX/S-record decode checksums and gaps using the existing parser, with 1MiB decoded/64MiB record input limits. Decoded findings carry absolute decoded address and first source-record offset, with source byte offset null because encoded text bytes differ from decoded bytes. A signature may span contiguous records, never a missing address.

A maximum 1GiB input is mmap-read; signature scans use 64KiB chunks with overlap. Entropy uses 4KiB windows and means possible compression or encryption, never an algorithm. No decompression, key extraction or key derivation occurs. At most 256 combined findings and 256KiB output are exported; finding saturation stops that byte scan and marks partial coverage. No-findings does not establish absence of cryptography.

Structural parsing is capped at 100000 ELF symbols/PE thunk records, 4096 import descriptors, and existing firmware table limits. Oversized/malformed structure fails closed. PE delay imports and managed runtime metadata, stripped ELF dynamic tables without section headers, .NET/Java/scripts/other proprietary families are not interpreted beyond byte triage; these limitations remain even if no signature is found. Ghidra cannot supply universal coverage.

Capstone supports declared little-endian x86/x86_64/AArch64 executable sections with validated file-backed mappings, up to 16MiB and one million instructions. Invalid encodings stop a region; no skipdata reinterpretation. Instruction evidence is a static decoding, not reachability proof. Ghidra uses fixed repository exporter, library loading disabled, relocations disabled for ELF, one CPU, 1GiB Java heap, a supervised shared deadline, and bounded scratch/stdout. Missing optional dependencies reduce coverage; failures never masquerade as an executed successful tool.

Development and fixtures run only in GitHub Actions, using generated benign specimens. The compiled fixture is analyzed statically; its AES instruction function is not executed. Linux real-tools exercises full ELF symbols, AES instructions and Ghidra references. Windows/Linux contract jobs run the complete suite. No real client evidence is used.

RED evidence: tests-only head 8339cfd8c6e3667319f4d0dfc9606fda810f0a9e, Actions run 41259424678, Windows job 124709461876: 10 tests, 9 expected missing-adapter assertion failures, 1 real-tools skip. GREEN evidence is recorded in the PR after actual runs.
