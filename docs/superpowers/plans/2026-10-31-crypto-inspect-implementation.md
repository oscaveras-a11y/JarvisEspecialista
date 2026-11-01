# Crypto inspection implementation

Base: 3061d191ce432b369a60be6c05cf89bf2ba2fd7b. Isolated remote branch codex/crypto-inspect. GitHub-only authoring and runner validation.

1. Commit contracts and Linux/Windows Actions first; observe failing assertion for missing entry point before implementation.
2. Add versioned full AES S-box, SHA-256 round table and ChaCha sigma signatures; fixed allowlisted technical strings stay weak evidence. Chunked scan with overlaps, bounded findings/output and deadline. Entropy is only compression/encryption ambiguity.
3. Reuse validated firmware PE/ELF mappings and bounded Intel HEX/S-record decoders; preserve file offsets and decoded address provenance. Structural PE imports/ELF symbols use bounded trusted format parsers; only recognized API allowlist is exported.
4. Optional Capstone walks only validated executable file-backed ranges and exports crypto instruction rule/address. Optional trusted Ghidra script resolves incoming references at mapped evidence addresses and recognized APIs; exports addresses only, no arbitrary names or pseudocode. Run real compiled benign fixtures in Actions.
5. Supervised child performs static analysis on CORE verified acquisition. Reverify before and inside transactional commit guard, authorization and pause checks, timeout min(CORE,300), input min(CORE,1GiB), <=256 findings and <=256KiB JSON.
6. CLI crypto-inspect CASE FILE; docs disclose all coverage, optional dependency and malformed/partial states. Run focused contracts, compiled real Ghidra check and complete Windows/Linux suite. Open draft PR against codex/readiness-integration with immutable RED/GREEN evidence.

Preflight: CLI shared with web front; crypto patch only adds its command and dispatch. No campaign or cryptanalysis edits. Root merges shared CLI preserving both fronts.
Ruling: reuse bounded firmware record decoders (1MiB decoded cap) and report this extra coverage limit; do not claim gigabyte sparse decoding. Structural export allowlist prevents arbitrary sample strings from entering results.

Ledger: plan committed; RED pending.
