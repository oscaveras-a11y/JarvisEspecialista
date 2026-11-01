# COFF implementation ledger
Spec: docs/superpowers/specs/2026-10-23-visionft-analysis-design.md.
Own staging branch: codex/visionft-coff-stage from aebe742. PR #27 branch remains stable during focused CI.
- RED reader absent: run 40614456890, five tests / eleven expected failed subcases.
- GREEN reader: five tests passed in 40614527947; real CORE step then RED because coff_operation was absent.
- Implementation: bounded mmap reader, distinct address fields, retained name bytes, optional trusted LLVM demanglers, supervised child, CORE operation and CLI.
- Pending: real compiler/demangler/CORE integration and regression results, reviewer, fast-forward own PR branch only after validation.
Ruling: standard COFF only; BigObj/anonymized variants explicitly unsupported. Auxiliary records are bounded/skipped, not semantically decoded. Original mangled names retained.
Ruling: section-relative values do not establish loaded addresses for relocatable objects; only PE headers provide RVA/VA. Symbols do not imply function boundaries.

- Fresh reviewer: confirmed standard .bss rejection; known self-review type mask issue. Minor missing ABI/output/failure tests added to integration/unit suite.
- RED 40614884266 at 082e047: array falsely flagged function and valid uninitialized section rejected (8 tests; 1 failure and 1 error).
- Fix pass: distinguish declared .bss size from file-backed bytes; exact derived type mask. New sparse 80 MiB offset test uses mmap.
- Pending: exact fix commit GREEN and full regressions before moving PR branch.
Ruling: .bss has no file offset; declared size belongs to uninitialized memory. Mixed/file-backed uninitialized layouts are explicitly unsupported rather than mapped speculatively.
Final review declined-to-judge rulings: CI success must be verified from runner output; private VisionFT, Qt/QML, FTW2, PDB/CodeView, typed auxiliaries, BigObj and relocations are explicitly pending, not silently covered by standard COFF capability. No merge or proprietary analysis is claimed.
