# COFF implementation ledger
Spec: docs/superpowers/specs/2026-10-23-visionft-analysis-design.md.
Own staging branch: codex/visionft-coff-stage from aebe742. PR #27 branch remains stable during focused CI.
- RED reader absent: run 40614456890, five tests / eleven expected failed subcases.
- GREEN reader: five tests passed in 40614527947; real CORE step then RED because coff_operation was absent.
- Implementation: bounded mmap reader, distinct address fields, retained name bytes, optional trusted LLVM demanglers, supervised child, CORE operation and CLI.
- Pending: real compiler/demangler/CORE integration and regression results, reviewer, fast-forward own PR branch only after validation.
Ruling: standard COFF only; BigObj/anonymized variants explicitly unsupported. Auxiliary records are bounded/skipped, not semantically decoded. Original mangled names retained.
Ruling: section-relative values do not establish loaded addresses for relocatable objects; only PE headers provide RVA/VA. Symbols do not imply function boundaries.
