# Selected functions implementation ledger
Spec: docs/superpowers/specs/2026-10-23-visionft-analysis-design.md.
Branch: codex/visionft-static-analysis; existing PR #27. Only synthetic tests on GitHub.
- RED: missing module, two assertion failures in run 40610167868 before implementation.
- New operation and trusted exporter: name/entry/range selectors, bounded decompilation and typed static references.
- Legacy quick preview remains untouched; shared adapter receives optional validated selection.
- CLI functions and docs/selected-functions.md explain address semantics and budgets.
- GREEN initial implementation: b06b642, all 13 runs passed; real Ghidra/CORE and 389-test suite in run 40610496476.
- Fresh static reviewer identified escaped Unicode output exceeding IPC; no other confirmed important defect beyond known pseudocode status.
- RED real Ghidra: run 40613477343 at 6e5f701; truncated pseudocode incorrectly reported completed.
- RED Unicode encoder regression: run 40613880162 at f5f2b85; 390 tests, one expected failure, 39 skips.
- Fix pass: selected results are partial for pseudocode truncation; byte-bounded serialization omits complete tail function records and preserves match counts with explicit flags. Output byte budget is API/CLI configurable.
- Pending: final real integrations and regression results for this fix; record immutable run links in PR body.
Ruling: intervals select function entry points, not arbitrary intersecting function bodies. Capstone deep selection and per-function checkpoints remain pending; do not claim those capabilities.

Ruling: retain a bounded partial record instead of aborting when escaped Unicode exceeds IPC — preserve whole function records in deterministic order, report omitted count; a small budget may omit all exported functions, so callers must inspect status/counts.
Minor deferred: false empty non-list selectors coerce to empty; namespaced ambiguity and per-reference truncation need dedicated real fixtures.
