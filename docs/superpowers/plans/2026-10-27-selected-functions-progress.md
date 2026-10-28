# Selected functions implementation ledger
Spec: docs/superpowers/specs/2026-10-23-visionft-analysis-design.md.
Branch: codex/visionft-static-analysis; existing PR #27. Only synthetic tests on GitHub.
- RED: missing module, two assertion failures in run 40610167868 before implementation.
- New operation and trusted exporter: name/entry/range selectors, bounded decompilation and typed static references.
- Legacy quick preview remains untouched; shared adapter receives optional validated selection.
- CLI functions and docs/selected-functions.md explain address semantics and budgets.
- Pending: execute real selected Ghidra fixture, regressions and fresh code review before declaring completion.
Ruling: intervals select function entry points, not arbitrary intersecting function bodies. Capstone deep selection and per-function checkpoints remain pending; do not claim those capabilities.
