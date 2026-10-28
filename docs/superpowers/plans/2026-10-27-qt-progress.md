# Qt resources implementation ledger
Spec: docs/superpowers/specs/2026-10-23-visionft-analysis-design.md.
Own staging branch codex/visionft-qt-stage from 7545685; do not move own PR #27 branch until verified.
- Official primary layout: qt/qtdeclarative and qt/qtbase tag v6.8.3, compiled data and StaticValue headers, RCC writer/reader.
- Real tools generated fixture in 40615425387: QML format 0x42, Qt 0x060803, 800-byte unit; reader missing RED.
- RED synthetic malformed/layout cases: 40615717559, five tests / thirteen missing-reader failed subcases.
- GREEN readers: 40615921852 — five unit tests and all actual rcc/qmlcachegen field/hash assertions passed; then RED missing qt_operation.
- RED budgets/features: 40616152677 — two failures (stored bytes on unsupported compression and undeclared compressed feature).
- RED encoder memory test: 40616367453 — missing qt_operation under a 256 MiB Linux address-space process, plus the two known failures.
- CORE operation/CLI added with read-only mmap, hash rechecks, bounded scanning, Linux address-space cap, streaming JSON admission and explicit partial summaries.
- Extra real coverage: double constant 1.25 and embedded RCC after an 80 MiB sparse prefix.
- Pending: exact implementation GREEN, fresh reviewer and regressions; CI links belong in PR body after actual verification.
Ruling: only RCC v3 and QV4 format0x42 with declared Qt6.8.3 decoded. Unknown versions remain explicit unsupported candidates.
Ruling: compiled QML results are always partial — bytecode and semantic imports/aliases/signals/enums are not decoded; no recovered-source claim.
Ruling: bounded serialized metadata may omit complete details/resources/components, preserving counts, hashes when retained and explicit omission flags. Streaming admission avoids expanding repeated Unicode into a huge intermediate JSON string.
Ruling: signatures locate candidates, not proof of a valid component. Static resource arrays with no RCC container header are not reconstructed automatically. Embedded qv4cdata may be located independently of resource paths.
Ruling: MD5 is only the unit's declared checksum scope; mismatch is reported as mismatch, not automatic corruption or authentication failure.
Ruling: Linux memory control is child virtual address space including mapping, not aggregate RSS; non-Linux uses explicit bounded allocations and lifecycle control without claiming an applied address-space hard cap.
