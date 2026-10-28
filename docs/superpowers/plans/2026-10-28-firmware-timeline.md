# Offline firmware timeline: design and implementation plan

User-approved scenario: investigate recorded original → changed → original firmware fingerprints, including incomplete records and ordinary operation. This implements forensic analysis (sections 4/8/18); it does not access equipment or electoral systems.

Approaches: final-file comparison cannot reveal a restored intermediate state. Live collection requires device-specific authorization and interfaces absent here. Implement offline correlation of supplied JSONL observations, preserving input evidence through the existing CORE acquisition contract.

Architecture: a bounded JSONL parser normalizes timezone-aware timestamps and declared clock uncertainty; groups by device/component; identifies strictly ordered A/B/A measurement runs. Access/update/boot events provide context only. Source and timestamps are declarations, not authenticated facts. Record gaps, sequence reversals, uncertain order and omitted findings. No verdict of fraud or manufacturer authenticity.

Files: src/cyber_core/forensics/firmware_timeline.py (parser/analyzer and narrow CORE adapter); CLI operations wiring; tests/test_firmware_timeline.py; .github/workflows/firmware-timeline.yml; docs/firmware-timeline.md.

Interfaces: analyze(stream, *, max_bytes=16777216,max_line_bytes=16384,max_events=10000,max_findings=128,max_seconds=30,check=None) returns JSON-safe metadata. run_timeline(core,case,path,**budgets) acquires verified copy, checks permission and pause during parsing, persists evidence, parameters and analyzer/runtime versions.

Review focus: overlapping clocks must not imply strict order; separate devices/components; duplicate IDs and keys; false positives from accesses/update claims; bounded malformed inputs and output.

- [ ] Commit synthetic tests and run GitHub CI; expect missing analyzer/CLI failures.
- [ ] Implement parser, correlation, CORE/CLI adapter and usage docs. Run targeted tests plus complete offline regressions on Linux and Windows.
- [ ] Fresh read-only review, address important findings with failing tests first, publish reviewable PR; do not merge.

Limits: no real device adapters, signature verification of logs, remote collection, manufacturer identity, continuous coverage guarantee or proof of fraud. Equal final hashes cannot rule out a temporary change. Synthetic declared measurements do not demonstrate deployment on actual hardware.
