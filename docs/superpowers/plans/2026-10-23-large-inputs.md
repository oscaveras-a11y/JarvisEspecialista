# Large Inputs Implementation Plan
> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.
**Goal:** Enable static acquisition and firmware inspection up to 1 GiB without whole-file Python allocations.
**Architecture:** Preserve existing service/child boundary and defaults; use read-only file mappings and chunked hashing/comparison.
**Tech Stack:** Python 3.12, existing CORE, GitHub Actions Windows/Linux.
**Spec:** docs/superpowers/specs/2026-10-23-visionft-analysis-design.md

## Global Constraints
Only synthetic inputs on GitHub. Preserve other branches. Default 64 MiB retained; configurable ceiling 1 GiB. Not full VisionFT delivery.
## Review Focus
Mapping closure on failure; malformed large headers; whitespace-leading text; comparison tail/range cap; consistency between service and child ceilings.
### Task 1: Capacity
- [ ] Add tests for 600 MiB firmware/CORE, 250 MiB PE, comparison >64 MiB and configured rejection.
- [ ] Run failing tests on GitHub and inspect failure reasons.
- [ ] Replace firmware whole-file allocations with closed read-only mappings, hash chunks; bounded text conversion.
- [ ] Increase consistent service/child/external input ceilings to 1 GiB with strict validation.
- [ ] Run capacity tests and full regressions in Windows/Linux on GitHub; review results.
### Later tasks
NSIS, COFF/Qt, targeted Ghidra, FTW2 variants, comparison normalization and checkpoints remain governed by the full design and are not claimed by this capacity increment.
## Ledger
Ruling: execute capacity increment inline under existing approval; no additional confirmation.
Pre-flight: service -> child -> firmware must share the same 1 GiB ceiling; byte defaults remain 64 MiB.
