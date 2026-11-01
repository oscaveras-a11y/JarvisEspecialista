# Scoped passive ZAP Implementation Plan

> **For agentic workers:** Use superpowers:executing-plans; implement inline and request one whole-branch review.

**Goal:** Execute real passive ZAP against controlled HTTPS observations and persist sanitized campaign results.
**Architecture:** Existing pinned transport collects bounded responses. ZAP imports HAR with sendRequests=false in Docker network=none. No TLS interception proxy is needed for passive import.
**Tech Stack:** Python 3.12 unittest, CORE/SQLite, Docker Linux, ZAP 2.17.0 pinned to sha256:030d3df57735dacbb83464854758e674dd9ad01d79d12a129a8e58b1fd384238.
**Spec:** docs/superpowers/specs/2026-10-30-zap-passive-design.md

## Global Constraints
GitHub-only; no local clone/install/run. Preserve branches/contracts. No active scans, crawling, credentials or real targets. Eight GET paths, 0.25s interval, max1MiB body, shared300s budget limited by CORE. No implicit docker pull. Alerts suspected; full_pentest_completed=false.

## Review Focus
Incomplete/encoded bodies imply partial coverage. Raw scanner errors/cookies/body never reach results. Containers require cleanup independently of client process. Queue completion must follow successful import and message count. Receipt binds inputs/parameters/engine identity.

## Task 1 — contracts and RED
Files: tests/test_passive_zap.py; .github/workflows/zap-passive.yml.
- [ ] Add cookie metadata, strict alert projection, containment, campaign grant/unavailable and real TLS/ZAP/CORE tests.
- [ ] Commit before implementation; observe adapter-missing RED in GitHub.

## Task 2 — controlled transport and offline scanner
Files: src/cyber_core/web_probe.py; src/cyber_core/pentest/passive.py, passive_child.py, zap_driver.py.
- [ ] Add trusted internal response callback, preserving default probe output.
- [ ] Implement cookie_metadata(headers), sanitize_alerts(alerts,grant), container_command(docker,name,folder,driver,seconds).
- [ ] Implement shared-deadline acquisition/scanning, backend preflight; network=none, read-only, no caps, CPU1, memory1GiB,128PIDs,bounded tmpfs.
- [ ] Driver imports HAR without sendRequests, verifies message count and queue, records version/add-ons, projects alerts before stdout.
- [ ] Parent checks lifecycle/hashes during work and publication, removes named container on exit; in-container deadline watchdog.
- [ ] HAR/session temporary; bounded scratch; document abrupt termination orphan risk.
- [ ] Observe focused GREEN and complete regression.

## Task 3 — campaigns and CLI
Files: campaigns.py; cli/operations.py; docs/zap-passive.md.
- [ ] dast_passive requires grant, runs adapter and recognizes receipt; unavailable stays unsupported.
- [ ] Add web-passive CLI with grant/CA/body/time.
- [ ] Real ZAP fixture vulnerable/corrected, receipt adoption/no-repeat, pause publication, input mutation/redaction; Windows regressions.
- [ ] Add RED regressions for review findings before fixes.
- [ ] Document exact head CI, limits and remaining capabilities.

## Execution ledger
Ruling: offline HAR replaces interception gateway for passive increment — scanner has zero egress and existing transport enforces scope — HAR normalization/partial coverage remains explicit.
Ruling: isolated remote Codex branch — AGENTS mandates GitHub-only — validation only runners.
