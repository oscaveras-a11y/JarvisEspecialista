# Web and crypto readiness implementation plan
> **For agentic workers:** Use superpowers:executing-plans per independent front, TDD and one whole-front review; independent branches may use superpowers:dispatching-parallel-agents.
**Goal:** Implement both fronts of the approved readiness design with usable CORE/CLI and reproducible GitHub-only evidence.
**Architecture:** Reuse the Codex stack and preserve the exact current main PDF fix. Crypto analysis is a separate supervised static adapter. Active ZAP remains network=none and uses a loopback HTTP relay over one mounted AF_UNIX socket to a host gateway that enforces scope and verifies upstream HTTPS; session material remains with the gateway, not in scanner argv.
**Tech Stack:** Python3.12/unittest/SQLite, existing Ghidra/Capstone integrations, pinned ZAP2.17.0 Docker image.
**Spec:** docs/superpowers/specs/2026-10-31-web-and-crypto-readiness-design.md

## Global constraints
GitHub-only authoring/execution; no local clone/install/product run. No real site operations, credentials or private evidence in CI. Preserve other-agent branches. No main merge or deploy. Eight active paths,128requests,1concurrent,0.5s interval,300s maximum,1MiB bodies,128KiB result,128alerts; CPU1,1GiB,128PIDs,tmpfs512MiB. Crypto max1GiB subject CORE,256findings,256KiB output,300s subject CORE.

## Review focus
1. Scope canonicalization: encoded traversal/query keys/redirects/Host/CONNECT cannot bypass exact routes.
2. Container has no direct network; socket relay cannot become arbitrary TCP/HTTP tunnel.
3. Secret/session material never enters argv/SQLite results/audit/stdout; sessions cannot cross profiles.
4. Active interruptions cannot silently replay effects; published receipt adoption must preserve exact inputs.
5. Binary constants/strings/imports/addresses remain distinct evidence, including malformed/partial/mapped formats and compression.

## Task0 — integration baseline
Files: formats.py from exact main plus this plan.
- [ ] Compare de2fe89..main: confirm only formats.py changed.
- [ ] Preserve that exact file on isolated Codex integration branch, with main as second parent.
- [ ] Regression on Windows/Linux before claiming combined base verified.
Produces: immutable integration SHA for independent workers.

## TaskB — crypto identification
Files: reverse_engineering/crypto_* modules, trusted Ghidra exporter, tests/test_crypto_inspect.py, .github/workflows/crypto-inspect.yml; CLI operations.py.
- [ ] Write detailed per-front plan and RED tests on own remote branch before source.
- [ ] Implement crypto-inspect CLI and run_crypto_inspect(core,case,path,...) producing audited operation crypto_inspect.
- [ ] PE/ELF imports/symbols, fixed full constants, weak strings, Capstone optional instructions and Ghidra static references; BIN/HEX/S-record coverage/mapping explicit.
- [ ] Streaming/mmap budgets, negative/compressed/malformed fixtures and source/offset integrity; real compiled fixture/Ghidra in CI, complete Windows/Linux suite.
Produces: isolated branch/PR, exact changed files and RED/GREEN evidence; parent integrates preserving shared CLI/campaign contracts.

## TaskA1 — active grant and gateway
Files: pentest/active_gateway.py, tests/test_active_gateway.py, .github/workflows/web-active.yml.
Interface: validate_active_grant(dict)->normalized dict; ActiveGateway(grant,ca_pem=None,request_headers=None,control=None,seconds=...) context manager with socket_path, endpoint metadata, redacted observations, counters.
Grant v1: origin HTTPS; routes list of {path,methods,query_params,body_params}; classes list drawn from reflected_xss/sql_injection; allow_active:true; authorization; expires_at. Optional session-only login/check routes require explicit purpose; no wildcards. Query values may vary; key names and route/method remain fixed. Body accepted only declared form/JSON fields within budgets. No redirects/upstream proxy.
- [ ] RED: parse/scope checks, malicious request framing, real synthetic TLS over Unix HTTP, cookies/raw values absent from metadata, shared budgets and interruption.
- [ ] Gateway binds private AF_UNIX endpoint, accepts only bounded origin-form HTTP, serializes forwarding, pins public DNS and validates TLS. Input auth headers are ignored/rejected; trusted request_headers supplies per-profile headers.
- [ ] Count every attempt before upstream; reject expiry/revocation/mutation via control callback before each transmission. No arbitrary host/CONNECT/network destination.
Produces gateway module/tests only on separate branch; no CLI/campaign edits; use file-based output payload for integration via root.

## TaskA2 — ZAP active driver and CORE
Files: pentest/active.py, active_driver.py, active_relay.py, tests/test_web_active.py; campaigns.py and CLI after crypto integration.
Interface: run_active(core,case,manifest,*,ca_file=None,receipt=None,control_check=None,...)->operation dast_active.
- [ ] RED: real ZAP driver flags/rules, gateway/relay/network proofs and vulnerable/corrected fixtures.
- [ ] Container network=none, pinned image, explicit heap512MiB. Loopback listener sends only HTTP over mounted gateway socket. Virtual HTTP scanner origin is never called upstream TLS identity.
- [ ] Disable all active rules then enable supported non-temporal40012/40018 behavior verified from source. Set budget/thread/parameter controls; only granted inputs initialized. No spider/callbacks/scripts.
- [ ] Sanitize query/body values from findings; preserve rule/risk/confidence/path/opaque parameter reference and reproduction classification. Results partial on budget/queue/unsupported cases.
- [ ] Freeze manifests/CA/tool identity, lifecycle control, cleanup/watchdog, active receipt and uncertain-effect state; no automatic replay of interrupted unpublished active stage.
- [ ] Complete real Linux fixture + full Windows/Linux regressions.

## TaskA3 — sessions and access
Files: pentest/web_sessions.py, tests/test_web_sessions.py; gateway/active integration shared by root.
Interface: SessionBroker(grant,material_path,...), isolated_profile(name), login/check, get_headers().
- [ ] RED: bearer/cookie/form/JSON login, session expiry, A/B resource policy matrix and secret redaction.
- [ ] Secret material read from bounded operator local file outside serialized manifests/argv/results; hashes only in memory for mutation control. No _acquire copy of credentials.
- [ ] Same-origin bounded cookie jars; no target-supplied origin expansion; valid session checker required. Unsupported MFA/OAuth reported, not bypassed.
- [ ] Gateway injects only current profile auth; scanner cannot replace credentials. Active stage owns one profile; access matrix compares explicit operator policy, never HTTP200 alone.
- [ ] Test failure/expiry/reopen and effect uncertainty; full regressions.

## TaskA4 — retest and delivery
Files: CLI/campaign/report wiring, docs/web-active.md, docs/crypto-inspect.md and evidence ledger.
- [ ] Preserve historical findings, retest corrected fixture, display partial/unavailable accurately.
- [ ] Review exact combined immutable branch; fix Important/Critical with RED/GREEN, then full suite.
- [ ] Draft PRs and results with limitations; no main integration or real-target operation.
- [ ] Do not mark whole request complete while either approved front remains pending.

## Execution ledger
Ruling: execute the user-approved sequence without another plan approval — user approved the design explicitly and repo permits routine implementation/testing — no merge/deploy authority inferred.
Ruling: use AF_UNIX relay with scanner network=none instead of a general TLS interception proxy — only two active input classes need mutation forwarding and upstream remains pinned HTTPS — virtual origin differs, so origin/TLS-specific active checks are not claimed; passive HTTPS remains available.
