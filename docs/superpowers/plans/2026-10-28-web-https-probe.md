# HTTPS real-target protocol verification: design and plan

Purpose: prepare Jarvis to test explicitly authorized real HTTPS endpoints, preserving existing lab and firmware modules. This increment is protocol observation (section 10) and process/resource supervision (12/14), not a vulnerability exploitation engine (Claude section 9).

Approach: separate web-probe CLI using a local scoped, expiring manifest. Existing loopback write demonstration remains separate. Reject broad crawling/exploitation: no target authorization or requested action list supports those operations. Implementation uses GET only on up to eight explicit paths and never follows redirects.

Grant v1: version=1, origin=https origin only, paths=list of ASCII absolute paths without queries/encoded/dot traversal, allow_read=true, authorization=nonempty operator declaration, expires_at=timezone-aware future timestamp. It is a declaration, not proof of identity/ownership. Existing CORE authorization/pause/revoke/cancel and manifest digest remain mandatory.

Network: resolve inside supervised child; reject nonpublic, multicast and transition/private address forms, reject mixed DNS answers, pin a vetted address on each request, validate TLS against hostname and trusted roots, no proxies/redirects. Optional scoped CA file acquired and hashed, never disable TLS verification. No credentials/cookies sent. No content, cookie values or raw errors in output.

Budgets: up to 8 paths; per-response body hash prefix 1..1048576 bytes, default65536; total process time up to300s/default30, capped by CORE; 0.25s between requests; worker stdout bounded65536; manifest8192 bytes. Chunked body hashing, bounded headers, supervisor kills blocked DNS/TLS/read on timeout or cancellation. No in-flight cancellation guarantee below supervisor polling interval.

Results: TLS version, certificate SHA-256, public peer IP, status, selected security-header presence, body/prefix SHA-256 and completeness, sanitized failures. Missing headers are observations, not exploitable-vulnerability verdicts. Result/audit/report plus manifest/optional CA hashes and runtime versions. Interruption is audited; no per-request checkpoint/resume yet.

Validation: real TLS synthetic fixture bound to a public-looking address routed to runner loopback and a reserved .test hostname in /etc/hosts. Generated CA trusted only via the supplied scoped certificate. Production validation code is unchanged; no private-address bypass. Tests prove CLI→CORE→supervised worker→DNS validation→pinned TLS→HTTP→audited report, redirect refusal, prefix limits and rejection of an untrusted certificate. No external website/electoral target traffic.

Files: web_probe.py, web_probe_child.py; narrow CLI additions; tests/test_web_probe.py; workflow web-https-probe.yml; docs/web-probe.md.

- [ ] RED synthetic tests on GitHub.
- [ ] Implement protocol transport and integration; run targeted and full offline suite.
- [ ] Independent read-only review, fix important findings with regression tests; draft PR, no merge.

Review focus: DNS re-resolution/pinning, scope parser normalization, private destinations and redirects, slow-drip deadlines, authorization revocation/manifest mutation, leaked headers/body, incomplete result labeling.
