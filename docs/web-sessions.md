# Host session broker
Status: A3 broker implementation; active CORE/CLI/gateway wiring is a separate integration.
Development and validation use synthetic local fixtures on GitHub runners only.

## Trusted host API
`SessionBroker(grant, material_path, *, transport, control=None, clock=time.time)`
reads the operator file directly (regular file, at most 16 KiB). Never use CORE
`_acquire` for that file, put its contents/digest in manifests/results/audit,
or send it to worker stdin, argv, stdout, scanner storage or a container.
The file must be an operator-authorized protected input outside the case's
evidence/result tree. The caller authorizes that location and keeps OS access
restricted. Python memory is not a secure enclave and is not guaranteed zeroized.
Only a random-key HMAC mutation fingerprint is held in host memory; no offline
guessable credential digest is exported.

`isolated_profile(name)` returns a fresh independent jar and lifecycle.
Call `login()` before a stage; `check()` verifies the declared session marker.
`get_headers(path='/', method='GET')` checks scope and the current session,
then supplies only `Authorization` and/or `Cookie`. After any login/check
failure that profile is permanently blocked; create a new isolated profile only
as an explicit new attempt. Never automatically replay a failed login or a
stage with unknown effects. Anonymous profiles do not claim authentication.

The trusted `transport(method, path, headers, body)` returns
`{'status': int, 'headers': [(name,value),...], 'body': bytes, 'complete': True}`.
`complete` defaults to true for transports which always return complete bodies.
All response bodies/headers remain private. Response limit is 1 MiB/64 KiB,
at most 128 headers. Redirects and incomplete responses are rejected.
The broker implements no network access: the injected host gateway must enforce
upstream HTTPS/TLS/DNS pinning, budgets, expiry, cancellation, request fields and
exact origin for EVERY login/check/access/scan request. Broker routes are copied
from the immutable grant, and each login/check/access route requires its matching
explicit `purpose`; a route without purpose is scan only.

The gateway's scanner header provider wrapper is:
`lambda method, path: profile.get_headers(path, method)`.
Scanner-supplied auth/cookies must be stripped by that gateway. Broker transport
requests use a separate trusted host entry point with explicit private headers,
so checker requests never recurse through the scanner provider. Every checker
counts toward the shared gateway budget. A stage must recheck after scanner
completion and publish authenticated coverage only if that final check succeeds.
Failure/expiry/cancellation reclassifies or blocks the stage. Scanner data must
never be persisted as evidence of authenticated coverage after session loss.
The control callable may return true or raise to stop. A gateway server thread
must use a thread-safe event instead of accessing CORE's SQLite connection.

## Protected JSON material v1
Top-level keys are exactly `version: 1` and `profiles` (1–8 distinct public,
non-secret names, matching letters/digits/underscore/hyphen, at most 32 chars).
Each profile is one of:
- `{"kind":"anonymous"}`
- `{"kind":"bearer","token":"OPERATOR_SECRET","check":CHECK}`
- `{"kind":"cookie","cookies":[COOKIE],"check":CHECK}`
- `{"kind":"form","login":{"path":"/login","fields":{"username":"OPERATOR_SECRET","password":"OPERATOR_SECRET"}},"check":CHECK}`
- `{"kind":"json","login":{"path":"/login","fields":{"username":"OPERATOR_SECRET","password":"OPERATOR_SECRET"}},"check":CHECK}`

CHECK is `{"path":"/session","status":200,"json_marker":{"field":"authenticated","value":true}}`,
or the same path/status with `"sha256":"64 lowercase hexadecimal characters"`
instead of json_marker. A marker is a top-level JSON scalar field; status alone
is insufficient. The hash is an operator-supplied expected response-body digest,
never a hash of credentials. Do not use responses containing credentials as
hash checkers. Duplicate keys/nonfinite JSON are rejected.

COOKIE is exactly `{"name":"sid","value":"OPERATOR_SECRET","path":"/","secure":true,"expires":EPOCH_SECONDS}`.
There are at most 16 cookies per profile. They are HTTPS host-only, sent only
for matching path boundaries, and removed/ignored on expiry. Login/check
Set-Cookie requires Secure and no Domain; Max-Age/Expires are honored with a
one-day Max-Age cap. A session cookie without expiry is limited to 300 seconds
of this isolated profile. Cross-origin and broad Domain cookies are rejected.
No target response can expand the granted origin.

Login POST is sent exactly once using explicitly configured form or JSON fields;
there is no credential guessing, script execution or automatic discovery.
MFA, CAPTCHA, arbitrary OAuth/OIDC, browser/JavaScript login, refresh-token flows,
bearer extraction from JSON login responses and flows needing hidden CSRF fields
are unsupported. An operator must choose a supported flow, not bypass those steps.

## Explicit access comparison
`broker.assess_access(case)` accepts exactly:
`{"path":"/resource","allowed":["alice"],"profiles":["alice","bob","anonymous"],"status":200,"json_marker":{"field":"resource","value":"operator-defined-resource"}}`.
The resource marker and policy are supplied by the operator. Profiles are fresh
and isolated. Each resource response is followed by a session check.
Results contain public profile names, levels and fixed reason codes only:
a resource observed for a disallowed profile is confirmed only after an allowed
profile positively matched the same explicit resource. HTTP200 alone is
inconclusive. HTTP401/403 can be reported as denied. Missing positive controls
or lost sessions remain alerts, not successful coverage or permission inference.
No raw response/body/token/cookie/checker value appears in comparison output.

## Verification and limits
The dedicated workflow runs focused broker tests using a real in-process HTTP
server and a trusted injected synthetic transport, plus the complete regression
suite on Linux and Windows. That fixture proves broker behavior, not TLS/egress
containment. Real synthetic HTTPS and ZAP gateway containment belong to the
combined active integration. No live site operation was performed.

## Execution ledger
Ruling: use an injected gateway transport rather than a second network adapter —
one enforcement point owns upstream TLS and all budgets; broker-only fixture
tests cannot prove network containment, which remains the combined front's gate.
Ruling: retain a keyed HMAC only in memory instead of a persisted input hash —
mutation detection remains available without an offline credential verifier.
Ruling: reject Domain/non-Secure cookies and unsupported interactive flows —
coverage is explicit and narrower than a full browser session engine.
Initial RED: f260c49b1bb10d1a0f74151f96bad72eb2f71f13, run 41259315591,
eight expected missing-capability assertion failures.
Secret-context RED: b27a9165688ae6378e6e9c46fd40cda382d3188e, run 41259475105,
raw exception context retained; fixed by 28e374a0f0e7bb52e55001017c80b1154811c766.
Missing-marker RED: 6feaaf1a94590dde2aa3ea79fb4c825e81df21ed, run 41259584261,
absent field matched null; fixed by requiring field presence.
