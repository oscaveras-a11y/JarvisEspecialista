# Active gateway A1 plan and execution ledger

Base: 3061d191ce432b369a60be6c05cf89bf2ba2fd7b. GitHub-only; no product execution locally.

Plan: (1) tests and Actions RED before source; (2) strict active grant parser and bounded private AF_UNIX HTTP gateway; (3) real synthetic TLS fixture and full Windows/Linux regression; (4) review and draft PR, no merge.

Interface: validate_active_grant(dict), parse_active_grant(bytes), ActiveGateway(grant,ca_pem=None,request_headers=None,control=None,seconds=300,max_requests=128,body_bytes=1048576,socket_dir=None). request_headers is trusted dict or callable(method,path). control is thread-safe, called before sends and during waits; true means stop. socket_path is absolute. snapshot() returns redacted observations and numeric counters. Optional route purpose defaults scan; login/check/access are explicit non-scan purposes.

Ruling: per-front ledger lives in this deliverable rather than a local checkout because AGENTS requires GitHub-only authoring. The scanner sees a virtual HTTP origin; upstream remains exact pinned HTTPS. Never claim target TLS/origin-specific scanner coverage.

Ledger: plan recorded; RED pending.

RED observed: tests-only aa2daad71c4b12d73e3acf9fe6183a5ac8898e62, Actions run 41259328920, Ubuntu job124709117961. Four contract tests failed because cyber_core.pentest.active_gateway did not exist; dependency install and synthetic fixture route passed. Windows duplicate canceled. Source introduced afterwards at bee35f9aefbf9cb38fd5b207e7a235a6cc340aa9.

Private transport: perform(method,path,headers=None,body=b'',purpose=None) returns transient {status,headers,body}. This host-only API bypasses scanner provider and uses the same reentrant serialization, scope, TLS, budget and control engine. Unix scanner traffic can reach only purpose=scan. Provider(method,path) may call a session checker through perform; each check consumes the shared budget. All raw response headers/body must stay ephemeral.

The relay must replace its virtual HTTP origin Host with the exact grant HTTPS authority. Gateway never uses scanner Host to choose a destination. All other authority values are rejected. No CONNECT, absolute targets, redirects, wildcard/encoded paths or undeclared keys. Scanner Authorization/Cookie are discarded; trusted profile provider supplies them.

Self-review: added hanging-DNS cancellation test at e2cb1acf04ce04ee531a1539fb9de127af1086e9 before correcting synchronous resolution. RED pending in Actions queue. No readiness claim until GREEN and review.
