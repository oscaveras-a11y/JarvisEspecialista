# Active gateway A1 plan and execution ledger

Base: 3061d191ce432b369a60be6c05cf89bf2ba2fd7b. GitHub-only; no product execution locally.

Plan: (1) tests and Actions RED before source; (2) strict active grant parser and bounded private AF_UNIX HTTP gateway; (3) real synthetic TLS fixture and full Windows/Linux regression; (4) review and draft PR, no merge.

Interface: validate_active_grant(dict), parse_active_grant(bytes), ActiveGateway(grant,ca_pem=None,request_headers=None,control=None,seconds=300,max_requests=128,body_bytes=1048576,socket_dir=None). request_headers is trusted dict or callable(method,path). control is thread-safe, called before sends and during waits; true means stop. socket_path is absolute. snapshot() returns redacted observations and numeric counters. Optional route purpose defaults scan; login/check/access are explicit non-scan purposes.

Ruling: per-front ledger lives in this deliverable rather than a local checkout because AGENTS requires GitHub-only authoring. The scanner sees a virtual HTTP origin; upstream remains exact pinned HTTPS. Never claim target TLS/origin-specific scanner coverage.

Ledger: plan recorded; RED pending.
