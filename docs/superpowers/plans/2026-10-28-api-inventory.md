# OpenAPI inventory implementation plan

Goal: inventory supplied OpenAPI JSON and intersect declared endpoints with the existing read grant.
Architecture: bounded offline parser, audited CORE adapter, CLI and separate api_inventory campaign stage.
Tech stack: existing Python standard library; no network, target execution or new dependency.
Spec: docs/superpowers/specs/2026-10-28-pentest-platform-design.md (incremental API preparation).

Constraints: GitHub-only synthetic tests; own branch; no raw examples, credentials or descriptions in output.
Supported subset: OpenAPI 3.0.x/3.1.x JSON; local path-item references only, bounded depth. Unknown formats/refs/servers/security return explicit partial/unsupported.
Servers follow operation > path > document precedence; only a single exact server with a bounded static base path can authorize mapping, and the grant remains independent.
No template expansion, method execution or authentication verdict. GET eligibility means a candidate for the existing read probe only.

Review focus: reference cycles/external fetch, server overrides/variables, security inheritance/anonymous alternatives, JSON depth and output growth, lifecycle/receipt integrity.

- [x] Write parser, CLI and campaign tests; observe RED on GitHub.
- [x] Implement analyze(raw,grant,**limits), run_inventory(core,case,path,grant_path,...), CLI and campaign receipt.
- [ ] Run focused and whole regression suite on Linux and Windows, including existing real synthetic HTTPS integration.
- [ ] Fresh read-only review, fix important findings with RED/GREEN, publish draft PR with evidence.

Ruling: use an isolated remote branch rather than local worktree because AGENTS.md mandates GitHub-only development/testing.
Ruling: api_inventory is separate from api; documenting routes cannot claim runtime API testing.

RED: workflow 40777653975, eight expected missing-adapter failures. First implementation CI40777823043 exposed missing CLI dispatch; corrected in205ce61.
Review: fresh read-only reviewer found no Important/Critical bugs. Minor deferred: control-character URL normalization, documented in docs/api-inventory.md. No requests or grant expansion.
