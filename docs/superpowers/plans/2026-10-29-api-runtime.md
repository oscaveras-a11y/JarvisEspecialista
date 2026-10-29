# API runtime lab plan

Execution: inline; GitHub API branch isolation, per AGENTS.md. No local product execution.

Goal: compare bounded GET responses with a documented OpenAPI subset and independently specified synthetic bearer access expectations; preserve durable campaigns.

Architecture: api_runtime.py owns validation, comparison and run_api; api_runtime_child.py executes exclusively against jarvis-api.test on 127.0.0.1 with verified TLS. Campaign api stage uses frozen spec/grant/matrix/CA hashes and existing audited receipts. Existing inventory and Claude branches remain unchanged.

Constraints: only synthetic profiles anonymous, invalid, alice, bob; no credential inputs; GET only, no redirects, explicit grant paths; full_pentest_completed=false. Authentication here means synthetic bearer enforcement, not login/OAuth/session testing. Separate authentication and authorization campaign engines remain unavailable.

Review focus: incomplete bodies, unsupported schema keywords, malformed schemas, HTTP 200 false positives, cancellation/ownership before publication.

- [x] Task 1: commit tests/test_api_runtime.py and workflow; observe RED in GitHub Actions.
- [x] Task 2: implement compare_response, validate_matrix, lab TLS worker and run_api; assert body hashes, no bodies/tokens persisted, positive controls for access failure confirmation.
- [x] Task 3: integrate api_matrix frozen input and api execution/receipt in campaigns.py; real Core campaign, storage failure/reopen/adopt, mutation, pause and cancellation checks.
- [x] Task 4: docs/api-runtime.md exact subset and limits; focused and full Linux/Windows regression; record immutable head/run links.

Verification: python scripts/run-tests.py test_api_runtime.py; python scripts/run-tests.py. Real TLS test on Linux with ephemeral self-signed fixture CA; no real sites.

Ruling: AGENTS.md explicitly authorizes implementations and synthetic tests without approval for each change; owner requests continued implementation. Local worktree/ledger scripts replaced by remote branch and this committed plan to comply with GitHub-only restriction.

Progress: implementation and documentation delivered; initial full-suite GREEN Linux/Windows at 494c891. Independent review reproduced and corrected response depth/node/numeric limits, wrapper injection and decimal rounding with RED tests. Final immutable-head verification and exact run links are maintained in PR #34. Synthetic API TLS cancellation and durable receipt recovery execute in the Linux integration test.
