# Persistent agent broker implementation plan

Authorized execution: GitHub APIs and disposable Actions runners only. Starting
commit: 4ca8b44b5250c760302137e3033ddcc7f571214c. Dedicated branch
codex/agents-broker. No product checkout, installation or tests on the owner's PC.

1. Publish offline contracts first and observe their failure in Actions.
2. Add a namespaced additive SQLite store without changing core user_version.
3. Add persistent primary/cross-review jobs with explicit summary-transfer
   authorization, sanitized verified observations, digest/dependency binding,
   reservations, claim tokens and leases. Unknown outcomes after sending require
   an explicit operator decision before another potentially billable call.
4. Implement both CLI adapters, strict framing and bounded cancellation-aware
   subprocess handling. No automatic provider call in normal CI.
5. Run the contracts and complete offline suite on Windows/Linux disposable
   runners, fix regressions, and report exactly what ran.
6. Provide a separate workflow_dispatch-only synthetic provider smoke workflow,
   opt-in disabled by default. Do not dispatch it in this task.

Tool execution stays in CORE. The broker only proposes reviews. Claude remains
optional. Declared operator/reviewer identity remains declared; no beta login is
introduced. Existing service, memory, CLI and orchestrator entrypoints are left
for the coordinating agent to integrate.

Official references consulted on 2026-10-17:
- https://learn.chatgpt.com/docs/developer-commands?surface=cli
- https://code.claude.com/docs/en/cli-reference

Offline parser fixtures are not real provider validation.
