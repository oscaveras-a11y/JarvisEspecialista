# Durable Codex / Claude review broker

The broker implements separate persistent primary-review and cross-review jobs.
CORE retains technical tool execution. Agents receive verified, allowlisted
derived metadata and return proposals. A proposal never changes scientific
acceptance, scope, authorization or investigation outcome automatically.

## Integration contract

This change adds broker modules and adapters without editing existing
service.Core, memory, CLI or orchestrator.review_summary entrypoints. The
coordinating integration must connect the CLI before claiming an end-user flow.

Import Broker from cyber_core.orchestrator.broker and construct Broker(core).
Public operations:
- enqueue(case, agent='codex', allow_cloud=False, depends_on=None) returns job ID.
- run_one(case, job_id=None) runs one pending job and returns its durable record;
  None means no pending claim, not a completed provider call.
- get(case, job_id) and jobs(case) read saved jobs, including normalized response.
- retry(case, job_id, allow_cloud=True, reason=..., acknowledge_uncertain=False)
  records an explicit retry decision. Unknown outcomes require the acknowledgment.

For a cross-review, complete a Codex primary job, then enqueue a Claude job with
depends_on set to that primary ID. The reviewer must be a different agent and
the evidence snapshot must still match. Single-agent primary review works
without Claude. The cross-review includes the primary proposal as untrusted
data, bound to its audited response digest.

## Persistence and integrity

Tables agent_broker_meta (own schema version 1) and agent_jobs are additive.
They do not alter PRAGMA user_version, existing tables, evidence, or audits.
Job creation, claims, reservations, recovery, retry and completion append
checkpoints and hash-linked audit events.

Each job binds its approved summary to verified evidence-result digests and
optional primary response digest. Files are reverified before sending and
before publication; stored result digests are checked during execution.
Unknown jobs, changed evidence, changed dependencies, expired authorizations,
revocation, pause, cancellation and stale claim tokens cannot publish a result.

Primary and cross-review jobs are separate rows. Duplicate requests for the
same agent, evidence snapshot and dependency reuse the existing job, avoiding
silent duplicate provider calls. A changed observation requires a new job.

Jobs expose pending, running, done, awaiting_resources, uncertain, stale,
cancelled, paused and blocked states. A sent job with an expired lease becomes
uncertain; an expired unsent claim becomes pending. The broker never
automatically retries a sent job. A crash after reservation may mean zero or
one provider call; it cannot prove exactly-once delivery or absence of billing.

The shared investigations.agent_calls counter is reserved transactionally
before sending, including failed attempts. Default per-case limit is the
Core setting when present, otherwise five; an explicit broker call_limit can
tighten it. Per-job attempts are bounded separately. Timeout, bounded input
and bounded combined stdout/stderr constrain local execution. These are not
a financial cost cap or a guarantee of immediate upstream cancellation.

## CLI adapter configuration

Configure absolute executable paths with CYBER_CODEX_EXECUTABLE and
CYBER_CLAUDE_EXECUTABLE, or use PATH discovery. Shell script extensions and
Windows npm .cmd shims are rejected. Use compatible executables; discovery
does not establish authentication, provider access or successful integration.

Codex uses ephemeral exec JSONL and a read-only sandbox, ignores user config
and policy rules, disables shell execution, hooks, multi-agent tools and web
search for this review. Project document size is zero. Claude uses print JSON,
bare mode, no built-in/MCP tools, no slash commands, no Chrome, no persisted
session and one turn. Both validate structured completion and bounded review
text. A trusted stdin-gated launcher is contained before starting the CLI;
the existing CORE process-tree containment handles descendants.

Only each adapter's provider-auth variables and required runtime environment
are passed to its child. GitHub tokens and the other provider's auth variables
are excluded. Arbitrary stderr and provider error payloads are not saved in
the database or printed. Missing executables/authentication/quota/connectivity
are resource dependencies, not successful reviews.

These controls reduce the adapter surface. They do not turn model instructions
into an OS security boundary or establish professional correctness. Managed
provider policy and installed CLI versions can impose further restrictions.

## Optional real synthetic smoke test

The workflow Agent broker manual provider smoke is workflow_dispatch only.
confirm_live defaults to false. It has no pull_request or push trigger.
No real smoke workflow was dispatched during development of this PR.

The owner supplies repository secrets CYBER_CODEX_API_KEY and/or
CYBER_ANTHROPIC_API_KEY through GitHub settings. The workflow passes them only
to the disposable runner; this PR creates no secret or account credential.
Missing required credentials yield awaiting_resources, live_integration=false
and exit 2 before any provider call. The both option requires both credentials
before sending either job.

The workflow installs selected CLIs on its disposable Ubuntu runner and records
their resolved versions. Exact version inputs are recommended for repeatable
runs; latest is an explicit convenience, not an immutable dependency pin.
Only a fixed synthetic binary is analyzed; evidence bytes, filenames, paths,
objective and authorization text are excluded from the outgoing summary.
Logs show per-agent status, call-attempt indicator and reported usage, not
raw provider responses or credentials. No database, credential or evidence
artifact is uploaded.

Authentication for these subprocesses is separate from this development chat.
Provider credentials are required for a live provider call; the beta introduces
no application login. Operator/reviewer identity remains declared.

## Validation boundaries

Offline fixtures exercise strict CLI response handling; synthetic Python
subprocesses exercise timeout, cancellation and output limits. Durable broker
tests use real SQLite and verified synthetic evidence, replacing only provider
calls with controlled adapters. They test CORE behavior, not provider access.

A real Codex response, a real Claude response and two-agent cross-review each
need their own successful manually authorized smoke run. None is implied by
offline suite success. Neither kind of test establishes forensic competence,
hardware integration, legal authority or a resolved real case.

Official references checked 2026-10-17:
- https://learn.chatgpt.com/docs/developer-commands?surface=cli
- https://learn.chatgpt.com/docs/config-file/config-reference
- https://learn.chatgpt.com/docs/non-interactive-mode
- https://code.claude.com/docs/en/cli-reference
