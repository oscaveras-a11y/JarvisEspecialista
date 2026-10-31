# Scientific investigation workflow

The CLI now stores registered hypotheses, revision history, experiment plans, runs, references, declared independent reviews and verification snapshots in SQLite schema 3. Older schemas are upgraded additively.

## Evidence and claims

Automatic entropy suggestions remain provisional suggestions. Registered hypotheses are separately identified and tested. Plausibility is a finite value from 0 to 1, not a calibrated probability. A revision invalidates applicability of earlier reviews.

An experiment declares a criterion, an allowlisted tool and 1 to 20 scalar dictionary-field comparisons in a JSON criteria file inside the authorized scope. Operators are eq, ne, gt, gte, lt and lte; there is no eval, shell or executable expression. A completed, audited analysis result from the same case must be supplied. The verified copy is hashed again, including both copies for comparisons. Old acquisitions without a complete audited result digest must be acquired again before entering this workflow.

Every run stores the evidence digest, hypothesis revision, comparisons, outcome and operator. Missing or incompatible observations are inconclusive, not refutations. A failed applicable comparison refutes the prediction. Identical semantic observations are rejected as repeated progress even when acquired to new filenames. Each plan permits at most three runs by default (configurable from 1 to 10); repeated plans with identical conditions reuse the existing plan.

Review requires a declared reviewer distinct from the hypothesis author, plan author and run operator. Each current-revision run must be reviewed or explicitly rejected. Reviews recheck evidence and cannot reuse a stale revision. Supported and refuted accepted runs cause a conflict. New unreviewed runs reopen the claim.

## CLI example

Create a case using investigate, analyze a known control, and retain its task_id. Register a hypothesis:

```powershell
cyber hypothesis add CASE --statement 'Control contains three bytes' --author analyst
```

Create a JSON file in scope containing:

```json
[{"field":"size","op":"eq","value":3},{"field":"copy_verified","op":"eq","value":true}]
```

Then execute:

```powershell
cyber experiment plan CASE HYPOTHESIS --name 'Known size' --criterion 'Both conditions match' --author analyst --tool analyze-file --assertions-file 'C:\Lab\checks.json'
cyber experiment evaluate CASE EXPERIMENT --task TASK --operator analyst
cyber experiment review CASE RUN --reviewer reviewer --decision accepted --reason 'Recomputed size and verified hash'
cyber verify CASE --state RESOLVIDO --actor owner --reason 'Registered control criterion demonstrated'
cyber hypothesis list CASE
cyber experiment list CASE
cyber history --query control --project laboratory
```

## State gates

RESOLVIDO requires no pending/failed tasks, no open/conflicting registered hypotheses, accepted independent reviews for each plan and current run, fresh artifact integrity, reproduced comparisons, and a supported criterion. New tasks or scientific records reopen terminal cases.

SEM SOLUCAO VIAVEL DEMONSTRADA requires at least two reviewed strategies and cannot contradict supported solution conditions. It describes the registered investigation, never a universal impossibility claim. AGUARDANDO RECURSOS records a specific impediment without claiming validation. A final snapshot is compared again under a SQLite writer lock before the state change, so newly queued work invalidates stale verification.

All 7 states from the scope (item 13) are accepted by `finalize`: RESOLVIDO, EM INVESTIGACAO, AGUARDANDO INFORMACOES, AGUARDANDO AUTORIZACAO, AGUARDANDO RECURSOS, SEM SOLUCAO VIAVEL DEMONSTRADA and FALHA DE EXECUCAO. FALHA DE EXECUCAO declares an operational execution failure (not a scientific conclusion) and, like RESOLVIDO/SEM SOLUCAO VIAVEL DEMONSTRADA, is cleared back to EM INVESTIGACAO when new work is queued — unlike the AGUARDANDO states, which stay put until the operator explicitly resumes them. It does not go through the evidence/review gates those two scientific terminal states require, and `validated` stays false.

The unit tests demonstrate a known control, not a universal solution to a client problem. Criteria quality and relevance to the business objective still require a competent independent reviewer.

## Trust limits

Reviewer names and operator names are local declarations, not authenticated multiuser identities or cryptographic attestations. The engine verifies reproducible data comparisons and records declared review; it cannot prove that a named human actually acted independently. Hash-linked events are not digital signatures. Protect each client storage using OS access controls; multiuser authentication and signed external custody remain separate requirements before commercial deployment.

The research command registers metadata for an operator-consulted HTTPS reference, its version and provenance (documented, inference or experimental). It does not fetch or independently validate the document. The recorded timestamp is registration time. Source contents are never treated as agent instructions. Automatic documented-source retrieval is still pending.

Failed tasks currently block terminal verification and remain visible; an audited operator disposition/retry workflow is still required for investigations that intentionally abandon a failing tool. Provider authentication, worktree orchestration and production worker validation remain separate pending deliverables.
