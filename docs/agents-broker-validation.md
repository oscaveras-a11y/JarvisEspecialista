# Agent broker validation receipt

Development used GitHub APIs and disposable GitHub-hosted runners only. No
product clone, dependency installation or tests ran on the owner's PC. Provider
credentials were not inspected or created. No real provider smoke was dispatched.

## First test-first cycle

Tests and offline workflow published before production implementation:
3e23a76dfa3c357958365d75892d56a1d1766fcc.
[Actions run 39041013672](https://github.com/oscaveras-a11y/JarvisEspecialista/actions/runs/39041013672),
Ubuntu job 117420360064: agent contracts failed as expected for the absent
persistent broker, Claude stub, strict parsing, cancellation and aggregate output
contracts. Complete suite: 218 tests, 21 failures and 10 errors attributable to
the new contracts, eight platform skips. No provider call occurred.

Initial implementation: 6ef62c5b98638b2f9e97732484a4b8a69a741bf6.
[Actions run 39041292008](https://github.com/oscaveras-a11y/JarvisEspecialista/actions/runs/39041292008),
Ubuntu job 117421156933: 35 agent tests in 2.292 s; complete suite 218 in
23.691 s, OK with eight platform skips; dependency and syntax checks passed.
Windows execution was superseded by the next test-first cycle; this Ubuntu
result does not claim a completed Windows result.

## Second test-first cycle

Additional test commit: 51a982903e58528117ae63221bf229d956096037.
[Actions run 39041435330](https://github.com/oscaveras-a11y/JarvisEspecialista/actions/runs/39041435330),
Ubuntu job 117421587659: two expected failures for the missing opt-in-only
synthetic probe and one expected malformed-usage error. Complete suite: 224
tests, failures=2, errors=1, skipped=8. Root cause of the malformed usage error:
an unvalidated list reached dictionary iteration; it is now classified as an
uncertain provider outcome, with no silent retry.

## Meaning of these tests

The broker tests use real SQLite, real synthetic evidence acquisition and
audit/copy verification. Controlled adapters replace external provider calls.
Parser tests use recorded-shape synthetic JSON fixtures. Process tests use
Python subprocesses. They validate contracts and local execution boundaries,
not successful authentication, paid model access or real provider communication.

The live-probe tests execute only the opt-out and missing-credentials branches.
Both must report live_call_attempted=false and live_integration=false.

The manual provider workflow and its CLI package installation are prepared but
not live-validated by this task. Successful Codex, Claude and two-agent live
cross-review remain pending their own explicitly requested real smoke results.

The existing CLI is not connected by this PR; the coordinating agent integrates
that entrypoint separately. No beta login or authenticated reviewer identity is
introduced. This PR never marks a scientific result solved from agent text.
