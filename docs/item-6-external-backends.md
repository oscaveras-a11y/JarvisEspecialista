# Item 6: optional real external backend adapters

This increment provides analyze_external(verified_path, metadata, config, timeout).
The initial adapter increment was standalone. The current [CORE integration](real-tools-core.md)
connects explicit host configuration to verified acquisition, monitored execution,
SQLite publication and reports.
The caller supplies an already verified absolute file and metadata containing
format=elf or format=pe for Ghidra. Without config no external tool is started.

Configuration is trusted host policy, never evidence or an agent command:
- ghidra: home and java_home, both absolute paths.
- binwalk: executable, an absolute path.
Unknown fields (including free-form arguments) are rejected. Linux is the first
supported execution platform; other platforms return unsupported_platform.
Missing installations are dependency_unavailable. Unsupported Ghidra inputs
are unsupported_format. completed requires valid bounded backend output.
Ghidra can report partial or no_functions; failures remain explicit.

## Real execution and provenance

Ghidra 12.1.4 ZIP ghidra_12.1.4_PUBLIC_20260921.zip SHA256:
ddac49f903da9d5bac833e5cc79395098b9c33cfd3279be5f31bd00387d2d4db.
Uses JDK 21 and a packaged, trusted ExportPreview.java HeadlessScript.
Imports ELF/PE with library loading and relocations disabled, readOnly,
one analysis CPU, 1 GiB Java heap, and at most 30 seconds of auto-analysis.
The script detects auto-analysis timeout, exports up to eight functions with
three seconds per decompilation and 8192 characters per function.
Pseudocode is an interpretation, not recovered original source.

Binwalk 3.1.0 published crate SHA256:
99d5dc70f5021c55624f098adae4d1de9c1c07d000475664704b675aad7e0811.
Runner compiles with Rust 1.85.1 and the published lockfile.
Runs quiet, one thread, JSON to a fresh file, without extraction or recursion.
Validates input path and every finding range; zero size means unknown.
Up to 128 findings are presented, with total count and truncation.
Some signature validators internally decompress data, even with extraction off.

Both results bind to input SHA256 and byte count, version, limits and
limitations. The sample is never launched. The installation/download step is
online; analysis does not call providers or require agent credentials.

## Supervision and limits

Call only inside a monitored process tree. Backend processes inherit the
caller's group/job; they do not detach. The outer supervisor MUST terminate
and confirm descendants on worker completion, failure or cancellation.
The adapter kills/reaps the immediate tool on a local error. It intentionally
does not claim independent full-tree containment. The real acceptance script
supplies POSIX process-group supervision around each worker.

A shared monotonic deadline covers hashing, launches and both backends.
Inputs are capped at 64 MiB. Stdio is capped at 256 KiB, JSON at 2 MiB.
Linux launcher imposes a hard 16 MiB per-file write limit and finite CPU time.
Scratch aggregate 64 MiB and 2048 entries are polled while the backend runs;
these aggregate limits are monitored, not a filesystem quota: a process can
temporarily overshoot between polls. Projects, cache and logs use a private
temporary tree cleaned on normal/error return. Forced outer termination can
leave a temp directory until runner disposal. There is no privilege/network
sandbox and no total native-memory limit; Java heap is not total process RAM.
No untrusted extractions are materialized.

## Acceptance evidence

TDD commit a9d339896e3339e135a5f52f463813017cb4c0c3, GitHub run
[39040792334](https://github.com/oscaveras-a11y/JarvisEspecialista/actions/runs/39040792334):
package installed, then 12 expected errors demonstrated the missing adapter.
No positive backend result is claimed by that run.

The external-backends workflow installs checksum-verified real tools on a
disposable Linux runner. It builds but never executes a synthetic ELF returning
42, requires real Ghidra decompilation, and requires real Binwalk identification
of synthetic gzip at offset 256. Neither backend check can pass by skipping.
Unit dummies cover failure behavior only; they are not real integration proof.
Current positive runs must be inspected per commit. The current acceptance script additionally requires CORE-to-SQLite/report
integration and the actual Binwalk CLI route; see [current contract](real-tools-core.md).

## Primary references

- [Ghidra release and digest](https://github.com/NationalSecurityAgency/ghidra/releases/tag/Ghidra_12.1.4_build)
- [Pinned headless contract](https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.4_build/Ghidra/RuntimeScripts/Common/support/analyzeHeadlessREADME.md)
- [Binwalk pinned CLI](https://github.com/ReFirmLabs/binwalk/blob/v3.1.0/src/cliparser.rs)
- [Published crate checksum index](https://github.com/rust-lang/crates.io-index/blob/master/bi/nw/binwalk)

Regression run [39041223831](https://github.com/oscaveras-a11y/JarvisEspecialista/actions/runs/39041223831)
ran 15 contracts: 12 passed, two assertions failed and the JSON reader fake
exposed the old unbounded read_bytes path. The corrected reader uses
read(MAX_JSON+1), including when stat becomes stale, and normalized schemas
drop unrecognized fields and reject non-integer confidence values.

The first real run [39041000349](https://github.com/oscaveras-a11y/JarvisEspecialista/actions/runs/39041000349)
installed verified tools and confirmed Java packaging, then failed because
the exporter produced no JSON. The actual HeadlessScript 12.1.4 API is
analysisTimeoutOccurred(), despite the README's stale method reference.
The Java exporter now uses the class API. This failed run is not a passing
Ghidra or Binwalk analysis receipt.
