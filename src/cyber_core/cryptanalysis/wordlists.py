"""Bundled wordlist for authorized real password recovery.

Ships the full "rockyou" list — 14,344,391 real passwords exposed in the
2009 RockYou data breach — gzip-compressed inside the package so the
repository clone stays a reasonable size (~51 MiB instead of ~133 MiB).
Fetched from the well-known mirror used by naive-hashcat
(https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt,
sha256 of the uncompressed file: 6dfa76aa0e02303994fd1062d0ac983f0b69ece5474d85a5bba36362e19c1076),
line count and byte size verified against the file's well-known values
(14,344,391 lines, 139,921,497 bytes) before being compressed.

This is real historical breach data, not a synthetic or curated list —
only use it against files the operator is authorized to test, same as
every other password-recovery route in this project.

Streamed line by line, never materialized as a 14-million-entry list, so
using it costs time and CPU, not memory.
"""
import gzip
import importlib.resources

BUILTIN_WORDLIST_NAME = "rockyou"
# The file's own line count (its well-known size); used only as an upper
# bound for max_attempts. iter_builtin_wordlist() yields slightly fewer
# candidates than this, since it skips the handful of blank lines.
BUILTIN_WORDLIST_ENTRIES = 14_344_391


def iter_builtin_wordlist():
    """Yield each non-blank candidate password from the bundled rockyou list, in order."""
    resource = importlib.resources.files("cyber_core") / "data" / "wordlists" / "rockyou.txt.gz"
    with resource.open("rb") as raw, gzip.open(raw, "rb") as handle:
        for line in handle:
            line = line.rstrip(b"\r\n")
            if not line:
                continue
            try:
                yield line.decode("utf-8")
            except UnicodeDecodeError:
                yield line.decode("latin-1")
