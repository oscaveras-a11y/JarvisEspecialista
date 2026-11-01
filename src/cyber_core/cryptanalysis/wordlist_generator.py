"""Local, rule-based password-candidate generator from operator-supplied hints.

Part of item 7 (criptografia/recuperação) — the "layer 2" of the two-layer
recovery design in docs/ai-assisted-recovery-plan.md: a human (or, later,
an AI such as Qwen3) supplies a short list of base words/themes relevant
to the target (names, dates, pets, references); this module expands each
one into realistic variations (case, leetspeak, digits, years, separators,
two-word combinations) using fixed rules — no model, no inference, no
network. The whole point of doing this with rules instead of a live model
is speed: a real cracking tool tests thousands to millions of candidates
per second, far faster than any model could generate them one at a time,
so generation must be a one-shot, instant, bounded expansion the tool can
then run against for as long as it needs to (hours or days).

The expanded list is a plain source of CANDIDATES, nothing more: whatever
consumes it (the CLI's --wordlist file, a recovery-session's --candidates
material) is the only thing that ever tests a candidate against a real
file and decides whether it matched. This module never opens, reads or
tests any target file.

Also provides generate_bruteforce(): true exhaustive enumeration over a
character set rather than hint words, requested and built with the
explicit, stated understanding that it can only ever be exhaustive for
short lengths — see that function's own docstring for the exact reason.

Both generators accept limit=None (the default), meaning unbounded: they
keep yielding candidates forever, growing length without end, until the
caller stops iterating (Ctrl+C on the CLI, the recovery-session being
stopped, or — for a file write — the disk running out of space). This was
an explicit operator request to remove the earlier fixed ceiling. A caller
that wants a bound can still pass an explicit `limit`.
"""
import itertools
from cyber_core.errors import CoreError

MAX_WORDS = 50
MAX_WORD_LENGTH = 64
_BRUTEFORCE_CHARSET = (
    'abcdefghijklmnopqrstuvwxyz'
    'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    '0123456789'
    '!@#$%^&*()_-+=~`[]{}|;:,.<>?/'
)

_LEET = str.maketrans({'a': '4', 'e': '3', 'i': '1', 'o': '0', 's': '5'})
_SUFFIXES = ('', '1', '12', '123', '1234', '01', '007', '!', '!!', '@', '#', '$', '_', '-', '.')
_SEPARATORS = ('', '.', '_', '-')
# Recent-first: a birth year, an anniversary or "the current year" habit is
# far more likely than an arbitrary year decades away, so later truncation
# (when the limit is hit) drops the least likely candidates first.
_YEARS = tuple(str(year) for year in range(2026, 1950, -1))
_YEAR_SUFFIXES_2DIGIT = tuple(year[-2:] for year in _YEARS)


def _forms(word):
    # Case variants, deduplicated, original form first (most likely as-typed).
    seen, out = set(), []
    for candidate in (word, word.lower(), word.upper(), word.capitalize()):
        if candidate not in seen:
            seen.add(candidate)
            out.append(candidate)
    return out


def _leet(word):
    translated = word.lower().translate(_LEET)
    return translated if translated != word.lower() else None


def generate_variations(words, *, limit=None):
    """Yield deduplicated password candidates expanded from `words`.

    Pure function (deterministic order) except that, unbounded (the
    default, limit=None), it never terminates on its own: rounds 1-3 are
    finite, but round 4 grows the numeric-suffix width without end
    (00, ..., 99, 000, ..., 999, 0000, ...), so the overall generator is
    infinite. Callers that need a file write it themselves (see
    Core.materialize_generated_wordlist), the same way the bundled rockyou
    wordlist is written to a file rather than kept in memory, and must
    stop the iteration themselves (a bound `limit`, or an external
    interrupt) if they don't want it to run forever.
    """
    if not isinstance(words, (list, tuple)) or not 1 <= len(words) <= MAX_WORDS:
        raise CoreError('Provide between 1 and ' + str(MAX_WORDS) + ' hint words')
    for word in words:
        if not isinstance(word, str) or not word or len(word) > MAX_WORD_LENGTH or '\n' in word or '\r' in word:
            raise CoreError('Each hint word must be 1-' + str(MAX_WORD_LENGTH) + ' characters, no newlines')
    if limit is not None and (type(limit) is not int or limit < 1):
        raise CoreError('limit must be a positive integer, or None for no limit')

    seen = set()

    def emit(candidate):
        if candidate and candidate not in seen:
            seen.add(candidate)
            return True
        return False

    def generate():
        bases = []
        for word in words:
            bases.extend(_forms(word))
            leet = _leet(word)
            if leet:
                bases.append(leet)
        # Round 1: bare forms and forms with a short, common suffix — the
        # most realistic, highest-probability candidates, tried first.
        for base in bases:
            for suffix in _SUFFIXES:
                yield base + suffix
        # Round 2: forms with a plausible year appended (full and 2-digit).
        for base in bases:
            for year in _YEAR_SUFFIXES_2DIGIT:
                yield base + year
            for year in _YEARS:
                yield base + year
        # Round 3: two-word combinations, if more than one hint was given.
        if len(words) > 1:
            for i, first in enumerate(words):
                for second in words[i + 1:]:
                    for form_a in _forms(first):
                        for form_b in _forms(second):
                            for sep in _SEPARATORS:
                                yield form_a + sep + form_b
                                yield form_b + sep + form_a
        # Round 4: arbitrary numeric suffixes (PIN-style, e.g. "Rex42",
        # "Rex007", "Rex2026" as a bare number rather than a year), widening
        # the digit count without end (2 digits, then 3, then 4, ...) so
        # that an unbounded caller (limit=None) always has more candidates
        # to produce rather than exhausting this round. Lower priority than
        # the rounds above — a real date/year or a second real hint word is
        # a more likely password than an arbitrary number — but a common
        # enough pattern that it is worth sweeping once the more targeted
        # rounds are exhausted.
        for width in itertools.count(2):
            for base in bases:
                for number in range(10 ** width):
                    yield base + ('%0' + str(width) + 'd') % number
        # Round 5: digits mixed with a symbol together, the pattern behind
        # "Rex123!"/"!Rex123" style passwords that pure-digit or pure-symbol
        # suffixes alone never produce.
        for base in bases:
            for digits in ('1', '12', '123', '1234'):
                for symbol in ('!', '@', '#', '$', '.', '_', '-'):
                    yield base + digits + symbol
                    yield base + symbol + digits

    for candidate in generate():
        if emit(candidate):
            yield candidate
            if limit is not None and len(seen) >= limit:
                return


def generate_bruteforce(*, charset=None, min_length=1, max_length=None, limit=None):
    """Yield every string of `charset`, shortest length first.

    This is true exhaustive brute force over a character set (letters,
    digits and symbols by default) — no hint words, no human pattern, just
    every possible string in order, growing in length without end unless
    `max_length` or `limit` is given. Stated plainly because this was asked
    for, unbounded, with that understanding already given: the number of
    strings of a given length L over a charset of size C is C**L. For the
    default charset (89 characters) at L=36, that is on the order of
    10**70 — more than the ~10**80 atoms in the observable universe, and
    unreachable by any computer that could ever be built, regardless of
    how this function is written, or how long it is left running. It does
    not pretend otherwise: lengths are tried shortest first (so the
    lengths that genuinely are exhaustible — a handful of characters — are
    covered in full before anything longer), and left to run unbounded it
    will keep producing candidates forever, covering only an
    infinitesimal, non-representative slice of any length long enough for
    that to matter. Stopping it (an explicit `limit` or `max_length`, or an
    external interrupt — Ctrl+C on the CLI, stopping the recovery-session,
    the destination disk filling up) is entirely the caller's
    responsibility.

    For real exhaustive search over a SHORT password, a dedicated
    cracking tool's own mask-attack mode (e.g. hashcat -a 3) is the right
    tool: it enumerates in compiled code directly against the target, at
    a rate no Python generator writing a candidates file could match, and
    needs no file to be materialized at all. See
    docs/ai-assisted-recovery-plan.md for when to use which.
    """
    if charset is None:
        charset = _BRUTEFORCE_CHARSET
    if not isinstance(charset, str) or not charset or len(set(charset)) != len(charset):
        raise CoreError('charset must be a non-empty string of unique characters')
    if any(c in '\n\r' for c in charset):
        raise CoreError('charset must not include newline characters')
    if type(min_length) is not int or min_length < 1:
        raise CoreError('min_length must be a positive integer')
    if max_length is not None and (type(max_length) is not int or max_length < min_length):
        raise CoreError('max_length must be an integer >= min_length, or None for no limit')
    if limit is not None and (type(limit) is not int or limit < 1):
        raise CoreError('limit must be a positive integer, or None for no limit')
    lengths = itertools.count(min_length) if max_length is None else range(min_length, max_length + 1)
    produced = 0
    for length in lengths:
        for combo in itertools.product(charset, repeat=length):
            yield ''.join(combo)
            produced += 1
            if limit is not None and produced >= limit:
                return
