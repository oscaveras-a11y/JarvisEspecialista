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
"""
from cyber_core.errors import CoreError

MAX_WORDS = 50
MAX_WORD_LENGTH = 64
MAX_VARIATIONS = 100000

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


def generate_variations(words, *, limit=MAX_VARIATIONS):
    """Yield bounded, deduplicated password candidates expanded from `words`.

    Pure function: no I/O, no randomness, same input always yields the same
    output in the same order. Callers that need a file write it themselves
    (see Core.materialize_generated_wordlist), the same way the bundled
    rockyou wordlist is written to a file rather than kept in memory.
    """
    if not isinstance(words, (list, tuple)) or not 1 <= len(words) <= MAX_WORDS:
        raise CoreError('Provide between 1 and ' + str(MAX_WORDS) + ' hint words')
    for word in words:
        if not isinstance(word, str) or not word or len(word) > MAX_WORD_LENGTH or '\n' in word or '\r' in word:
            raise CoreError('Each hint word must be 1-' + str(MAX_WORD_LENGTH) + ' characters, no newlines')
    if type(limit) is not int or not 1 <= limit <= MAX_VARIATIONS:
        raise CoreError('limit must be between 1 and ' + str(MAX_VARIATIONS))

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

    for candidate in generate():
        if emit(candidate):
            yield candidate
            if len(seen) >= limit:
                return
