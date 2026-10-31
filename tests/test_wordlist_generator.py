import itertools
import unittest

from cyber_core.errors import CoreError
from cyber_core.cryptanalysis.wordlist_generator import generate_bruteforce, generate_variations


class WordlistGeneratorUnitTests(unittest.TestCase):
    def test_includes_case_variants_and_common_suffixes(self):
        out = set(generate_variations(['Rex'], limit=1000))
        for expected in ('Rex', 'rex', 'REX', 'Rex1', 'Rex123', 'Rex!', 'rex2024', 'Rex26'):
            self.assertIn(expected, out)

    def test_includes_leetspeak_substitution(self):
        out = set(generate_variations(['password'], limit=1000))
        self.assertIn('p455w0rd', out)

    def test_combines_two_hint_words(self):
        out = set(generate_variations(['rex', 'max'], limit=100000))
        self.assertIn('rexmax', out)
        self.assertIn('rex_max', out)
        self.assertIn('max-rex', out)

    def test_single_word_has_no_two_word_combination_round(self):
        # A single hint word has nothing to combine with: 'solo-buddy'-style
        # combinations can only appear once a second hint word is given.
        solo = set(generate_variations(['solo'], limit=5000))
        with_pair = set(generate_variations(['solo', 'buddy'], limit=5000))
        self.assertNotIn('solo-buddy', solo)
        self.assertIn('solo-buddy', with_pair)

    def test_is_deterministic(self):
        first = list(generate_variations(['Rex', 'Max'], limit=5000))
        second = list(generate_variations(['Rex', 'Max'], limit=5000))
        self.assertEqual(first, second)

    def test_never_yields_a_duplicate(self):
        out = list(generate_variations(['Rex', 'Max'], limit=20000))
        self.assertEqual(len(out), len(set(out)))

    def test_respects_the_limit(self):
        out = list(generate_variations(['Rex', 'Max', 'Buddy'], limit=37))
        self.assertEqual(len(out), 37)

    def test_any_limit_is_reachable_with_a_single_hint_word(self):
        # Since the removal of the fixed 1,000,000 ceiling, the generator
        # must be able to produce an arbitrarily large number of unique
        # candidates from even a single hint word (round 4's numeric
        # suffix keeps widening without end), not just with many hints.
        out = list(generate_variations(['rex'], limit=2_000_000))
        self.assertEqual(len(out), 2_000_000)

    def test_unbounded_generation_never_stops_on_its_own(self):
        # limit=None must mean genuinely infinite: take an arbitrary large
        # slice and confirm it is still producing fresh, unique candidates.
        gen = generate_variations(['rex'])
        slice_ = list(itertools.islice(gen, 500_000))
        self.assertEqual(len(slice_), 500_000)
        self.assertEqual(len(set(slice_)), 500_000)

    def test_rejects_invalid_words(self):
        with self.assertRaises(CoreError):
            list(generate_variations([]))
        with self.assertRaises(CoreError):
            list(generate_variations(['x'] * 51))
        with self.assertRaises(CoreError):
            list(generate_variations(['']))
        with self.assertRaises(CoreError):
            list(generate_variations(['x' * 65]))
        with self.assertRaises(CoreError):
            list(generate_variations(['line\nbreak']))
        with self.assertRaises(CoreError):
            list(generate_variations([123]))

    def test_rejects_invalid_limit(self):
        with self.assertRaises(CoreError):
            list(generate_variations(['rex'], limit=0))
        with self.assertRaises(CoreError):
            list(generate_variations(['rex'], limit=-1))
        with self.assertRaises(CoreError):
            list(generate_variations(['rex'], limit='100'))


class BruteforceGeneratorUnitTests(unittest.TestCase):
    def test_enumerates_shortest_length_first(self):
        out = list(generate_bruteforce(charset='ab', min_length=1, max_length=3, limit=100))
        self.assertEqual(out[:2], ['a', 'b'])
        self.assertEqual(set(out[:6]), {'a', 'b', 'aa', 'ab', 'ba', 'bb'})

    def test_is_exhaustive_for_a_small_charset_and_length(self):
        out = list(generate_bruteforce(charset='xyz', min_length=1, max_length=2, limit=1000))
        expected = ['x', 'y', 'z'] + [a + b for a in 'xyz' for b in 'xyz']
        self.assertEqual(out, expected)

    def test_never_yields_a_duplicate(self):
        out = list(generate_bruteforce(charset='abcd', min_length=1, max_length=4, limit=5000))
        self.assertEqual(len(out), len(set(out)))

    def test_respects_an_explicit_limit(self):
        out = list(generate_bruteforce(limit=12345))
        self.assertEqual(len(out), 12345)

    def test_respects_an_explicit_max_length_with_no_limit(self):
        out = list(generate_bruteforce(charset='ab', min_length=1, max_length=3))
        self.assertEqual(len(out), 2 + 4 + 8)
        self.assertTrue(all(1 <= len(c) <= 3 for c in out))

    def test_unbounded_generation_grows_past_any_fixed_length(self):
        # No max_length, no limit beyond what we slice off: the default
        # must be genuinely infinite, reaching lengths well past the old
        # fixed 8-character default.
        gen = generate_bruteforce(charset='ab')
        slice_ = list(itertools.islice(gen, 2 + 4 + 8 + 16 + 32 + 1))
        self.assertEqual(len(slice_[-1]), 6)

    def test_rejects_invalid_charset(self):
        with self.assertRaises(CoreError):
            list(generate_bruteforce(charset=''))
        with self.assertRaises(CoreError):
            list(generate_bruteforce(charset='aab'))
        with self.assertRaises(CoreError):
            list(generate_bruteforce(charset='a\nb'))

    def test_rejects_invalid_lengths(self):
        with self.assertRaises(CoreError):
            list(generate_bruteforce(min_length=0))
        with self.assertRaises(CoreError):
            list(generate_bruteforce(min_length=5, max_length=2))

    def test_rejects_invalid_limit(self):
        with self.assertRaises(CoreError):
            list(generate_bruteforce(limit=0))
        with self.assertRaises(CoreError):
            list(generate_bruteforce(limit=-5))


if __name__ == '__main__':
    unittest.main()
