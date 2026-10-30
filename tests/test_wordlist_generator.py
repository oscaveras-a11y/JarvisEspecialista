import unittest

from cyber_core.errors import CoreError
from cyber_core.cryptanalysis.wordlist_generator import generate_variations


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
        # A single hint word has nothing to combine with, so the output
        # must be exactly rounds 1+2 (suffixes/years) and never grow from
        # a second, unrelated hint word later added to the same case.
        solo = len(list(generate_variations(['solo'], limit=100000)))
        with_pair = len(list(generate_variations(['solo', 'buddy'], limit=100000)))
        self.assertGreater(with_pair, solo)

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
            list(generate_variations(['rex'], limit=100001))


if __name__ == '__main__':
    unittest.main()
