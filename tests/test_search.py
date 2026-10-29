"""Searching: candidate enumeration, determinism, and the arithmetic."""

from __future__ import annotations

import unittest

from selector_collide.keccak import selector_hex, selector_int
from selector_collide.search import (
    DEFAULT_ALPHABET,
    SearchError,
    benchmark,
    candidate_names,
    expected_candidates,
    find_birthday_pair,
    find_preimage,
    median_candidates,
    parse_count,
)


class ParseCount(unittest.TestCase):
    def test_plain_integers(self):
        self.assertEqual(parse_count("1"), 1)
        self.assertEqual(parse_count("1000000"), 1_000_000)

    def test_underscores(self):
        self.assertEqual(parse_count("100_000_000"), 100_000_000)

    def test_scientific_notation(self):
        self.assertEqual(parse_count("1e8"), 100_000_000)
        self.assertEqual(parse_count("2.5e3"), 2500)

    def test_powers_of_two(self):
        self.assertEqual(parse_count("2**32"), 4_294_967_296)
        self.assertEqual(parse_count("2**16"), 65_536)

    def test_whitespace_is_trimmed(self):
        self.assertEqual(parse_count("  1e6 "), 1_000_000)

    def test_rejections(self):
        for given in ("", "0", "-5", "1.5", "lots", "1e", "2**", "1e500"):
            with self.subTest(given):
                with self.assertRaises(SearchError):
                    parse_count(given)


class CandidateNames(unittest.TestCase):
    def test_order_is_empty_then_shortest_first(self):
        self.assertEqual(
            list(candidate_names("ab", 8)),
            ["", "a", "b", "aa", "ab", "ba", "bb", "aaa"],
        )

    def test_the_limit_is_respected_exactly(self):
        for limit in (0, 1, 2, 3, 7, 100):
            with self.subTest(limit=limit):
                self.assertEqual(len(list(candidate_names("abc", limit))), limit)

    def test_names_are_distinct(self):
        names = list(candidate_names(DEFAULT_ALPHABET, 5000))
        self.assertEqual(len(names), len(set(names)))

    def test_the_order_is_the_same_every_time(self):
        self.assertEqual(
            list(candidate_names(DEFAULT_ALPHABET, 500)),
            list(candidate_names(DEFAULT_ALPHABET, 500)),
        )

    def test_names_use_only_the_alphabet(self):
        for name in candidate_names("xyz", 60):
            with self.subTest(name):
                self.assertTrue(set(name) <= set("xyz"))

    def test_an_empty_alphabet_is_refused(self):
        with self.assertRaises(SearchError):
            list(candidate_names("", 10))

    def test_a_repeated_character_is_refused(self):
        with self.assertRaises(SearchError):
            list(candidate_names("aab", 10))


class Arithmetic(unittest.TestCase):
    def test_expected_candidates_is_two_to_the_bits(self):
        self.assertEqual(expected_candidates(32), 4_294_967_296)
        self.assertEqual(expected_candidates(16), 65_536)
        self.assertEqual(expected_candidates(8), 256)

    def test_median_is_about_69_percent_of_the_mean(self):
        self.assertEqual(median_candidates(32), 2_977_044_471)
        ratio = median_candidates(32) / expected_candidates(32)
        self.assertAlmostEqual(ratio, 0.6931471805599453, places=6)

    def test_median_is_below_the_mean_at_every_width(self):
        for bits in (8, 16, 24, 32):
            with self.subTest(bits=bits):
                self.assertLess(median_candidates(bits), expected_candidates(bits))


class Preimage(unittest.TestCase):
    def test_a_short_search_finds_a_low_bit_match(self):
        target = selector_hex("transfer(address,uint256)")
        result = find_preimage(target, bits=8, budget=100_000)
        self.assertTrue(result.found)
        self.assertEqual(
            selector_int(result.signature) >> 24, selector_int("transfer(address,uint256)") >> 24
        )

    def test_the_result_is_a_valid_signature_of_the_template(self):
        result = find_preimage("0xa9059cbb", bits=8, budget=100_000,
                               template="f{}(address,uint256)")
        self.assertTrue(result.signature.startswith("f"))
        self.assertTrue(result.signature.endswith("(address,uint256)"))

    def test_the_same_arguments_give_the_same_signature(self):
        first = find_preimage("0xa9059cbb", bits=12, budget=200_000)
        second = find_preimage("0xa9059cbb", bits=12, budget=200_000)
        self.assertEqual(first.signature, second.signature)
        self.assertEqual(first.tried, second.tried)

    def test_a_tiny_budget_exhausts_without_a_match(self):
        result = find_preimage("0xa9059cbb", bits=32, budget=200)
        self.assertFalse(result.found)
        self.assertIsNone(result.signature)
        self.assertEqual(result.tried, 200)
        self.assertEqual(result.budget, 200)

    def test_the_target_is_normalised_in_the_result(self):
        self.assertEqual(find_preimage("A9059CBB", bits=4, budget=1000).target,
                         "0xa9059cbb")
        self.assertEqual(find_preimage("0x000000ff", bits=4, budget=1000).target,
                         "0x000000ff")

    def test_a_one_bit_target_is_nearly_immediate(self):
        result = find_preimage("0x00000000", bits=1, budget=1000)
        self.assertTrue(result.found)
        self.assertLess(result.tried, 100)

    def test_bits_outside_one_to_thirty_two_are_refused(self):
        for bits in (0, -1, 33, 64):
            with self.subTest(bits=bits):
                with self.assertRaises(SearchError):
                    find_preimage("0xa9059cbb", bits=bits, budget=10)

    def test_a_template_without_a_placeholder_is_refused(self):
        with self.assertRaises(SearchError):
            find_preimage("0xa9059cbb", template="f()", budget=10)

    def test_a_template_with_two_placeholders_is_refused(self):
        with self.assertRaises(SearchError):
            find_preimage("0xa9059cbb", template="f{}{}()", budget=10)

    def test_a_template_that_is_not_a_signature_is_refused(self):
        for template in ("f{}", "{}", "f{}(uint256) extra"):
            with self.subTest(template):
                with self.assertRaises(SearchError):
                    find_preimage("0xa9059cbb", template=template, budget=10)

    def test_the_rate_is_reported(self):
        result = find_preimage("0xa9059cbb", bits=32, budget=500)
        self.assertGreater(result.rate, 0)
        self.assertGreater(result.elapsed, 0)

    def test_progress_is_called(self):
        seen = []
        find_preimage("0xffffffff", bits=32, budget=300,
                      progress=lambda tried, elapsed: seen.append(tried),
                      progress_every=100)
        self.assertEqual(seen, [100, 200, 300])


class Birthday(unittest.TestCase):
    """One search is shared: a 32-bit birthday collision costs ~65,000 hashes."""

    @classmethod
    def setUpClass(cls):
        cls.result = find_birthday_pair(budget=400_000)

    def test_a_pair_is_found(self):
        self.assertTrue(self.result.found)
        self.assertIsNotNone(self.result.selector)

    def test_the_pair_is_two_different_signatures(self):
        self.assertNotEqual(self.result.first, self.result.second)

    def test_both_signatures_really_hash_to_the_reported_selector(self):
        self.assertEqual(selector_hex(self.result.first), self.result.selector)
        self.assertEqual(selector_hex(self.result.second), self.result.selector)

    def test_a_collision_appears_well_inside_the_birthday_bound(self):
        # 400,000 candidates is about five times the 50% point for a 32-bit
        # space; failing here would mean the hash is badly non-uniform.
        self.assertLess(self.result.tried, 400_000)

    def test_the_pair_matches_the_default_template(self):
        for signature in (self.result.first, self.result.second):
            with self.subTest(signature):
                self.assertTrue(signature.startswith("f"))
                self.assertTrue(signature.endswith("()"))

    def test_the_same_arguments_give_the_same_outcome(self):
        first = find_birthday_pair(alphabet="abcdef", budget=20_000)
        second = find_birthday_pair(alphabet="abcdef", budget=20_000)
        self.assertEqual(first.found, second.found)
        self.assertEqual(first.first, second.first)
        self.assertEqual(first.second, second.second)
        self.assertEqual(first.tried, second.tried)

    def test_a_tiny_budget_exhausts(self):
        result = find_birthday_pair(budget=50)
        self.assertFalse(result.found)
        self.assertIsNone(result.selector)
        self.assertEqual(result.tried, 50)

    def test_a_bad_template_is_refused(self):
        with self.assertRaises(SearchError):
            find_birthday_pair(template="no placeholder()", budget=10)


class Benchmark(unittest.TestCase):
    def test_it_hashes_what_it_was_asked_to(self):
        hashed, seconds = benchmark(500)
        self.assertEqual(hashed, 500)
        self.assertGreater(seconds, 0)

    def test_a_bad_template_is_refused(self):
        with self.assertRaises(SearchError):
            benchmark(10, template="nope")


if __name__ == "__main__":
    unittest.main()
