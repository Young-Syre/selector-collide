"""Recompute every published collision this package quotes.

The table in ``selector_collide.known`` is only useful if it is true. Rather
than trusting the strings, each group is hashed here with this package's own
Keccak, which is itself pinned to published vectors in ``test_keccak.py``.
"""

from __future__ import annotations

import unittest

from selector_collide.keccak import selector_hex
from selector_collide.known import KNOWN_COLLISIONS, alternatives_for


class KnownCollisions(unittest.TestCase):
    def test_every_member_hashes_to_its_group_selector(self):
        for selector, group in KNOWN_COLLISIONS.items():
            for signature in group:
                with self.subTest(signature=signature):
                    self.assertEqual(selector_hex(signature), selector)

    def test_every_group_has_at_least_two_distinct_signatures(self):
        for selector, group in KNOWN_COLLISIONS.items():
            with self.subTest(selector):
                self.assertGreaterEqual(len(set(group)), 2)

    def test_the_erc20_transfer_group(self):
        group = KNOWN_COLLISIONS["0xa9059cbb"]
        self.assertIn("transfer(address,uint256)", group)
        self.assertIn("many_msg_babbage(bytes1)", group)
        self.assertIn("func_2093253501(bytes)", group)
        self.assertEqual(selector_hex("transfer(address,uint256)"), "0xa9059cbb")
        self.assertEqual(selector_hex("many_msg_babbage(bytes1)"), "0xa9059cbb")

    def test_the_transfer_from_group(self):
        self.assertEqual(
            selector_hex("transferFrom(address,address,uint256)"),
            selector_hex("gasprice_bit_ether(int128)"),
        )

    def test_the_burn_group(self):
        self.assertEqual(
            selector_hex("burn(uint256)"),
            selector_hex("collate_propagate_storage(bytes16)"),
        )

    def test_selector_keys_are_lowercase_and_well_formed(self):
        for selector in KNOWN_COLLISIONS:
            with self.subTest(selector):
                self.assertTrue(selector.startswith("0x"))
                self.assertEqual(len(selector), 10)
                self.assertEqual(selector, selector.lower())

    def test_alternatives_excludes_the_signature_asked_about(self):
        alternatives = alternatives_for("0xa9059cbb", "transfer(address,uint256)")
        self.assertNotIn("transfer(address,uint256)", alternatives)
        self.assertIn("many_msg_babbage(bytes1)", alternatives)

    def test_alternatives_returns_everything_when_no_signature_is_given(self):
        self.assertEqual(len(alternatives_for("0xa9059cbb")), 3)

    def test_alternatives_is_case_insensitive(self):
        self.assertEqual(alternatives_for("0xA9059CBB"), alternatives_for("0xa9059cbb"))

    def test_an_unknown_selector_has_no_alternatives(self):
        self.assertEqual(alternatives_for("0x00000000"), ())


if __name__ == "__main__":
    unittest.main()
