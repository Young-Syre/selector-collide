"""Canonicalisation: the table in the README, plus the cases that must fail."""

from __future__ import annotations

import unittest

from selector_collide.signature import (
    Entry,
    SignatureError,
    canonical_signature,
    canonical_type,
    parse_signature,
    split_top_level,
)

# (input type, canonical form)
TYPE_TABLE = (
    ("address", "address"),
    ("bool", "bool"),
    ("string", "string"),
    ("bytes", "bytes"),
    ("bytes1", "bytes1"),
    ("bytes32", "bytes32"),
    ("uint8", "uint8"),
    ("uint256", "uint256"),
    ("int128", "int128"),
    ("function", "function"),
    # aliases
    ("uint", "uint256"),
    ("int", "int256"),
    ("byte", "bytes1"),
    ("fixed", "fixed128x18"),
    ("ufixed", "ufixed128x18"),
    ("fixed128x18", "fixed128x18"),
    ("ufixed8x80", "ufixed8x80"),
    # arrays
    ("uint256[]", "uint256[]"),
    ("uint[]", "uint256[]"),
    ("uint[3]", "uint256[3]"),
    ("uint[2][]", "uint256[2][]"),
    ("address[][4]", "address[][4]"),
    # tuples
    ("(address,uint256)", "(address,uint256)"),
    ("(uint,int)", "(uint256,int256)"),
    ("(address,(bool,uint))", "(address,(bool,uint256))"),
    ("(address,uint256)[]", "(address,uint256)[]"),
    ("(address,uint256)[2]", "(address,uint256)[2]"),
    ("((uint8)[2],bytes)", "((uint8)[2],bytes)"),
    ("()", "()"),
    # Solidity source noise
    ("address payable", "address"),
    ("address payable recipient", "address"),
    ("uint256 amount", "uint256"),
    ("uint256[] memory amounts", "uint256[]"),
    ("bytes calldata data", "bytes"),
    ("uint256[] storage slotRef", "uint256[]"),
    ("contract IERC20", "address"),
    ("contract IERC20 token", "address"),
    ("interface IVault vault", "address"),
    ("enum Vault.Mode", "uint8"),
    ("enum Vault.Mode mode", "uint8"),
    ("(address,uint256)[2] memory batch", "(address,uint256)[2]"),
    ("  uint   ", "uint256"),
)

REJECTED_TYPES = (
    "",
    "uint7",
    "uint264",
    "int0",
    "bytes0",
    "bytes33",
    "fixed7x18",
    "fixed128x0",
    "fixed128x81",
    "fixed128",
    "struct Vault.RedeemRequest",
    "struct Vault.RedeemRequest request",
    "MyToken",
    "Vault.Mode",
    "tuple",
    "uint256[0]",
    "uint256[01]",
    "uint256[-1]",
    "(address,uint256",
    "address,uint256)",
    "uint256 a b",
    "address payable contract IERC20",
)


class CanonicalTypes(unittest.TestCase):
    def test_table(self):
        for given, expected in TYPE_TABLE:
            with self.subTest(given):
                self.assertEqual(canonical_type(given), expected)

    def test_rejections(self):
        for given in REJECTED_TYPES:
            with self.subTest(given):
                with self.assertRaises(SignatureError):
                    canonical_type(given)

    def test_tuple_expands_from_components(self):
        components = [
            {"name": "shares", "type": "uint256"},
            {"name": "receiver", "type": "address"},
            {"name": "deadline", "type": "uint64"},
        ]
        self.assertEqual(
            canonical_type("tuple", components), "(uint256,address,uint64)"
        )

    def test_tuple_array_expands_from_components(self):
        components = [{"name": "a", "type": "uint"}, {"name": "b", "type": "bool"}]
        self.assertEqual(canonical_type("tuple[]", components), "(uint256,bool)[]")
        self.assertEqual(canonical_type("tuple[2]", components), "(uint256,bool)[2]")

    def test_nested_tuple_components(self):
        components = [
            {"name": "outer", "type": "uint8"},
            {
                "name": "inner",
                "type": "tuple[2]",
                "components": [
                    {"name": "x", "type": "address"},
                    {"name": "y", "type": "bytes4"},
                ],
            },
        ]
        self.assertEqual(
            canonical_type("tuple", components), "(uint8,(address,bytes4)[2])"
        )

    def test_integer_widths_at_the_edges(self):
        self.assertEqual(canonical_type("uint8"), "uint8")
        self.assertEqual(canonical_type("uint256"), "uint256")
        self.assertEqual(canonical_type("int8"), "int8")
        self.assertEqual(canonical_type("int256"), "int256")


class SplitTopLevel(unittest.TestCase):
    def test_splits_only_at_depth_zero(self):
        self.assertEqual(
            split_top_level("uint256,(address,bool)[2],bytes"),
            ["uint256", "(address,bool)[2]", "bytes"],
        )

    def test_single_part(self):
        self.assertEqual(split_top_level("uint256"), ["uint256"])

    def test_empty(self):
        self.assertEqual(split_top_level(""), [])

    def test_nested_tuples(self):
        self.assertEqual(
            split_top_level("(a,(b,c)),d"), ["(a,(b,c))", "d"]
        )

    def test_unbalanced_is_refused(self):
        for given in ("(a,b", "a,b)", "a[1"):
            with self.subTest(given):
                with self.assertRaises(SignatureError):
                    split_top_level(given)


class ParseSignature(unittest.TestCase):
    def test_canonical_signature_round_trip(self):
        entry = parse_signature("transfer(address,uint256)")
        self.assertEqual(entry.name, "transfer")
        self.assertEqual(entry.types, ("address", "uint256"))
        self.assertEqual(entry.signature, "transfer(address,uint256)")
        self.assertEqual(entry.selector, "0xa9059cbb")
        self.assertEqual(entry.kind, "function")

    def test_solidity_declaration(self):
        entry = parse_signature(
            "function transfer(address to, uint256 amount) external returns (bool)"
        )
        self.assertEqual(entry.signature, "transfer(address,uint256)")
        self.assertEqual(entry.selector, "0xa9059cbb")
        self.assertEqual(entry.outputs, ("bool",))
        self.assertEqual(entry.state_mutability, "nonpayable")

    def test_view_is_recorded(self):
        entry = parse_signature("balanceOf(address account) view")
        self.assertEqual(entry.state_mutability, "view")
        self.assertFalse(entry.is_state_changing)

    def test_payable_is_recorded(self):
        entry = parse_signature("deposit(uint256) external payable")
        self.assertEqual(entry.state_mutability, "payable")
        self.assertTrue(entry.is_state_changing)

    def test_modifiers_are_collected(self):
        entry = parse_signature("withdraw(uint256) external onlyAdmin whenNotPaused")
        self.assertEqual(entry.modifiers, ("onlyAdmin", "whenNotPaused"))

    def test_modifiers_do_not_change_the_selector(self):
        plain = parse_signature("withdraw(uint256)")
        guarded = parse_signature("withdraw(uint256) onlyAdmin")
        self.assertEqual(plain.selector, guarded.selector)
        self.assertNotEqual(plain.modifiers, guarded.modifiers)

    def test_returns_clause_with_names_and_tuples(self):
        entry = parse_signature(
            "quote(uint256 amount) view returns (uint256 out, (address,bool) meta)"
        )
        self.assertEqual(entry.signature, "quote(uint256)")
        self.assertEqual(entry.outputs, ("uint256", "(address,bool)"))

    def test_error_entries(self):
        entry = parse_signature(
            "error InsufficientBalance(uint256 available, uint256 required)"
        )
        self.assertEqual(entry.kind, "error")
        self.assertEqual(entry.signature, "InsufficientBalance(uint256,uint256)")
        self.assertEqual(entry.selector, "0xcf479181")
        self.assertTrue(entry.has_selector)
        self.assertFalse(entry.dispatchable)

    def test_event_entries_have_no_selector(self):
        entry = parse_signature("event Transfer(address from, address to, uint256 value)")
        self.assertEqual(entry.kind, "event")
        self.assertIsNone(entry.selector)
        self.assertFalse(entry.has_selector)

    def test_fallback_and_receive(self):
        for text, kind in (("fallback()", "fallback"), ("receive()", "receive"),
                           ("fallback", "fallback"), ("receive", "receive")):
            with self.subTest(text):
                entry = parse_signature(text)
                self.assertEqual(entry.kind, kind)
                self.assertIsNone(entry.selector)
                self.assertEqual(entry.signature, f"{kind}()")
                self.assertFalse(entry.dispatchable)

    def test_no_parameters(self):
        entry = parse_signature("owner()")
        self.assertEqual(entry.types, ())
        self.assertEqual(entry.selector, "0x8da5cb5b")

    def test_whitespace_is_irrelevant(self):
        a = parse_signature("transfer( address  to , uint256 amount )")
        self.assertEqual(a.signature, "transfer(address,uint256)")

    def test_dollar_and_underscore_names(self):
        for name in ("_private", "$flash", "a0_$b"):
            with self.subTest(name):
                self.assertEqual(parse_signature(f"{name}()").name, name)

    def test_bad_signatures_are_refused(self):
        for given in ("", "transfer", "transfer(address", "1transfer()",
                      "tran-sfer()", "transfer(struct Foo.Bar)",
                      "f(uint256) returns (uint256"):
            with self.subTest(given):
                with self.assertRaises(SignatureError):
                    parse_signature(given)

    def test_describe_shows_mutability_and_modifiers(self):
        entry = parse_signature("withdraw(uint256) onlyAdmin")
        self.assertEqual(entry.describe(), "withdraw(uint256) [nonpayable onlyAdmin]")

    def test_canonical_signature_helper(self):
        self.assertEqual(
            canonical_signature("transfer", ["address", "uint256"]),
            "transfer(address,uint256)",
        )

    def test_entries_are_hashable_and_comparable(self):
        a = Entry("owner", (), "function", "view")
        b = Entry("owner", (), "function", "view")
        self.assertEqual(a, b)
        self.assertEqual(len({a, b}), 1)

    def test_outputs_do_not_affect_equality(self):
        a = Entry("owner", (), "function", "view", outputs=("address",))
        b = Entry("owner", (), "function", "view", outputs=())
        self.assertEqual(a, b)


if __name__ == "__main__":
    unittest.main()
