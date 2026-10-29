"""Loading ABIs, artefacts and signature lists from files."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from selector_collide.abi import (
    AbiError,
    load_selector_list,
    load_source,
    parse_selector,
)

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"

MINIMAL_ABI = [
    {
        "type": "function",
        "name": "transfer",
        "inputs": [
            {"name": "to", "type": "address"},
            {"name": "amount", "type": "uint256"},
        ],
        "outputs": [{"name": "", "type": "bool"}],
        "stateMutability": "nonpayable",
    }
]


class Temp:
    """A throwaway directory, so tests never depend on where the repo lives."""

    def __enter__(self):
        self._tmp = tempfile.TemporaryDirectory()
        return Path(self._tmp.name)

    def __exit__(self, *exc):
        self._tmp.cleanup()


def write(directory: Path, name: str, content) -> Path:
    path = directory / name
    path.write_text(content if isinstance(content, str) else json.dumps(content))
    return path


class LoadAbiJson(unittest.TestCase):
    def test_plain_abi_array(self):
        with Temp() as tmp:
            source = load_source(write(tmp, "Token.json", MINIMAL_ABI))
        self.assertEqual(source.fmt, "abi-json")
        self.assertEqual(source.label, "Token.json")
        self.assertEqual(len(source.functions), 1)
        self.assertEqual(source.functions[0].selector, "0xa9059cbb")

    def test_build_artefact_with_abi_key(self):
        with Temp() as tmp:
            path = write(tmp, "Token.json", {"abi": MINIMAL_ABI, "bytecode": "0x00"})
            source = load_source(path)
        self.assertEqual(source.fmt, "artefact-json")
        self.assertEqual(source.functions[0].signature, "transfer(address,uint256)")

    def test_label_is_the_basename_only(self):
        with Temp() as tmp:
            nested = tmp / "deep" / "deeper"
            nested.mkdir(parents=True)
            source = load_source(write(nested, "Token.json", MINIMAL_ABI))
        self.assertEqual(source.label, "Token.json")
        self.assertNotIn("/", source.label)

    def test_explicit_label_overrides(self):
        with Temp() as tmp:
            source = load_source(write(tmp, "Token.json", MINIMAL_ABI), label="proxy")
        self.assertEqual(source.label, "proxy")

    def test_missing_type_defaults_to_function(self):
        abi = [{"name": "owner", "inputs": [], "outputs": [], "stateMutability": "view"}]
        with Temp() as tmp:
            source = load_source(write(tmp, "a.json", abi))
        self.assertEqual(source.functions[0].kind, "function")
        self.assertEqual(source.functions[0].selector, "0x8da5cb5b")

    def test_events_and_constructors_are_dropped(self):
        abi = [
            {"type": "constructor", "inputs": [{"name": "x", "type": "address"}]},
            {"type": "event", "name": "Transfer", "inputs": []},
        ] + MINIMAL_ABI
        with Temp() as tmp:
            source = load_source(write(tmp, "a.json", abi))
        self.assertEqual(len(source.entries), 1)
        self.assertEqual(source.entries[0].name, "transfer")

    def test_fallback_and_receive_are_kept(self):
        abi = [
            {"type": "fallback", "stateMutability": "payable"},
            {"type": "receive", "stateMutability": "payable"},
        ]
        with Temp() as tmp:
            source = load_source(write(tmp, "a.json", abi))
        self.assertTrue(source.has_fallback)
        self.assertTrue(source.has_receive)
        self.assertEqual(source.selector_map(), {})

    def test_pre_050_constant_and_payable_booleans(self):
        abi = [
            {"type": "function", "name": "owner", "inputs": [], "constant": True},
            {"type": "function", "name": "buy", "inputs": [], "payable": True},
            {"type": "function", "name": "poke", "inputs": []},
        ]
        with Temp() as tmp:
            source = load_source(write(tmp, "a.json", abi))
        mutabilities = {e.name: e.state_mutability for e in source.functions}
        self.assertEqual(mutabilities["owner"], "view")
        self.assertEqual(mutabilities["buy"], "payable")
        self.assertEqual(mutabilities["poke"], "nonpayable")

    def test_struct_inputs_expand_to_tuples(self):
        source = load_source(EXAMPLES / "implementation.json")
        signatures = {e.signature for e in source.functions}
        self.assertIn("previewRedeem((uint256,address,uint64))", signatures)

    def test_contract_internal_type_is_an_address(self):
        source = load_source(EXAMPLES / "implementation.json")
        signatures = {e.signature for e in source.functions}
        self.assertIn("initialize(address,address)", signatures)

    def test_errors_are_loaded_separately_from_functions(self):
        source = load_source(EXAMPLES / "implementation.json")
        self.assertEqual([e.signature for e in source.errors],
                         ["InsufficientBalance(uint256,uint256)"])
        self.assertNotIn("InsufficientBalance(uint256,uint256)",
                         {e.signature for e in source.functions})

    def test_modifiers_key_is_read(self):
        source = load_source(EXAMPLES / "proxy.json")
        by_name = {e.name: e for e in source.functions}
        self.assertEqual(by_name["upgradeTo"].modifiers, ("onlyAdmin",))
        self.assertEqual(by_name["owner"].modifiers, ())

    def test_selector_map_can_include_errors(self):
        source = load_source(EXAMPLES / "implementation.json")
        self.assertNotIn("0xcf479181", source.selector_map())
        self.assertIn("0xcf479181", source.selector_map(include_errors=True))

    def test_selector_map_groups_duplicates_in_file_order(self):
        abi = [
            {"type": "function", "name": "burn", "inputs": [{"type": "uint256"}]},
            {"type": "function", "name": "collate_propagate_storage",
             "inputs": [{"type": "bytes16"}]},
        ]
        with Temp() as tmp:
            source = load_source(write(tmp, "a.json", abi))
        entries = source.selector_map()["0x42966c68"]
        self.assertEqual([e.name for e in entries],
                         ["burn", "collate_propagate_storage"])


class LoadSignatureList(unittest.TestCase):
    def test_signature_list(self):
        source = load_source(EXAMPLES / "router-surface.txt")
        self.assertEqual(source.fmt, "signatures")
        self.assertTrue(source.has_fallback)
        self.assertTrue(source.has_receive)
        signatures = {e.signature for e in source.functions}
        self.assertIn("sweep(address,address)", signatures)
        self.assertIn("setPaused(bool)", signatures)

    def test_modifiers_from_a_signature_list(self):
        source = load_source(EXAMPLES / "router-surface.txt")
        by_name = {e.name: e for e in source.functions}
        self.assertEqual(by_name["sweep"].modifiers, ("onlyOperator",))
        self.assertEqual(by_name["setPaused"].modifiers, ("onlyGuardian",))

    def test_comments_and_blank_lines_are_ignored(self):
        with Temp() as tmp:
            path = write(tmp, "sigs.txt", "# a comment\n\nowner()  # trailing\n\n")
            source = load_source(path)
        self.assertEqual(len(source.entries), 1)
        self.assertEqual(source.entries[0].selector, "0x8da5cb5b")

    def test_a_bad_line_names_its_line_number(self):
        with Temp() as tmp:
            path = write(tmp, "sigs.txt", "owner()\nnot a signature\n")
            with self.assertRaises(AbiError) as caught:
                load_source(path)
        self.assertIn("sigs.txt:2", str(caught.exception))


class Failures(unittest.TestCase):
    def test_missing_file(self):
        with Temp() as tmp:
            with self.assertRaises(AbiError):
                load_source(tmp / "nope.json")

    def test_invalid_json(self):
        with Temp() as tmp:
            with self.assertRaises(AbiError) as caught:
                load_source(write(tmp, "a.json", "[{,}]"))
        self.assertIn("invalid JSON", str(caught.exception))

    def test_json_object_without_abi_key(self):
        with Temp() as tmp:
            with self.assertRaises(AbiError) as caught:
                load_source(write(tmp, "a.json", {"bytecode": "0x00"}))
        self.assertIn("'abi'", str(caught.exception))

    def test_empty_file(self):
        with Temp() as tmp:
            with self.assertRaises(AbiError):
                load_source(write(tmp, "a.txt", "   \n"))

    def test_entry_without_a_name(self):
        with Temp() as tmp:
            with self.assertRaises(AbiError):
                load_source(write(tmp, "a.json", [{"type": "function", "inputs": []}]))

    def test_unknown_entry_type(self):
        with Temp() as tmp:
            with self.assertRaises(AbiError):
                load_source(write(tmp, "a.json", [{"type": "modifier", "name": "m"}]))

    def test_input_without_a_type(self):
        abi = [{"type": "function", "name": "f", "inputs": [{"name": "x"}]}]
        with Temp() as tmp:
            with self.assertRaises(AbiError):
                load_source(write(tmp, "a.json", abi))

    def test_unresolvable_struct_without_components(self):
        abi = [{"type": "function", "name": "f",
                "inputs": [{"name": "r", "type": "tuple"}]}]
        with Temp() as tmp:
            with self.assertRaises(AbiError):
                load_source(write(tmp, "a.json", abi))

    def test_modifiers_key_must_be_strings(self):
        abi = [{"type": "function", "name": "f", "inputs": [], "modifiers": [1]}]
        with Temp() as tmp:
            with self.assertRaises(AbiError):
                load_source(write(tmp, "a.json", abi))


class Selectors(unittest.TestCase):
    def test_parse_selector_accepts_both_forms(self):
        self.assertEqual(parse_selector("0xA9059CBB"), "0xa9059cbb")
        self.assertEqual(parse_selector("a9059cbb"), "0xa9059cbb")
        self.assertEqual(parse_selector("  0xa9059cbb  "), "0xa9059cbb")

    def test_parse_selector_rejects_wrong_widths(self):
        for given in ("0xa9059cb", "0xa9059cbbb", "", "0x", "0xzzzzzzzz", "9cbb"):
            with self.subTest(given):
                with self.assertRaises(AbiError):
                    parse_selector(given)

    def test_allowlist_mixes_selectors_and_signatures(self):
        label, pairs = load_selector_list(EXAMPLES / "allowlist.txt")
        self.assertEqual(label, "allowlist.txt")
        selectors = [selector for selector, _ in pairs]
        self.assertIn("0xa9059cbb", selectors)
        self.assertIn("0x18160ddd", selectors)
        self.assertEqual(len(pairs), 5)

    def test_allowlist_keeps_the_signature_as_the_origin(self):
        _, pairs = load_selector_list(EXAMPLES / "allowlist.txt")
        origins = dict(pairs)
        self.assertEqual(origins["0xa9059cbb"], "transfer(address,uint256)")
        self.assertEqual(origins["0x18160ddd"], "0x18160ddd")

    def test_allowlist_refuses_junk(self):
        with Temp() as tmp:
            with self.assertRaises(AbiError):
                load_selector_list(write(tmp, "a.txt", "0xa9059cbb\nnot a thing\n"))

    def test_allowlist_refuses_an_empty_list(self):
        with Temp() as tmp:
            with self.assertRaises(AbiError):
                load_selector_list(write(tmp, "a.txt", "# only a comment\n"))


if __name__ == "__main__":
    unittest.main()
