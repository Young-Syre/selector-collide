"""Rendering: determinism, JSON shape, and the no-findings case."""

from __future__ import annotations

import json
import unittest
from pathlib import Path

from selector_collide.abi import load_source
from selector_collide.analyse import Finding, analyse_shadowing, sort_findings
from selector_collide.report import (
    render_json,
    render_selectors_json,
    render_selectors_text,
    render_text,
)

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"

SAMPLE = [
    Finding("SC001", "high", "0x3659cfe6", "proxy shadows upgradeTo(address)",
            "a longer explanation that has to be wrapped onto several lines "
            "because it is prose and the terminal is only so wide",
            ("upgradeTo(address)",), ("proxy.json", "impl.json")),
    Finding("SC007", "info", None, "router declares a fallback", "short detail"),
]


class TextReport(unittest.TestCase):
    def test_the_mode_and_inputs_are_shown(self):
        text = render_text("proxy shadowing", SAMPLE, ["proxy.json", "impl.json"])
        self.assertIn("selector-collide: proxy shadowing", text)
        self.assertIn("input: proxy.json", text)
        self.assertIn("input: impl.json", text)

    def test_rules_severities_and_selectors_appear(self):
        text = render_text("m", SAMPLE, [])
        self.assertIn("SC001", text)
        self.assertIn("HIGH", text)
        self.assertIn("0x3659cfe6", text)
        self.assertIn("proxy-shadow", text)

    def test_a_finding_without_a_selector_is_rendered(self):
        text = render_text("m", SAMPLE, [])
        self.assertIn("--------", text)
        self.assertIn("SC007", text)

    def test_the_summary_counts_by_severity(self):
        text = render_text("m", SAMPLE, [])
        self.assertIn("2 findings: 1 high, 1 info", text)

    def test_one_finding_is_singular(self):
        text = render_text("m", SAMPLE[:1], [])
        self.assertIn("1 finding: 1 high", text)

    def test_no_findings_says_so(self):
        text = render_text("m", [], ["a.json"])
        self.assertIn("no collisions found", text)
        self.assertNotIn("HIGH", text)

    def test_long_details_are_wrapped(self):
        text = render_text("m", SAMPLE, [])
        for line in text.splitlines():
            with self.subTest(line=line[:30]):
                self.assertLessEqual(len(line), 90)

    def test_the_same_input_renders_identically(self):
        self.assertEqual(render_text("m", SAMPLE, ["a"]), render_text("m", SAMPLE, ["a"]))


class JsonReport(unittest.TestCase):
    def test_it_is_valid_json_with_the_expected_keys(self):
        document = json.loads(render_json("proxy shadowing", SAMPLE, ["a.json"]))
        self.assertEqual(document["tool"], "selector-collide")
        self.assertEqual(document["mode"], "proxy shadowing")
        self.assertEqual(document["inputs"], ["a.json"])
        self.assertEqual(len(document["findings"]), 2)

    def test_counts_cover_every_severity(self):
        document = json.loads(render_json("m", SAMPLE, []))
        self.assertEqual(document["counts"],
                         {"high": 1, "medium": 0, "low": 0, "info": 1})

    def test_findings_carry_the_full_record(self):
        document = json.loads(render_json("m", SAMPLE, []))
        first = document["findings"][0]
        self.assertEqual(first["rule"], "SC001")
        self.assertEqual(first["name"], "proxy-shadow")
        self.assertEqual(first["severity"], "high")
        self.assertEqual(first["selector"], "0x3659cfe6")
        self.assertEqual(first["sources"], ["proxy.json", "impl.json"])

    def test_a_null_selector_survives_the_round_trip(self):
        document = json.loads(render_json("m", SAMPLE, []))
        self.assertIsNone(document["findings"][1]["selector"])

    def test_extra_fields_are_merged(self):
        document = json.loads(render_json("m", [], [], {"seconds": 1.5}))
        self.assertEqual(document["seconds"], 1.5)

    def test_output_is_byte_identical_across_runs(self):
        self.assertEqual(render_json("m", SAMPLE, ["a"]), render_json("m", SAMPLE, ["a"]))

    def test_keys_are_sorted(self):
        rendered = render_json("m", [], [])
        document = json.loads(rendered)
        self.assertEqual(list(document.keys()), sorted(document.keys()))

    def test_the_example_run_is_reproducible(self):
        proxy = load_source(EXAMPLES / "proxy.json")
        implementation = load_source(EXAMPLES / "implementation.json")
        findings = sort_findings(analyse_shadowing(proxy, implementation))
        first = render_json("proxy shadowing", findings, ["proxy.json"])
        findings_again = sort_findings(analyse_shadowing(proxy, implementation))
        second = render_json("proxy shadowing", findings_again, ["proxy.json"])
        self.assertEqual(first, second)


class SelectorListing(unittest.TestCase):
    def setUp(self):
        self.sources = [load_source(EXAMPLES / "implementation.json")]

    def test_rows_are_sorted_by_selector(self):
        text = render_selectors_text(self.sources, include_errors=False)
        selectors = [line.split()[0] for line in text.strip().splitlines()]
        self.assertEqual(selectors, sorted(selectors))

    def test_errors_are_excluded_by_default(self):
        text = render_selectors_text(self.sources, include_errors=False)
        self.assertNotIn("InsufficientBalance", text)

    def test_errors_can_be_included(self):
        text = render_selectors_text(self.sources, include_errors=True)
        self.assertIn("InsufficientBalance(uint256,uint256)", text)
        self.assertIn("error", text)

    def test_modifiers_and_mutability_are_shown(self):
        text = render_selectors_text(self.sources, include_errors=False)
        self.assertIn("onlyOwner", text)
        self.assertIn("view", text)

    def test_the_source_is_shown_only_when_there_is_more_than_one(self):
        single = render_selectors_text(self.sources, False)
        self.assertNotIn("[implementation.json]", single)
        both = render_selectors_text(
            self.sources + [load_source(EXAMPLES / "proxy.json")], False)
        self.assertIn("[implementation.json]", both)
        self.assertIn("[proxy.json]", both)

    def test_json_listing_shape(self):
        document = json.loads(render_selectors_json(self.sources, False))
        self.assertEqual(document["mode"], "selectors")
        self.assertEqual(document["inputs"], ["implementation.json"])
        row = document["selectors"][0]
        self.assertEqual(
            sorted(row.keys()),
            ["kind", "modifiers", "selector", "signature", "source", "stateMutability"],
        )

    def test_an_empty_listing_does_not_crash(self):
        sources = [load_source(EXAMPLES / "clean-proxy.json")]
        text = render_selectors_text(sources, False)
        self.assertIn("proxyAdmin()", text)

    def test_a_source_with_only_a_fallback_reports_nothing(self):
        from selector_collide.abi import Source
        from selector_collide.signature import parse_signature
        empty = Source("x", (parse_signature("fallback()"),), "signatures")
        self.assertEqual(render_selectors_text([empty], False),
                         "no function entries found\n")


if __name__ == "__main__":
    unittest.main()
