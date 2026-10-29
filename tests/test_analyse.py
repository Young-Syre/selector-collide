"""The collision rules, against the example ABIs and hand-built sources."""

from __future__ import annotations

import unittest
from pathlib import Path

from selector_collide.abi import Source, load_selector_list, load_source
from selector_collide.analyse import (
    RULES,
    SEVERITY_ORDER,
    Finding,
    analyse_abi,
    analyse_allowlist,
    analyse_diamond,
    analyse_shadowing,
    sort_findings,
)
from selector_collide.signature import parse_signature

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"


def source(label: str, *signatures: str) -> Source:
    entries = tuple(parse_signature(s, label) for s in signatures)
    return Source(label, entries, "signatures")


def rules_of(findings: list[Finding]) -> list[str]:
    return [f.rule for f in findings]


class Shadowing(unittest.TestCase):
    def setUp(self):
        self.proxy = load_source(EXAMPLES / "proxy.json")
        self.implementation = load_source(EXAMPLES / "implementation.json")
        self.findings = analyse_shadowing(self.proxy, self.implementation)

    def test_the_three_shared_selectors_are_reported(self):
        shadowed = {f.selector for f in self.findings if f.rule == "SC001"}
        self.assertEqual(shadowed, {"0x3659cfe6", "0xe74b981b", "0x8da5cb5b"})

    def test_state_changing_shadowing_is_high(self):
        by_selector = {f.selector: f for f in self.findings if f.rule == "SC001"}
        self.assertEqual(by_selector["0x3659cfe6"].severity, "high")
        self.assertEqual(by_selector["0xe74b981b"].severity, "high")

    def test_view_shadowing_is_medium(self):
        by_selector = {f.selector: f for f in self.findings if f.rule == "SC001"}
        self.assertEqual(by_selector["0x8da5cb5b"].severity, "medium")

    def test_modifier_divergence_is_reported_for_both_guarded_pairs(self):
        divergent = {f.selector for f in self.findings if f.rule == "SC002"}
        self.assertEqual(divergent, {"0x3659cfe6", "0xe74b981b"})
        for finding in self.findings:
            if finding.rule == "SC002":
                self.assertEqual(finding.severity, "high")

    def test_modifier_divergence_names_both_modifiers(self):
        finding = next(f for f in self.findings
                       if f.rule == "SC002" and f.selector == "0x3659cfe6")
        self.assertIn("onlyAdmin", finding.detail)
        self.assertIn("onlyOwner", finding.detail)

    def test_mutability_divergence_only_where_it_differs(self):
        divergent = {f.selector for f in self.findings if f.rule == "SC003"}
        self.assertEqual(divergent, {"0xe74b981b"})

    def test_no_modifier_divergence_where_both_are_unguarded(self):
        selectors = {f.selector for f in self.findings if f.rule == "SC002"}
        self.assertNotIn("0x8da5cb5b", selectors)

    def test_a_clean_pair_reports_nothing(self):
        clean = analyse_shadowing(
            load_source(EXAMPLES / "clean-proxy.json"),
            load_source(EXAMPLES / "clean-implementation.json"),
        )
        self.assertEqual(clean, [])

    def test_a_proxy_without_a_fallback_is_noted(self):
        proxy = source("proxy", "owner() view")
        implementation = source("impl", "deposit(uint256)")
        findings = analyse_shadowing(proxy, implementation)
        self.assertEqual(rules_of(findings), ["SC006"])
        self.assertEqual(findings[0].severity, "info")
        self.assertIsNone(findings[0].selector)

    def test_a_proxy_with_a_fallback_is_not_noted(self):
        proxy = source("proxy", "owner() view", "fallback()")
        implementation = source("impl", "deposit(uint256)")
        self.assertEqual(analyse_shadowing(proxy, implementation), [])

    def test_different_names_can_shadow(self):
        proxy = source("proxy", "collate_propagate_storage(bytes16) onlyMigrator",
                       "fallback()")
        implementation = source("impl", "burn(uint256)")
        findings = analyse_shadowing(proxy, implementation)
        self.assertEqual(rules_of(findings), ["SC001", "SC002"])
        self.assertEqual(findings[0].selector, "0x42966c68")
        self.assertEqual(findings[0].severity, "high")

    def test_findings_name_both_sources(self):
        for finding in self.findings:
            with self.subTest(finding.rule):
                self.assertIn("proxy.json", finding.sources)

    def test_selectors_are_lowercase_hex(self):
        for finding in self.findings:
            if finding.selector:
                with self.subTest(finding.selector):
                    self.assertRegex(finding.selector, r"^0x[0-9a-f]{8}$")


class Diamond(unittest.TestCase):
    def setUp(self):
        self.facets = [
            load_source(EXAMPLES / name) for name in (
                "diamond-facet-ownership.json",
                "diamond-facet-token.json",
                "diamond-facet-legacy.json",
            )
        ]
        self.findings = analyse_diamond(self.facets)

    def test_the_one_clash_is_found(self):
        clashes = [f for f in self.findings if f.rule == "SC004"]
        self.assertEqual(len(clashes), 1)
        self.assertEqual(clashes[0].selector, "0x42966c68")
        self.assertEqual(clashes[0].severity, "high")

    def test_the_clash_names_both_facets(self):
        clash = next(f for f in self.findings if f.rule == "SC004")
        self.assertEqual(
            set(clash.sources),
            {"diamond-facet-token.json", "diamond-facet-legacy.json"},
        )
        self.assertEqual(
            set(clash.signatures),
            {"burn(uint256)", "collate_propagate_storage(bytes16)"},
        )

    def test_the_unclashing_facet_is_not_blamed(self):
        clash = next(f for f in self.findings if f.rule == "SC004")
        self.assertNotIn("diamond-facet-ownership.json", clash.sources)

    def test_disjoint_facets_are_clean(self):
        facets = [
            source("a", "owner() view"),
            source("b", "deposit(uint256)"),
            source("c", "withdraw(uint256)"),
        ]
        self.assertEqual(analyse_diamond(facets), [])

    def test_three_facets_claiming_one_selector(self):
        facets = [
            source("a", "burn(uint256)"),
            source("b", "collate_propagate_storage(bytes16)"),
            source("c", "burn(uint256)"),
        ]
        findings = analyse_diamond(facets)
        clash = next(f for f in findings if f.rule == "SC004")
        self.assertEqual(len(clash.sources), 3)
        self.assertIn("3 facets", clash.title)

    def test_the_same_facet_twice_is_not_a_clash_with_itself(self):
        facet = source("a", "burn(uint256)")
        self.assertEqual([f for f in analyse_diamond([facet]) if f.rule == "SC004"], [])


class SingleAbi(unittest.TestCase):
    def test_duplicate_selectors_in_one_abi(self):
        merged = source("merged.txt", "burn(uint256)",
                        "collate_propagate_storage(bytes16)")
        findings = analyse_abi(merged)
        self.assertEqual(rules_of(findings), ["SC005"])
        self.assertEqual(findings[0].severity, "high")
        self.assertEqual(findings[0].selector, "0x42966c68")
        self.assertEqual(len(findings[0].signatures), 2)

    def test_the_same_signature_twice_is_not_a_duplicate_selector(self):
        repeated = source("a.txt", "burn(uint256)", "burn(uint256)")
        self.assertEqual([f for f in analyse_abi(repeated) if f.rule == "SC005"], [])

    def test_a_function_and_an_error_colliding_is_medium(self):
        mixed = source("a.txt", "burn(uint256)",
                       "error collate_propagate_storage(bytes16)")
        findings = analyse_abi(mixed, include_errors=True)
        self.assertEqual(rules_of(findings), ["SC005"])
        self.assertEqual(findings[0].severity, "medium")
        self.assertIn("decoded unambiguously", findings[0].detail)

    def test_errors_are_excluded_unless_asked_for(self):
        mixed = source("a.txt", "burn(uint256)",
                       "error collate_propagate_storage(bytes16)")
        self.assertEqual(analyse_abi(mixed, include_errors=False), [])

    def test_an_open_fallback_is_noted(self):
        router = source("router.txt", "owner() view", "fallback()")
        findings = analyse_abi(router)
        self.assertEqual(rules_of(findings), ["SC007"])
        self.assertEqual(findings[0].severity, "info")

    def test_a_receive_is_mentioned_alongside_the_fallback(self):
        router = source("router.txt", "fallback()", "receive()")
        finding = analyse_abi(router)[0]
        self.assertIn("receive", finding.detail)

    def test_fallback_notes_can_be_suppressed(self):
        router = source("router.txt", "fallback()")
        self.assertEqual(analyse_abi(router, include_fallback_notes=False), [])

    def test_the_example_router_surface_is_an_open_fallback(self):
        findings = analyse_abi(load_source(EXAMPLES / "router-surface.txt"))
        self.assertEqual(rules_of(findings), ["SC007"])


class Allowlist(unittest.TestCase):
    def setUp(self):
        self.label, self.pairs = load_selector_list(EXAMPLES / "allowlist.txt")
        self.findings = analyse_allowlist(self.label, self.pairs)

    def test_every_entry_produces_a_finding(self):
        self.assertEqual(len(self.findings), len(self.pairs))
        for finding in self.findings:
            self.assertEqual(finding.rule, "SC008")

    def test_a_published_collision_escalates_to_high(self):
        by_selector = {f.selector: f for f in self.findings}
        self.assertEqual(by_selector["0xa9059cbb"].severity, "high")
        self.assertEqual(by_selector["0x42966c68"].severity, "high")
        self.assertIn("many_msg_babbage(bytes1)", by_selector["0xa9059cbb"].detail)

    def test_an_unknown_selector_stays_medium(self):
        by_selector = {f.selector: f for f in self.findings}
        self.assertEqual(by_selector["0x095ea7b3"].severity, "medium")
        self.assertIn("2**32", by_selector["0x095ea7b3"].detail)

    def test_a_rate_turns_the_search_into_wall_clock_time(self):
        with_rate = analyse_allowlist(self.label, self.pairs, hash_rate=9000.0)
        medium = next(f for f in with_rate if f.severity == "medium")
        self.assertIn("days on one core", medium.detail)

    def test_without_a_rate_no_time_is_claimed(self):
        medium = next(f for f in self.findings if f.severity == "medium")
        self.assertNotIn("days", medium.detail)

    def test_duplicate_selectors_are_reported_once(self):
        findings = analyse_allowlist("a", [("0xa9059cbb", "transfer(address,uint256)"),
                                           ("0xa9059cbb", "0xa9059cbb")])
        self.assertEqual(len(findings), 1)


class Ordering(unittest.TestCase):
    def test_sort_is_by_severity_then_rule_then_selector(self):
        findings = [
            Finding("SC007", "info", None, "z", ""),
            Finding("SC001", "medium", "0xffffffff", "a", ""),
            Finding("SC001", "high", "0x00000002", "b", ""),
            Finding("SC001", "high", "0x00000001", "c", ""),
            Finding("SC002", "high", "0x00000003", "d", ""),
        ]
        ordered = sort_findings(findings)
        self.assertEqual(
            [(f.rule, f.severity, f.selector) for f in ordered],
            [
                ("SC001", "high", "0x00000001"),
                ("SC001", "high", "0x00000002"),
                ("SC002", "high", "0x00000003"),
                ("SC001", "medium", "0xffffffff"),
                ("SC007", "info", None),
            ],
        )

    def test_sorting_is_stable_across_calls(self):
        findings = analyse_shadowing(
            load_source(EXAMPLES / "proxy.json"),
            load_source(EXAMPLES / "implementation.json"),
        )
        first = [f.as_dict() for f in sort_findings(list(findings))]
        second = [f.as_dict() for f in sort_findings(list(reversed(findings)))]
        self.assertEqual(first, second)

    def test_every_rule_id_has_a_name(self):
        for rule in ("SC001", "SC002", "SC003", "SC004",
                     "SC005", "SC006", "SC007", "SC008"):
            with self.subTest(rule):
                self.assertIn(rule, RULES)

    def test_severities_are_from_the_known_set(self):
        findings = analyse_diamond([
            load_source(EXAMPLES / "diamond-facet-token.json"),
            load_source(EXAMPLES / "diamond-facet-legacy.json"),
        ])
        for finding in findings:
            with self.subTest(finding.rule):
                self.assertIn(finding.severity, SEVERITY_ORDER)

    def test_as_dict_is_json_shaped(self):
        finding = Finding("SC001", "high", "0xa9059cbb", "title", "detail",
                          ("a",), ("b",))
        self.assertEqual(finding.as_dict(), {
            "rule": "SC001",
            "name": "proxy-shadow",
            "severity": "high",
            "selector": "0xa9059cbb",
            "title": "title",
            "detail": "detail",
            "signatures": ["a"],
            "sources": ["b"],
        })


if __name__ == "__main__":
    unittest.main()
