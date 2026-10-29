"""The command line: modes, output shapes, and the documented exit codes."""

from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from selector_collide import exitcodes
from selector_collide.cli import main

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"


def run(*argv: str) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    code = main(list(argv), out=out, err=err)
    return code, out.getvalue(), err.getvalue()


class Shadowing(unittest.TestCase):
    def test_the_mode_flags_work_without_naming_the_command(self):
        code, out, _ = run("--proxy", str(EXAMPLES / "proxy.json"),
                           "--implementation", str(EXAMPLES / "implementation.json"))
        self.assertEqual(code, exitcodes.FINDINGS)
        self.assertIn("proxy shadowing", out)

    def test_naming_the_command_is_equivalent(self):
        without = run("--proxy", str(EXAMPLES / "proxy.json"),
                      "--implementation", str(EXAMPLES / "implementation.json"))
        with_name = run("check", "--proxy", str(EXAMPLES / "proxy.json"),
                        "--implementation", str(EXAMPLES / "implementation.json"))
        self.assertEqual(without, with_name)

    def test_the_impl_alias_is_accepted(self):
        code, _, _ = run("--proxy", str(EXAMPLES / "proxy.json"),
                         "--impl", str(EXAMPLES / "implementation.json"))
        self.assertEqual(code, exitcodes.FINDINGS)

    def test_the_expected_findings_are_reported(self):
        _, out, _ = run("--proxy", str(EXAMPLES / "proxy.json"),
                        "--implementation", str(EXAMPLES / "implementation.json"))
        self.assertIn("SC001", out)
        self.assertIn("SC002", out)
        self.assertIn("SC003", out)
        self.assertIn("0x3659cfe6", out)
        self.assertIn("6 findings", out)

    def test_a_clean_pair_exits_zero_and_says_nothing_was_found(self):
        code, out, _ = run("--proxy", str(EXAMPLES / "clean-proxy.json"),
                           "--implementation", str(EXAMPLES / "clean-implementation.json"))
        self.assertEqual(code, exitcodes.OK)
        self.assertIn("no collisions found", out)

    def test_json_output_is_parseable(self):
        _, out, _ = run("--proxy", str(EXAMPLES / "proxy.json"),
                        "--implementation", str(EXAMPLES / "implementation.json"),
                        "--json")
        document = json.loads(out)
        self.assertEqual(document["counts"]["high"], 4)
        self.assertEqual(document["counts"]["medium"], 2)
        self.assertEqual(len(document["findings"]), 6)

    def test_proxy_without_implementation_is_a_usage_error(self):
        code, _, err = run("--proxy", str(EXAMPLES / "proxy.json"))
        self.assertEqual(code, exitcodes.USAGE)
        self.assertIn("together", err)

    def test_two_modes_at_once_is_a_usage_error(self):
        code, _, err = run("--abi", str(EXAMPLES / "proxy.json"),
                           "--diamond", str(EXAMPLES / "proxy.json"),
                           str(EXAMPLES / "implementation.json"))
        self.assertEqual(code, exitcodes.USAGE)
        self.assertIn("exactly one mode", err)

    def test_no_mode_at_all_is_a_usage_error(self):
        code, _, err = run("check")
        self.assertEqual(code, exitcodes.USAGE)
        self.assertIn("exactly one mode", err)


class Diamond(unittest.TestCase):
    def test_one_clash_is_reported(self):
        code, out, _ = run(
            "--diamond",
            str(EXAMPLES / "diamond-facet-ownership.json"),
            str(EXAMPLES / "diamond-facet-token.json"),
            str(EXAMPLES / "diamond-facet-legacy.json"),
        )
        self.assertEqual(code, exitcodes.FINDINGS)
        self.assertIn("SC004", out)
        self.assertIn("0x42966c68", out)
        self.assertIn("1 finding", out)

    def test_one_facet_is_a_usage_error(self):
        code, _, err = run("--diamond", str(EXAMPLES / "diamond-facet-token.json"))
        self.assertEqual(code, exitcodes.USAGE)
        self.assertIn("at least two", err)

    def test_two_clean_facets_exit_zero(self):
        code, _, _ = run("--diamond",
                         str(EXAMPLES / "diamond-facet-ownership.json"),
                         str(EXAMPLES / "diamond-facet-token.json"))
        self.assertEqual(code, exitcodes.OK)


class SingleAbi(unittest.TestCase):
    def test_a_router_surface_reports_its_open_fallback(self):
        code, out, _ = run("--abi", str(EXAMPLES / "router-surface.txt"))
        self.assertEqual(code, exitcodes.OK)  # info is below the default threshold
        self.assertIn("SC007", out)

    def test_info_findings_can_be_made_to_fail(self):
        code, _, _ = run("--abi", str(EXAMPLES / "router-surface.txt"),
                         "--fail-on", "info")
        self.assertEqual(code, exitcodes.FINDINGS)

    def test_fail_on_never_always_exits_zero(self):
        code, _, _ = run("--proxy", str(EXAMPLES / "proxy.json"),
                         "--implementation", str(EXAMPLES / "implementation.json"),
                         "--fail-on", "never")
        self.assertEqual(code, exitcodes.OK)

    def test_fail_on_high_ignores_medium(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "mixed.txt"
            path.write_text("burn(uint256)\nerror collate_propagate_storage(bytes16)\n")
            code, out, _ = run("--abi", str(path), "--include-errors",
                               "--fail-on", "high")
            self.assertIn("MEDIUM", out)
            self.assertEqual(code, exitcodes.OK)

    def test_several_abis_at_once(self):
        code, out, _ = run("--abi", str(EXAMPLES / "proxy.json"),
                           str(EXAMPLES / "implementation.json"))
        self.assertEqual(code, exitcodes.OK)
        self.assertIn("proxy.json", out)
        self.assertIn("implementation.json", out)


class InputErrors(unittest.TestCase):
    def test_a_missing_file_exits_three(self):
        code, _, err = run("--abi", "definitely-not-here.json")
        self.assertEqual(code, exitcodes.INPUT)
        self.assertIn("cannot read", err)

    def test_invalid_json_exits_three(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bad.json"
            path.write_text("[{,}]")
            code, _, err = run("--abi", str(path))
        self.assertEqual(code, exitcodes.INPUT)
        self.assertIn("invalid JSON", err)

    def test_a_missing_proxy_exits_three(self):
        code, _, _ = run("--proxy", "nope.json",
                         "--implementation", str(EXAMPLES / "implementation.json"))
        self.assertEqual(code, exitcodes.INPUT)

    def test_a_bad_allowlist_exits_three(self):
        code, _, _ = run("allowlist", "nope.txt")
        self.assertEqual(code, exitcodes.INPUT)


class Selectors(unittest.TestCase):
    def test_listing_is_sorted_and_exits_zero(self):
        code, out, _ = run("selectors", str(EXAMPLES / "implementation.json"))
        self.assertEqual(code, exitcodes.OK)
        lines = out.strip().splitlines()
        self.assertEqual([line.split()[0] for line in lines],
                         sorted(line.split()[0] for line in lines))
        self.assertIn("0xa9059cbb", run("selectors",
                                        str(EXAMPLES / "diamond-facet-token.json"))[1])

    def test_json_listing(self):
        _, out, _ = run("selectors", str(EXAMPLES / "implementation.json"), "--json")
        document = json.loads(out)
        self.assertEqual(document["mode"], "selectors")
        self.assertGreater(len(document["selectors"]), 5)

    def test_errors_are_opt_in(self):
        _, without, _ = run("selectors", str(EXAMPLES / "implementation.json"))
        _, with_errors, _ = run("selectors", str(EXAMPLES / "implementation.json"),
                                "--include-errors")
        self.assertNotIn("InsufficientBalance", without)
        self.assertIn("InsufficientBalance", with_errors)

    def test_several_files_are_labelled(self):
        _, out, _ = run("selectors", str(EXAMPLES / "proxy.json"),
                        str(EXAMPLES / "implementation.json"))
        self.assertIn("[proxy.json]", out)
        self.assertIn("[implementation.json]", out)


class Allowlist(unittest.TestCase):
    def test_the_example_allowlist_reports_published_collisions(self):
        code, out, _ = run("allowlist", str(EXAMPLES / "allowlist.txt"))
        self.assertEqual(code, exitcodes.FINDINGS)
        self.assertIn("SC008", out)
        self.assertIn("many_msg_babbage(bytes1)", out)
        self.assertIn("collate_propagate_storage(bytes16)", out)

    def test_a_rate_adds_wall_clock_time(self):
        _, out, _ = run("allowlist", str(EXAMPLES / "allowlist.txt"), "--rate", "9000")
        self.assertIn("days on one core", out)

    def test_json_output(self):
        _, out, _ = run("allowlist", str(EXAMPLES / "allowlist.txt"), "--json")
        document = json.loads(out)
        self.assertEqual(document["mode"], "allowlist")
        self.assertEqual(document["counts"]["high"], 2)


class Find(unittest.TestCase):
    def test_a_partial_match_is_found_and_labelled_as_not_a_collision(self):
        code, out, _ = run("find", "0xa9059cbb", "--bits", "8", "--max", "100000")
        self.assertEqual(code, exitcodes.OK)
        self.assertIn("partial match", out)
        self.assertIn("is not a collision", out)

    def test_an_exhausted_budget_exits_four(self):
        code, out, _ = run("find", "0xa9059cbb", "--max", "200")
        self.assertEqual(code, exitcodes.NOT_FOUND)
        self.assertIn("no match after 200 candidates", out)

    def test_an_exhausted_search_extrapolates(self):
        _, out, _ = run("find", "0xa9059cbb", "--max", "200")
        self.assertIn("days on one core", out)
        self.assertIn("2,977,044,471", out)

    def test_scientific_notation_for_the_budget(self):
        code, _, _ = run("find", "0xa9059cbb", "--bits", "4", "--max", "1e3")
        self.assertEqual(code, exitcodes.OK)

    def test_params_builds_the_template(self):
        _, out, _ = run("find", "0xa9059cbb", "--bits", "8",
                        "--params", "address,uint256", "--max", "100000")
        self.assertIn("(address,uint256)", out)

    def test_template_and_params_together_are_a_usage_error(self):
        code, _, err = run("find", "0xa9059cbb", "--template", "f{}()",
                           "--params", "uint256")
        self.assertEqual(code, exitcodes.USAGE)
        self.assertIn("cannot both be given", err)

    def test_a_bad_selector_is_a_usage_error(self):
        code, _, err = run("find", "0xnothex")
        self.assertEqual(code, exitcodes.USAGE)
        self.assertIn("not a 4-byte selector", err)

    def test_a_bad_budget_is_a_usage_error(self):
        code, _, _ = run("find", "0xa9059cbb", "--max", "many")
        self.assertEqual(code, exitcodes.USAGE)

    def test_a_bad_bit_width_is_a_usage_error(self):
        code, _, _ = run("find", "0xa9059cbb", "--bits", "40", "--max", "10")
        self.assertEqual(code, exitcodes.USAGE)

    def test_json_output_carries_the_arithmetic(self):
        _, out, _ = run("find", "0xa9059cbb", "--max", "200", "--json")
        document = json.loads(out)
        self.assertFalse(document["found"])
        self.assertEqual(document["tried"], 200)
        self.assertEqual(document["expected_candidates_full_32_bit"], 4294967296)
        self.assertEqual(document["median_candidates_full_32_bit"], 2977044471)

    def test_a_found_signature_is_verified_in_the_output(self):
        _, out, _ = run("find", "0xa9059cbb", "--bits", "8",
                        "--max", "100000", "--json")
        document = json.loads(out)
        self.assertTrue(document["found"])
        self.assertEqual(document["selector"][:4], document["target"][:4])


class Collide(unittest.TestCase):
    def test_a_tiny_budget_exits_four(self):
        code, out, _ = run("collide", "--max", "100")
        self.assertEqual(code, exitcodes.NOT_FOUND)
        self.assertIn("no colliding pair", out)

    def test_json_output_shape(self):
        _, out, _ = run("collide", "--max", "100", "--json")
        document = json.loads(out)
        self.assertEqual(document["mode"], "collide")
        self.assertFalse(document["found"])
        self.assertEqual(document["signatures"], [])


class Benchmark(unittest.TestCase):
    def test_it_reports_a_rate(self):
        code, out, _ = run("benchmark", "--count", "500")
        self.assertEqual(code, exitcodes.OK)
        self.assertIn("hashed 500 candidate signatures", out)
        self.assertIn("median 32-bit search", out)

    def test_json_output(self):
        _, out, _ = run("benchmark", "--count", "500", "--json")
        document = json.loads(out)
        self.assertEqual(document["hashed"], 500)
        self.assertGreater(document["rate_per_second"], 0)
        self.assertEqual(document["median_candidates_32_bit"], 2977044471)

    def test_a_bad_count_is_a_usage_error(self):
        code, _, _ = run("benchmark", "--count", "none")
        self.assertEqual(code, exitcodes.USAGE)


class Selftest(unittest.TestCase):
    def test_every_vector_passes(self):
        code, out, _ = run("selftest")
        self.assertEqual(code, exitcodes.OK)
        self.assertIn("0 failed", out)
        self.assertNotIn("FAIL", out)

    def test_the_empty_string_vector_is_among_the_checks(self):
        _, out, _ = run("selftest")
        self.assertIn("empty string", out)

    def test_json_output_lists_every_check(self):
        _, out, _ = run("selftest", "--json")
        document = json.loads(out)
        self.assertEqual(document["failed"], 0)
        self.assertGreaterEqual(document["checks"], 20)
        self.assertTrue(all(result["ok"] for result in document["results"]))


class Help(unittest.TestCase):
    def test_bare_invocation_prints_help_and_exits_two(self):
        code, out, _ = run()
        self.assertEqual(code, exitcodes.USAGE)
        self.assertIn("usage:", out)

    def test_help_documents_the_exit_codes_and_the_absence_of_network_access(self):
        # argparse writes --help to the real stdout, so capture that too.
        captured = io.StringIO()
        with contextlib.redirect_stdout(captured):
            code = main(["--help"], out=captured, err=captured)
        self.assertEqual(code, 0)
        text = captured.getvalue()
        self.assertIn("exit codes:", text)
        self.assertIn("0  ran to completion", text)
        self.assertIn("4  a search ran its whole budget", text)
        self.assertIn("does not open a network connection", text.replace(
            "No command here opens a network connection",
            "does not open a network connection"))

    def test_every_subcommand_has_help(self):
        for command in ("check", "selectors", "find", "collide",
                        "allowlist", "benchmark", "selftest"):
            with self.subTest(command):
                captured = io.StringIO()
                with contextlib.redirect_stdout(captured):
                    code = main([command, "--help"], out=captured, err=captured)
                self.assertEqual(code, 0)
                self.assertIn("usage: selector-collide", captured.getvalue())

    def test_the_version_flag_reports_the_package_version(self):
        from selector_collide import __version__
        captured = io.StringIO()
        with contextlib.redirect_stdout(captured):
            code = main(["--version"], out=captured, err=captured)
        self.assertEqual(code, 0)
        self.assertIn(__version__, captured.getvalue())

    def test_exit_code_table_is_complete(self):
        for code in (exitcodes.OK, exitcodes.FINDINGS, exitcodes.USAGE,
                     exitcodes.INPUT, exitcodes.NOT_FOUND):
            with self.subTest(code=code):
                self.assertIn(code, exitcodes.DESCRIPTIONS)


if __name__ == "__main__":
    unittest.main()
