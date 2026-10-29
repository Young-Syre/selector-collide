"""Command line interface.

The three analysis modes live under ``check``, which is also the default, so
``selector-collide --proxy p.json --implementation i.json`` and
``selector-collide check --proxy p.json --implementation i.json`` are the same
command. The searches, the benchmark and the self-test are separate
subcommands because they do not read ABIs and do not produce findings.
"""

from __future__ import annotations

import argparse
import sys

from . import __version__
from .abi import AbiError, load_selector_list, load_source, parse_selector
from .analyse import (
    SEVERITY_ORDER,
    Finding,
    analyse_abi,
    analyse_allowlist,
    analyse_diamond,
    analyse_shadowing,
    sort_findings,
)
from .exitcodes import FINDINGS, INPUT, NOT_FOUND, OK, USAGE
from .keccak import keccak256, keccak256_hex, selector_hex
from .known import KNOWN_COLLISIONS
from .report import render_json, render_selectors_json, render_selectors_text, render_text
from .search import (
    DEFAULT_ALPHABET,
    SearchError,
    benchmark,
    expected_candidates,
    find_birthday_pair,
    find_preimage,
    median_candidates,
    parse_count,
)
from .vectors import BOUNDARY_VECTORS, DIGEST_VECTORS, SELECTOR_VECTORS, SLOT_VECTORS

__all__ = ["main", "run", "build_parser"]

_FAIL_ON_CHOICES = ("high", "medium", "low", "info", "never")

_EPILOG = """\
exit codes:
  0  ran to completion with nothing at or above the fail threshold
  1  at least one finding at or above the fail threshold (see --fail-on)
  2  usage error
  3  input error: a file was missing, unreadable, or not a usable ABI
  4  a search ran its whole budget without finding a collision

No command here opens a network connection. ABIs are read from local files;
there is no explorer lookup and no RPC call.
"""


def _add_output_flags(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--json", action="store_true", help="emit JSON instead of text")


def _add_fail_flag(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--fail-on",
        choices=_FAIL_ON_CHOICES,
        default="low",
        help="lowest severity that makes the command exit 1 (default: low; "
             "'never' always exits 0 when the run completed)",
    )


def _add_search_flags(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--max", dest="budget", default="1000000", metavar="N",
        help="candidate budget; accepts 1e8, 100_000_000 and 2**32 (default: 1000000)",
    )
    parser.add_argument(
        "--template", default=None, metavar="SIG",
        help="signature template with one {} for the generated part of the name "
             "(default: 'f{}()', or 'f{}(<params>)' when --params is given)",
    )
    parser.add_argument(
        "--params", default=None, metavar="TYPES",
        help="comma-separated parameter types for the default template, e.g. "
             "'address,uint256'; mutually exclusive with --template",
    )
    parser.add_argument(
        "--alphabet", default=DEFAULT_ALPHABET, metavar="CHARS",
        help="characters the generated part of the name is built from "
             "(default: a-z0-9)",
    )
    parser.add_argument(
        "--progress", action="store_true",
        help="write progress to stderr while searching",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="selector-collide",
        description=(
            "Find EVM function-selector collisions: proxy shadowing, diamond "
            "facet clashes, duplicate selectors in one ABI, and selector-keyed "
            "allowlists."
        ),
        epilog=_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"selector-collide {__version__}")
    subparsers = parser.add_subparsers(dest="command")

    check = subparsers.add_parser(
        "check",
        help="analyse ABIs for collisions (the default command)",
        description=(
            "Analyse one or more local ABIs. Exactly one mode must be chosen: "
            "--proxy with --implementation, or --diamond, or --abi."
        ),
        epilog=_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    check.add_argument("--proxy", metavar="ABI", help="the proxy's own ABI")
    check.add_argument(
        "--implementation", "--impl", dest="implementation", metavar="ABI",
        help="the implementation ABI the proxy delegates to",
    )
    check.add_argument(
        "--diamond", nargs="+", metavar="ABI", default=None,
        help="two or more EIP-2535 facet ABIs to check for clashes",
    )
    check.add_argument(
        "--abi", nargs="+", metavar="ABI", default=None,
        help="one or more ABIs to check on their own for duplicate selectors",
    )
    check.add_argument(
        "--include-errors", action="store_true",
        help="include custom errors, which share the 4-byte space for decoding "
             "even though they are never dispatched to",
    )
    _add_fail_flag(check)
    _add_output_flags(check)

    selectors = subparsers.add_parser(
        "selectors", help="list the selector of every entry in the given files",
    )
    selectors.add_argument("files", nargs="+", metavar="ABI")
    selectors.add_argument("--include-errors", action="store_true")
    _add_output_flags(selectors)

    find = subparsers.add_parser(
        "find",
        help="search for a signature with a given selector",
        description=(
            "Brute-force a short synthetic signature whose selector matches the "
            "target. A selector is 32 bits, so a uniform search expects 2**32 "
            "candidates; run 'selector-collide benchmark' to see what that costs "
            "here. Expect this to exhaust its budget without a hit unless the "
            "budget is of that order."
        ),
        epilog=_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    find.add_argument("selector", help="the 4-byte selector to match, e.g. 0xa9059cbb")
    find.add_argument(
        "--bits", type=int, default=32, metavar="N",
        help="compare only the top N bits of the selector (default: 32, a true "
             "collision). A lower value finds a partial match in proportionally "
             "less work, for calibration; it is not a collision.",
    )
    _add_search_flags(find)
    _add_output_flags(find)

    collide = subparsers.add_parser(
        "collide",
        help="search for any two signatures that share a selector (birthday search)",
        description=(
            "Find a colliding pair rather than a preimage. Among n candidates "
            "the expected number of colliding pairs is about n**2 / 2**33, so a "
            "50% chance needs roughly 77,000 candidates -- seconds of work, "
            "against days for a chosen target."
        ),
        epilog=_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    _add_search_flags(collide)
    _add_output_flags(collide)

    allowlist = subparsers.add_parser(
        "allowlist",
        help="assess an allowlist that is keyed on selectors",
        description=(
            "Read a list of allowed selectors or signatures and report, for "
            "each, whether a different signature could satisfy the same check."
        ),
        epilog=_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    allowlist.add_argument("file", metavar="FILE", help="one selector or signature per line")
    allowlist.add_argument(
        "--rate", type=float, default=None, metavar="HPS",
        help="hash rate in candidates per second, used to turn the search size "
             "into wall-clock time; get one from 'selector-collide benchmark'",
    )
    _add_fail_flag(allowlist)
    _add_output_flags(allowlist)

    bench = subparsers.add_parser(
        "benchmark", help="measure the selector hash rate of this machine",
    )
    bench.add_argument("--count", default="200000", metavar="N", help="candidates to hash")
    bench.add_argument("--template", default="f{}(address,uint256)", metavar="SIG")
    _add_output_flags(bench)

    selftest = subparsers.add_parser(
        "selftest", help="check the Keccak-256 implementation against committed vectors",
    )
    _add_output_flags(selftest)

    return parser


def _resolve_template(args) -> str:
    if args.template is not None and args.params is not None:
        raise SearchError("--template and --params cannot both be given")
    if args.template is not None:
        return args.template
    if args.params is not None:
        params = ",".join(p.strip() for p in args.params.split(",") if p.strip())
        return f"f{{}}({params})"
    return "f{}()"


def _threshold(fail_on: str) -> int:
    """The highest severity rank that still fails. Lower rank means worse."""
    if fail_on == "never":
        return -1  # no severity ranks at or below this, so nothing fails
    return SEVERITY_ORDER[fail_on]


def _exit_for(findings: list[Finding], fail_on: str) -> int:
    limit = _threshold(fail_on)
    worst = min((SEVERITY_ORDER.get(f.severity, 99) for f in findings), default=99)
    return FINDINGS if worst <= limit else OK


def _progress_writer(stream):
    def write(tried: int, elapsed: float) -> None:
        rate = tried / elapsed if elapsed else 0.0
        print(f"  tried {tried:,} in {elapsed:,.1f}s ({rate:,.0f}/s)", file=stream)
    return write


def _cmd_check(args, out, err) -> int:
    chosen = [
        name for name, value in (
            ("proxy/implementation", args.proxy or args.implementation),
            ("diamond", args.diamond),
            ("abi", args.abi),
        ) if value
    ]
    if len(chosen) != 1:
        print(
            "error: choose exactly one mode: --proxy with --implementation, "
            "--diamond, or --abi",
            file=err,
        )
        return USAGE
    if bool(args.proxy) != bool(args.implementation):
        print("error: --proxy and --implementation must be given together", file=err)
        return USAGE

    try:
        if args.proxy:
            proxy = load_source(args.proxy)
            implementation = load_source(args.implementation)
            mode = "proxy shadowing"
            inputs = [f"proxy {proxy.label} ({proxy.fmt})",
                      f"implementation {implementation.label} ({implementation.fmt})"]
            findings = analyse_shadowing(proxy, implementation)
            findings += analyse_abi(proxy, args.include_errors, include_fallback_notes=False)
            findings += analyse_abi(implementation, args.include_errors)
        elif args.diamond:
            if len(args.diamond) < 2:
                print("error: --diamond needs at least two facet ABIs", file=err)
                return USAGE
            sources = [load_source(path) for path in args.diamond]
            mode = "diamond facet clash"
            inputs = [f"facet {s.label} ({s.fmt})" for s in sources]
            findings = analyse_diamond(sources)
        else:
            sources = [load_source(path) for path in args.abi]
            mode = "single ABI"
            inputs = [f"{s.label} ({s.fmt})" for s in sources]
            findings = []
            for source in sources:
                findings += analyse_abi(source, args.include_errors)
    except AbiError as exc:
        print(f"error: {exc}", file=err)
        return INPUT

    findings = sort_findings(findings)
    if args.json:
        print(render_json(mode, findings, inputs), file=out)
    else:
        print(render_text(mode, findings, inputs), file=out, end="")
    return _exit_for(findings, args.fail_on)


def _cmd_selectors(args, out, err) -> int:
    try:
        sources = [load_source(path) for path in args.files]
    except AbiError as exc:
        print(f"error: {exc}", file=err)
        return INPUT
    if args.json:
        print(render_selectors_json(sources, args.include_errors), file=out)
    else:
        print(render_selectors_text(sources, args.include_errors), file=out, end="")
    return OK


def _cmd_find(args, out, err) -> int:
    try:
        target = parse_selector(args.selector)
        template = _resolve_template(args)
        budget = parse_count(args.budget)
    except (AbiError, SearchError) as exc:
        print(f"error: {exc}", file=err)
        return USAGE

    try:
        result = find_preimage(
            target,
            template=template,
            alphabet=args.alphabet,
            budget=budget,
            bits=args.bits,
            progress=_progress_writer(err) if args.progress else None,
        )
    except SearchError as exc:
        print(f"error: {exc}", file=err)
        return USAGE

    if args.json:
        import json as _json
        print(_json.dumps({
            "tool": "selector-collide",
            "mode": "find",
            "target": result.target,
            "bits": result.bits,
            "template": result.template,
            "alphabet": result.alphabet,
            "tried": result.tried,
            "budget": result.budget,
            "seconds": round(result.elapsed, 3),
            "rate_per_second": round(result.rate, 1),
            "found": result.found,
            "signature": result.signature,
            "selector": selector_hex(result.signature) if result.signature else None,
            "expected_candidates_full_32_bit": expected_candidates(32),
            "median_candidates_full_32_bit": median_candidates(32),
        }, indent=2, sort_keys=True), file=out)
    elif result.found:
        exact = result.bits == 32
        print(f"found {'collision' if exact else 'partial match'} after "
              f"{result.tried:,} candidates in {result.elapsed:,.1f}s "
              f"({result.rate:,.0f}/s)", file=out)
        print(f"  signature  {result.signature}", file=out)
        print(f"  selector   {selector_hex(result.signature)}", file=out)
        print(f"  target     {result.target}", file=out)
        if not exact:
            print(f"  NOTE: only the top {result.bits} bits were compared, so this "
                  f"is not a collision. A full 32-bit match needs about "
                  f"{2 ** (32 - result.bits):,} times more work.", file=out)
    else:
        print(f"no match after {result.tried:,} candidates in "
              f"{result.elapsed:,.1f}s ({result.rate:,.0f}/s)", file=out)
        print(f"  target     {result.target}", file=out)
        print(f"  template   {result.template}", file=out)
        if result.rate > 0 and result.bits == 32:
            seconds = median_candidates(32) / result.rate
            print(f"  at this rate the median 32-bit search "
                  f"({median_candidates(32):,} candidates) would take about "
                  f"{seconds / 86400:,.1f} days on one core", file=out)
    return OK if result.found else NOT_FOUND


def _cmd_collide(args, out, err) -> int:
    try:
        template = _resolve_template(args)
        budget = parse_count(args.budget)
    except SearchError as exc:
        print(f"error: {exc}", file=err)
        return USAGE

    try:
        result = find_birthday_pair(
            template=template,
            alphabet=args.alphabet,
            budget=budget,
            progress=_progress_writer(err) if args.progress else None,
        )
    except SearchError as exc:
        print(f"error: {exc}", file=err)
        return USAGE

    if args.json:
        import json as _json
        print(_json.dumps({
            "tool": "selector-collide",
            "mode": "collide",
            "template": result.template,
            "alphabet": result.alphabet,
            "tried": result.tried,
            "budget": result.budget,
            "seconds": round(result.elapsed, 3),
            "rate_per_second": round(result.rate, 1),
            "found": result.found,
            "selector": result.selector,
            "signatures": [result.first, result.second] if result.found else [],
        }, indent=2, sort_keys=True), file=out)
    elif result.found:
        print(f"found a colliding pair after {result.tried:,} candidates in "
              f"{result.elapsed:,.1f}s ({result.rate:,.0f}/s)", file=out)
        print(f"  selector   {result.selector}", file=out)
        print(f"  signature  {result.first}", file=out)
        print(f"  signature  {result.second}", file=out)
    else:
        print(f"no colliding pair after {result.tried:,} candidates in "
              f"{result.elapsed:,.1f}s ({result.rate:,.0f}/s)", file=out)
    return OK if result.found else NOT_FOUND


def _cmd_allowlist(args, out, err) -> int:
    try:
        label, pairs = load_selector_list(args.file)
    except AbiError as exc:
        print(f"error: {exc}", file=err)
        return INPUT
    findings = sort_findings(analyse_allowlist(label, pairs, args.rate))
    inputs = [f"{label} ({len(pairs)} entries)"]
    if args.json:
        print(render_json("allowlist", findings, inputs), file=out)
    else:
        print(render_text("allowlist", findings, inputs), file=out, end="")
    return _exit_for(findings, args.fail_on)


def _cmd_benchmark(args, out, err) -> int:
    try:
        count = parse_count(args.count)
    except SearchError as exc:
        print(f"error: {exc}", file=err)
        return USAGE
    try:
        hashed, seconds = benchmark(count, args.template)
    except SearchError as exc:
        print(f"error: {exc}", file=err)
        return USAGE
    rate = hashed / seconds if seconds else 0.0
    if args.json:
        import json as _json
        print(_json.dumps({
            "tool": "selector-collide",
            "mode": "benchmark",
            "template": args.template,
            "hashed": hashed,
            "seconds": round(seconds, 3),
            "rate_per_second": round(rate, 1),
            "median_candidates_32_bit": median_candidates(32),
            "median_days_32_bit": round(median_candidates(32) / rate / 86400, 2) if rate else None,
        }, indent=2, sort_keys=True), file=out)
    else:
        print(f"hashed {hashed:,} candidate signatures in {seconds:,.2f}s "
              f"({rate:,.0f}/s)", file=out)
        if rate:
            print(f"  median 32-bit search: {median_candidates(32):,} candidates, "
                  f"about {median_candidates(32) / rate / 86400:,.1f} days on one core",
                  file=out)
    return OK


def _cmd_selftest(args, out, err) -> int:
    results: list[tuple[str, bool, str, str]] = []

    for description, data, expected in DIGEST_VECTORS + BOUNDARY_VECTORS:
        actual = keccak256_hex(data)
        results.append((f"keccak256 {description}", actual == expected, expected, actual))

    for description, label, expected in SLOT_VECTORS:
        actual = hex(int.from_bytes(keccak256(label), "big") - 1)
        results.append((f"slot {description}", actual == expected, expected, actual))

    for signature, expected in SELECTOR_VECTORS:
        actual = selector_hex(signature)
        results.append((f"selector {signature}", actual == expected, expected, actual))

    for selector, group in sorted(KNOWN_COLLISIONS.items()):
        for signature in group:
            actual = selector_hex(signature)
            results.append((
                f"known collision {signature}", actual == selector, selector, actual,
            ))

    failed = [r for r in results if not r[1]]
    if args.json:
        import json as _json
        print(_json.dumps({
            "tool": "selector-collide",
            "mode": "selftest",
            "checks": len(results),
            "failed": len(failed),
            "results": [
                {"check": name, "ok": ok, "expected": expected, "actual": actual}
                for name, ok, expected, actual in results
            ],
        }, indent=2, sort_keys=True), file=out)
    else:
        for name, ok, expected, actual in results:
            if ok:
                print(f"  ok    {name}", file=out)
            else:
                print(f"  FAIL  {name}\n          expected {expected}\n"
                      f"          actual   {actual}", file=out)
        print(f"\n  {len(results)} checks, {len(failed)} failed", file=out)
    return OK if not failed else FINDINGS


_COMMANDS = {
    "check": _cmd_check,
    "selectors": _cmd_selectors,
    "find": _cmd_find,
    "collide": _cmd_collide,
    "allowlist": _cmd_allowlist,
    "benchmark": _cmd_benchmark,
    "selftest": _cmd_selftest,
}


def main(argv: list[str] | None = None, out=None, err=None) -> int:
    """Run the CLI. Returns the exit code rather than raising SystemExit."""
    argv = list(sys.argv[1:] if argv is None else argv)
    out = out if out is not None else sys.stdout
    err = err if err is not None else sys.stderr

    # Make 'check' the default command so that the mode flags can be given
    # directly, without naming the command.
    if argv and argv[0].startswith("-") and argv[0] not in ("-h", "--help", "--version"):
        argv.insert(0, "check")

    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:  # argparse already printed its message
        return int(exc.code or 0)

    if args.command is None:
        parser.print_help(out)
        return USAGE

    return _COMMANDS[args.command](args, out, err)


def run() -> None:
    """Console-script entry point."""
    sys.exit(main())
