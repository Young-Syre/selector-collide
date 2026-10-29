"""The collision rules.

Rule IDs are stable; the README carries the same table. Each rule answers a
different question about the same 4-byte namespace:

SC001-SC003  a proxy and its implementation disagree about who owns a selector
SC004        two diamond facets claim the same selector
SC005        one ABI contains two signatures with the same selector
SC006-SC007  what the presence or absence of a fallback means for dispatch
SC008        a selector allowlist is a 4-byte check, not a signature check
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .abi import Source
from .known import alternatives_for
from .search import median_candidates
from .signature import Entry

__all__ = [
    "Finding",
    "SEVERITY_ORDER",
    "RULES",
    "analyse_shadowing",
    "analyse_diamond",
    "analyse_abi",
    "analyse_allowlist",
    "sort_findings",
]

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}

RULES: dict[str, str] = {
    "SC001": "proxy-shadow",
    "SC002": "shadow-modifier-divergence",
    "SC003": "shadow-mutability-divergence",
    "SC004": "facet-clash",
    "SC005": "abi-duplicate-selector",
    "SC006": "proxy-without-fallback",
    "SC007": "open-fallback",
    "SC008": "allowlist-selector-keyed",
}


@dataclass(frozen=True)
class Finding:
    """One rule firing on one selector."""

    rule: str
    severity: str
    selector: str | None
    title: str
    detail: str
    signatures: tuple[str, ...] = field(default=())
    sources: tuple[str, ...] = field(default=())

    @property
    def name(self) -> str:
        return RULES[self.rule]

    def as_dict(self) -> dict:
        return {
            "rule": self.rule,
            "name": self.name,
            "severity": self.severity,
            "selector": self.selector,
            "title": self.title,
            "detail": self.detail,
            "signatures": list(self.signatures),
            "sources": list(self.sources),
        }


def sort_findings(findings: list[Finding]) -> list[Finding]:
    """Order findings by severity, then rule, then selector, then title."""
    return sorted(
        findings,
        key=lambda f: (
            SEVERITY_ORDER.get(f.severity, 99),
            f.rule,
            f.selector or "",
            f.title,
        ),
    )


def _describe(entry: Entry) -> str:
    return f"{entry.source}:{entry.describe()}"


def analyse_shadowing(proxy: Source, implementation: Source) -> list[Finding]:
    """Compare a delegatecall proxy's own ABI against its implementation's.

    A proxy dispatches on its own selectors first and only falls through to the
    fallback -- and so to the implementation -- when nothing matched. Any
    selector present in both is therefore answered by the proxy for ever, and
    the implementation's function behind it is dead code reachable only by
    calling the implementation directly.
    """
    findings: list[Finding] = []
    proxy_map = proxy.selector_map()
    impl_map = implementation.selector_map()

    for selector in sorted(set(proxy_map) & set(impl_map)):
        proxy_entries = proxy_map[selector]
        impl_entries = impl_map[selector]
        for proxy_entry in proxy_entries:
            for impl_entry in impl_entries:
                severity = "high" if impl_entry.is_state_changing else "medium"
                findings.append(Finding(
                    rule="SC001",
                    severity=severity,
                    selector=selector,
                    title=f"{proxy.label} shadows {impl_entry.signature}",
                    detail=(
                        f"{proxy_entry.signature} in {proxy.label} and "
                        f"{impl_entry.signature} in {implementation.label} share "
                        f"selector {selector}. The proxy matches it first, so the "
                        f"implementation's function is unreachable through the "
                        f"proxy. "
                        + (
                            "It is state-changing, so a call that was meant to "
                            "mutate the implementation's state runs the proxy's "
                            "function instead."
                            if impl_entry.is_state_changing
                            else "It is a read, so callers get the proxy's answer "
                                 "rather than the implementation's."
                        )
                    ),
                    signatures=(proxy_entry.signature, impl_entry.signature),
                    sources=(proxy.label, implementation.label),
                ))

                proxy_mods = set(proxy_entry.modifiers)
                impl_mods = set(impl_entry.modifiers)
                if proxy_mods != impl_mods:
                    only_proxy = sorted(proxy_mods - impl_mods) or ["none"]
                    only_impl = sorted(impl_mods - proxy_mods) or ["none"]
                    findings.append(Finding(
                        rule="SC002",
                        severity="high",
                        selector=selector,
                        title=f"access control differs on {selector}",
                        detail=(
                            f"The shadowing pair declares different modifiers: "
                            f"{proxy.label} has {', '.join(only_proxy)} and "
                            f"{implementation.label} has {', '.join(only_impl)}. "
                            f"Whichever guard the implementation's function relied "
                            f"on is no longer the guard that runs."
                        ),
                        signatures=(proxy_entry.describe(), impl_entry.describe()),
                        sources=(proxy.label, implementation.label),
                    ))

                if proxy_entry.state_mutability != impl_entry.state_mutability:
                    findings.append(Finding(
                        rule="SC003",
                        severity="medium",
                        selector=selector,
                        title=f"state mutability differs on {selector}",
                        detail=(
                            f"{proxy.label} declares {proxy_entry.signature} as "
                            f"{proxy_entry.state_mutability} while "
                            f"{implementation.label} declares "
                            f"{impl_entry.signature} as "
                            f"{impl_entry.state_mutability}. Callers compiled "
                            f"against the implementation's ABI will send calls the "
                            f"proxy's function handles differently."
                        ),
                        signatures=(proxy_entry.describe(), impl_entry.describe()),
                        sources=(proxy.label, implementation.label),
                    ))

    if not proxy.has_fallback:
        findings.append(Finding(
            rule="SC006",
            severity="info",
            selector=None,
            title=f"{proxy.label} declares no fallback",
            detail=(
                f"{proxy.label} has no fallback entry, so this ABI cannot forward "
                f"anything to {implementation.label}. Either the ABI is partial -- "
                f"solc omits a fallback declared in an inherited contract only if "
                f"it is not public, so check the full artefact -- or this contract "
                f"is not a forwarding proxy and the comparison does not apply."
            ),
            sources=(proxy.label,),
        ))

    return findings


def analyse_diamond(sources: list[Source]) -> list[Finding]:
    """Check EIP-2535 facets for selectors claimed by more than one facet.

    ``diamondCut`` rejects adding a selector that is already registered, so a
    clash is a deployment failure rather than a silent one -- but only for the
    facets registered in the same cut. A clash found here is the thing that
    makes an upgrade transaction revert, or that forces whoever wrote the cut
    to pick a winner and leave the loser unroutable.
    """
    findings: list[Finding] = []
    owners: dict[str, list[Entry]] = {}
    for source in sources:
        for selector, entries in source.selector_map().items():
            owners.setdefault(selector, []).extend(entries)

    for selector in sorted(owners):
        entries = owners[selector]
        facets = sorted({e.source for e in entries})
        if len(facets) > 1:
            findings.append(Finding(
                rule="SC004",
                severity="high",
                selector=selector,
                title=f"{selector} claimed by {len(facets)} facets",
                detail=(
                    f"Selector {selector} is exported by " + ", ".join(facets)
                    + ". A diamond holds one selector-to-facet mapping, so "
                    "registering the second facet reverts in diamondCut, and any "
                    "cut that works leaves one of these functions unroutable: "
                    + "; ".join(sorted(_describe(e) for e in entries))
                ),
                signatures=tuple(sorted({e.signature for e in entries})),
                sources=tuple(facets),
            ))

    for source in sources:
        findings.extend(analyse_abi(source, include_fallback_notes=False))
    return findings


def analyse_abi(
    source: Source,
    include_errors: bool = False,
    include_fallback_notes: bool = True,
) -> list[Finding]:
    """Check one ABI for internal duplicates and report its fallback posture."""
    findings: list[Finding] = []

    for selector, entries in sorted(source.selector_map(include_errors).items()):
        distinct = sorted({e.signature for e in entries})
        if len(distinct) > 1:
            kinds = sorted({e.kind for e in entries})
            cross_kind = len(kinds) > 1
            findings.append(Finding(
                rule="SC005",
                severity="medium" if cross_kind else "high",
                selector=selector,
                title=f"{selector} used by {len(distinct)} signatures in {source.label}",
                detail=(
                    f"{source.label} contains " + " and ".join(distinct)
                    + f", which share selector {selector}. "
                    + (
                        "One is a function and one a custom error, so dispatch is "
                        "unaffected, but a revert carrying this selector cannot be "
                        "decoded unambiguously."
                        if cross_kind else
                        "solc rejects this within a single contract, so this ABI "
                        "was assembled from more than one source -- a merged "
                        "interface, a hand-edited file, or a router's declared "
                        "surface -- and only one of the two is reachable."
                    )
                ),
                signatures=tuple(distinct),
                sources=(source.label,),
            ))

    if include_fallback_notes and source.has_fallback:
        findings.append(Finding(
            rule="SC007",
            severity="info",
            selector=None,
            title=f"{source.label} declares a fallback",
            detail=(
                f"{source.label} declares a fallback"
                + (" and a receive function" if source.has_receive else "")
                + ", so calls carrying a selector this ABI does not declare are "
                "not rejected: they reach the fallback body. Any check that "
                "treats this ABI as the contract's complete call surface -- an "
                "interface conformance test, an allowlist generated from it, a "
                "selector-to-facet map -- is incomplete by exactly the set of "
                "selectors the fallback handles."
            ),
            sources=(source.label,),
        ))

    return findings


def analyse_allowlist(
    label: str,
    pairs: list[tuple[str, str]],
    hash_rate: float | None = None,
) -> list[Finding]:
    """Assess an allowlist that is keyed on selectors rather than signatures.

    Every entry gets a finding, because every 4-byte key admits other
    signatures by construction. The severity distinguishes "an alternative is
    already public" from "an alternative exists but someone would have to go
    and find it".
    """
    findings: list[Finding] = []
    median = median_candidates(32)
    if hash_rate and hash_rate > 0:
        days = median / hash_rate / 86400.0
        cost = (
            f" At {hash_rate:,.0f} candidate signatures per second, the median "
            f"search is about {days:,.1f} days on one core."
        )
    else:
        cost = ""

    seen: set[str] = set()
    for selector, origin in pairs:
        if selector in seen:
            continue
        seen.add(selector)
        signature = origin if "(" in origin else None
        alternatives = alternatives_for(selector, signature)
        if alternatives:
            findings.append(Finding(
                rule="SC008",
                severity="high",
                selector=selector,
                title=f"{selector} has a published colliding signature",
                detail=(
                    f"{label} allows {origin}. "
                    + ", ".join(alternatives)
                    + (" also hashes" if len(alternatives) == 1 else " also hash")
                    + f" to {selector}, so a caller can satisfy this "
                    f"allowlist with a function this allowlist was never meant to "
                    f"permit. Key the check on the full signature, or on a hash "
                    f"wider than four bytes, or on the target address as well."
                ),
                signatures=(origin,) + alternatives,
                sources=(label,),
            ))
        else:
            findings.append(Finding(
                rule="SC008",
                severity="medium",
                selector=selector,
                title=f"{selector} is allowed by selector, not by signature",
                detail=(
                    f"{label} allows {origin}. No colliding signature for "
                    f"{selector} is known to this tool, but the selector space is "
                    f"32 bits wide: a uniform search expects 2**32 candidates and "
                    f"has a median of {median:,} before one appears."
                    + cost
                    + " The check admits any signature that lands on these four "
                    "bytes, not only this one."
                ),
                signatures=(origin,),
                sources=(label,),
            ))
    return findings
