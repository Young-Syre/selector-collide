"""Rendering: plain text for a terminal, JSON for anything else.

Both renderers are deterministic. Findings are sorted by
:func:`selector_collide.analyse.sort_findings` before they get here, selector
tables are sorted by selector, and nothing in the output depends on dictionary
iteration order, the wall clock, or the paths the inputs happened to come from.
"""

from __future__ import annotations

import json

from .abi import Source
from .analyse import SEVERITY_ORDER, Finding

__all__ = ["render_text", "render_json", "render_selectors_text", "render_selectors_json"]

_SEVERITY_LABEL = {
    "high": "HIGH  ",
    "medium": "MEDIUM",
    "low": "LOW   ",
    "info": "INFO  ",
}


def _wrap(text: str, width: int = 78, indent: str = "        ") -> list[str]:
    words = text.split()
    lines: list[str] = []
    current: list[str] = []
    length = 0
    for word in words:
        if current and length + 1 + len(word) > width - len(indent):
            lines.append(indent + " ".join(current))
            current = [word]
            length = len(word)
        else:
            current.append(word)
            length += (1 if length else 0) + len(word)
    if current:
        lines.append(indent + " ".join(current))
    return lines


def counts_by_severity(findings: list[Finding]) -> dict[str, int]:
    counts = {severity: 0 for severity in SEVERITY_ORDER}
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    return counts


def render_text(mode: str, findings: list[Finding], inputs: list[str]) -> str:
    """Render findings as indented text."""
    lines = [f"selector-collide: {mode}"]
    for label in inputs:
        lines.append(f"  input: {label}")
    lines.append("")

    if not findings:
        lines.append("  no collisions found")
        lines.append("")
        return "\n".join(lines)

    for finding in findings:
        selector = finding.selector or "--------"
        label = _SEVERITY_LABEL.get(finding.severity, finding.severity.upper())
        lines.append(f"  {label}  {finding.rule} {finding.name}")
        lines.append(f"          selector {selector}  {finding.title}")
        lines.extend(_wrap(finding.detail, indent="          "))
        lines.append("")

    counts = counts_by_severity(findings)
    summary = ", ".join(
        f"{counts[severity]} {severity}"
        for severity in ("high", "medium", "low", "info")
        if counts.get(severity)
    )
    noun = "finding" if len(findings) == 1 else "findings"
    lines.append(f"  {len(findings)} {noun}: {summary}")
    lines.append("")
    return "\n".join(lines)


def render_json(mode: str, findings: list[Finding], inputs: list[str], extra: dict | None = None) -> str:
    document = {
        "tool": "selector-collide",
        "mode": mode,
        "inputs": inputs,
        "counts": counts_by_severity(findings),
        "findings": [finding.as_dict() for finding in findings],
    }
    if extra:
        document.update(extra)
    return json.dumps(document, indent=2, sort_keys=True)


def _selector_rows(sources: list[Source], include_errors: bool) -> list[dict]:
    rows: list[dict] = []
    kinds = ("function", "error") if include_errors else ("function",)
    for source in sources:
        for entry in source.entries:
            if entry.kind in kinds and entry.selector is not None:
                rows.append({
                    "selector": entry.selector,
                    "signature": entry.signature,
                    "kind": entry.kind,
                    "stateMutability": entry.state_mutability,
                    "modifiers": list(entry.modifiers),
                    "source": source.label,
                })
    rows.sort(key=lambda r: (r["selector"], r["signature"], r["source"]))
    return rows


def render_selectors_text(sources: list[Source], include_errors: bool) -> str:
    rows = _selector_rows(sources, include_errors)
    if not rows:
        return "no function entries found\n"
    width = max(len(r["signature"]) for r in rows)
    multiple = len({r["source"] for r in rows}) > 1
    lines = []
    for row in rows:
        line = f"{row['selector']}  {row['signature']:<{width}}  {row['kind']}"
        if row["stateMutability"]:
            line += f" {row['stateMutability']}"
        if row["modifiers"]:
            line += " " + " ".join(row["modifiers"])
        if multiple:
            line += f"  [{row['source']}]"
        lines.append(line)
    return "\n".join(lines) + "\n"


def render_selectors_json(sources: list[Source], include_errors: bool) -> str:
    return json.dumps({
        "tool": "selector-collide",
        "mode": "selectors",
        "inputs": [source.label for source in sources],
        "selectors": _selector_rows(sources, include_errors),
    }, indent=2, sort_keys=True)
