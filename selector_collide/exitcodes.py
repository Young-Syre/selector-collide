"""Exit codes. These are part of the interface and are documented in the README."""

from __future__ import annotations

__all__ = ["OK", "FINDINGS", "USAGE", "INPUT", "NOT_FOUND", "DESCRIPTIONS"]

OK = 0           # ran to completion with nothing at or above the fail threshold
FINDINGS = 1     # at least one finding at or above the fail threshold
USAGE = 2        # the command line was wrong (argparse also uses 2)
INPUT = 3        # an input file was missing, unreadable, or not a usable ABI
NOT_FOUND = 4    # a search ran its whole budget without finding a collision

DESCRIPTIONS = {
    OK: "no findings at or above the fail threshold",
    FINDINGS: "findings at or above the fail threshold",
    USAGE: "usage error",
    INPUT: "input error",
    NOT_FOUND: "search budget exhausted without a collision",
}
