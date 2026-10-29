"""Searching for colliding signatures.

Two different problems live here, with very different costs, and the
difference is the whole point of the module:

*Preimage search* -- given one selector, find a signature that hashes to it.
There is no shortcut: a selector is 32 bits, so a uniform search expects
2**32 ~ 4.3e9 candidates, and the distribution is geometric, so the median is
about 0.69 * 2**32 ~ 3.0e9. At the hash rate this package achieves in pure
Python (measure it yourself with ``selector-collide benchmark``) that is days
of single-core work, not minutes. The function below therefore takes a
candidate budget and is expected to return nothing; it reports what it did.

*Birthday search* -- find any two signatures that share a selector, without
caring which. Among ``n`` candidates the expected number of colliding pairs is
roughly ``n**2 / 2**33``, so a 50% chance needs only about
``sqrt(2 * ln 2 * 2**32)`` ~ 77,000 candidates. That is seconds of work, and
it is enough to demonstrate the bug class concretely.

Both searches enumerate candidates in a fixed order, so the same arguments
always return the same result.
"""

from __future__ import annotations

import string
import time
from dataclasses import dataclass

from .keccak import selector_int_of_bytes

__all__ = [
    "SearchError",
    "PreimageResult",
    "BirthdayResult",
    "DEFAULT_ALPHABET",
    "parse_count",
    "candidate_names",
    "find_preimage",
    "find_birthday_pair",
    "expected_candidates",
    "median_candidates",
    "benchmark",
]

# Lowercase letters and digits: every string built from these is a legal
# Solidity identifier once prefixed, and the prefix keeps the first character
# from being a digit.
DEFAULT_ALPHABET = string.ascii_lowercase + string.digits


class SearchError(ValueError):
    """A search was asked for something it cannot do."""


@dataclass(frozen=True)
class PreimageResult:
    """The outcome of a bounded preimage search."""

    target: str
    bits: int
    template: str
    alphabet: str
    tried: int
    budget: int
    elapsed: float
    signature: str | None

    @property
    def found(self) -> bool:
        return self.signature is not None

    @property
    def rate(self) -> float:
        return self.tried / self.elapsed if self.elapsed > 0 else 0.0


@dataclass(frozen=True)
class BirthdayResult:
    """The outcome of a birthday search for any colliding pair."""

    template: str
    alphabet: str
    tried: int
    budget: int
    elapsed: float
    selector: str | None
    first: str | None
    second: str | None

    @property
    def found(self) -> bool:
        return self.first is not None and self.second is not None

    @property
    def rate(self) -> float:
        return self.tried / self.elapsed if self.elapsed > 0 else 0.0


def parse_count(text: str) -> int:
    """Parse a candidate budget, accepting ``1e8``, ``100_000_000`` and ``2**32``.

    Scientific notation is accepted because it is how the size of these
    searches is naturally written; the result must still be a whole number.
    """
    cleaned = text.strip().replace("_", "")
    if not cleaned:
        raise SearchError("empty count")
    try:
        if cleaned.isdigit():
            value = int(cleaned)
        elif cleaned.startswith("2**"):
            value = 2 ** int(cleaned[3:])
        else:
            as_float = float(cleaned)
            if as_float != int(as_float):
                raise SearchError(f"{text!r} is not a whole number of candidates")
            value = int(as_float)
    except (ValueError, OverflowError) as exc:
        raise SearchError(f"cannot read {text!r} as a candidate count") from exc
    if value < 1:
        raise SearchError(f"candidate count must be at least 1, got {value}")
    return value


def expected_candidates(bits: int = 32) -> int:
    """Mean number of candidates a uniform preimage search needs."""
    return 2 ** bits


def median_candidates(bits: int = 32) -> int:
    """Median number of candidates a uniform preimage search needs.

    The number of trials is geometric with p = 2**-bits, so the median is
    ln(2) / p, about 69% of the mean.
    """
    return int(0.6931471805599453 * (2 ** bits))


def _check_template(template: str) -> None:
    if template.count("{}") != 1:
        raise SearchError(
            f"template {template!r} must contain exactly one '{{}}' placeholder "
            f"for the generated part of the name"
        )
    if "(" not in template or not template.rstrip().endswith(")"):
        raise SearchError(
            f"template {template!r} must look like a signature, e.g. 'f{{}}(uint256)'"
        )


def candidate_names(alphabet: str, limit: int):
    """Yield the first ``limit`` names over ``alphabet``, shortest first.

    The order is deterministic: all one-character names in alphabet order, then
    all two-character names, and so on. The generated part may be empty, which
    makes the bare template its own first candidate.
    """
    if not alphabet:
        raise SearchError("alphabet is empty")
    if len(set(alphabet)) != len(alphabet):
        raise SearchError("alphabet contains a repeated character")

    produced = 0
    if limit <= 0:
        return
    yield ""
    produced += 1
    width = 1
    base = len(alphabet)
    while produced < limit:
        for index in range(base ** width):
            if produced >= limit:
                return
            digits = []
            value = index
            for _ in range(width):
                digits.append(alphabet[value % base])
                value //= base
            digits.reverse()
            yield "".join(digits)
            produced += 1
        width += 1


def find_preimage(
    target: str,
    *,
    template: str = "f{}()",
    alphabet: str = DEFAULT_ALPHABET,
    budget: int = 1_000_000,
    bits: int = 32,
    progress=None,
    progress_every: int = 250_000,
) -> PreimageResult:
    """Search for a signature whose selector matches ``target``.

    ``bits`` restricts the comparison to the top ``bits`` bits of the selector.
    At the default 32 this is a true collision; a lower value finds a partial
    match in proportionally less work, which is useful for checking that the
    search is wired up correctly and for calibrating how long the full search
    would take. A partial match is not a collision and the report says so.
    """
    _check_template(template)
    if not 1 <= bits <= 32:
        raise SearchError(f"bits must be between 1 and 32, got {bits}")

    target_value = int(target[2:] if target.lower().startswith("0x") else target, 16)
    shift = 32 - bits
    wanted = target_value >> shift

    prefix, _, suffix = template.partition("{}")
    prefix_bytes = prefix.encode("utf-8")
    suffix_bytes = suffix.encode("utf-8")

    hash_selector = selector_int_of_bytes  # local alias: this is the hot loop
    tried = 0
    found: str | None = None
    start = time.perf_counter()
    for name in candidate_names(alphabet, budget):
        tried += 1
        candidate = prefix_bytes + name.encode("utf-8") + suffix_bytes
        if hash_selector(candidate) >> shift == wanted:
            found = candidate.decode("utf-8")
            break
        if progress is not None and tried % progress_every == 0:
            progress(tried, time.perf_counter() - start)
    elapsed = time.perf_counter() - start

    return PreimageResult(
        target="0x" + format(target_value, "08x"),
        bits=bits,
        template=template,
        alphabet=alphabet,
        tried=tried,
        budget=budget,
        elapsed=elapsed,
        signature=found,
    )


def find_birthday_pair(
    *,
    template: str = "f{}()",
    alphabet: str = DEFAULT_ALPHABET,
    budget: int = 1_000_000,
    progress=None,
    progress_every: int = 250_000,
) -> BirthdayResult:
    """Search for any two generated signatures that share a selector.

    Memory grows with the number of candidates tried: one dictionary entry per
    distinct selector, so a budget of 1e6 needs a few tens of megabytes.
    """
    _check_template(template)

    prefix, _, suffix = template.partition("{}")
    prefix_bytes = prefix.encode("utf-8")
    suffix_bytes = suffix.encode("utf-8")

    hash_selector = selector_int_of_bytes
    seen: dict[int, bytes] = {}
    tried = 0
    pair: tuple[bytes, bytes, int] | None = None
    start = time.perf_counter()
    for name in candidate_names(alphabet, budget):
        tried += 1
        candidate = prefix_bytes + name.encode("utf-8") + suffix_bytes
        value = hash_selector(candidate)
        previous = seen.get(value)
        if previous is not None:
            pair = (previous, candidate, value)
            break
        seen[value] = candidate
        if progress is not None and tried % progress_every == 0:
            progress(tried, time.perf_counter() - start)
    elapsed = time.perf_counter() - start

    return BirthdayResult(
        template=template,
        alphabet=alphabet,
        tried=tried,
        budget=budget,
        elapsed=elapsed,
        selector=("0x" + format(pair[2], "08x")) if pair else None,
        first=pair[0].decode("utf-8") if pair else None,
        second=pair[1].decode("utf-8") if pair else None,
    )


def benchmark(count: int = 200_000, template: str = "f{}(address,uint256)") -> tuple[int, float]:
    """Hash ``count`` distinct candidate signatures, returning count and seconds.

    This is the number quoted in the README. It measures the same code path the
    searches use, including candidate construction, so it is the rate a search
    actually achieves rather than a permutation microbenchmark.
    """
    _check_template(template)
    prefix, _, suffix = template.partition("{}")
    prefix_bytes = prefix.encode("utf-8")
    suffix_bytes = suffix.encode("utf-8")

    hash_selector = selector_int_of_bytes
    tried = 0
    start = time.perf_counter()
    for name in candidate_names(DEFAULT_ALPHABET, count):
        hash_selector(prefix_bytes + name.encode("utf-8") + suffix_bytes)
        tried += 1
    return tried, time.perf_counter() - start
