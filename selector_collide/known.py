"""Selector collisions that are public knowledge, used to make reports concrete.

Each group below is a set of distinct canonical signatures that share one
4-byte selector. They are widely circulated examples -- the first group in
particular is the stock demonstration that ERC-20's ``transfer`` selector is
not unique -- and every one of them is recomputed from scratch by
``tests/test_known.py`` using this package's own Keccak implementation. If a
group were wrong, the test suite would fail; nothing here is taken on trust.

The table exists so that when a selector allowlist happens to contain one of
these, the report can name the alternative signature outright instead of
arguing in the abstract about 32-bit search spaces.
"""

from __future__ import annotations

__all__ = ["KNOWN_COLLISIONS", "alternatives_for"]

# selector -> signatures sharing it, in the order they are reported.
KNOWN_COLLISIONS: dict[str, tuple[str, ...]] = {
    "0xa9059cbb": (
        "transfer(address,uint256)",
        "many_msg_babbage(bytes1)",
        "func_2093253501(bytes)",
    ),
    "0x23b872dd": (
        "transferFrom(address,address,uint256)",
        "gasprice_bit_ether(int128)",
    ),
    "0x42966c68": (
        "burn(uint256)",
        "collate_propagate_storage(bytes16)",
    ),
}


def alternatives_for(selector: str, signature: str | None = None) -> tuple[str, ...]:
    """Known signatures sharing ``selector``, excluding ``signature`` itself."""
    group = KNOWN_COLLISIONS.get(selector.lower(), ())
    return tuple(s for s in group if s != signature)
