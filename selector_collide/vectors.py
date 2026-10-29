"""Keccak-256 test vectors, kept in the package so ``selftest`` can run anywhere.

The first group is published: the empty-string digest, three classic Keccak
vectors, two ERC-20 event topics that appear in every token transfer log on
every EVM chain, and the two EIP-1967 storage slots, which that EIP states as
``keccak256(label) - 1``. Anyone can check them against an independent Keccak
implementation or against a block explorer.

The second group is the four selectors that anyone can check against a
deployed ERC-20 contract.

The third group is boundary cases around the 136-byte rate, where a padding
mistake shows up. These digests are this implementation's own output; they are
not published vectors, and they earn their place by being cross-checked in
``tests/test_keccak.py`` against the independent spec-literal implementation in
``tests/reference_keccak.py``. They exist to catch a regression, not to prove
correctness on their own.
"""

from __future__ import annotations

__all__ = ["DIGEST_VECTORS", "SELECTOR_VECTORS", "BOUNDARY_VECTORS", "SLOT_VECTORS"]

# (description, input bytes, expected 64-hex digest)
DIGEST_VECTORS: tuple[tuple[str, bytes, str], ...] = (
    (
        "empty string",
        b"",
        "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
    ),
    (
        '"abc"',
        b"abc",
        "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45",
    ),
    (
        '"testing"',
        b"testing",
        "5f16f4c7f149ac4f9510d9cf8cf384038ad348b3bcdc01915f95de12df9d1b02",
    ),
    (
        "pangram",
        b"The quick brown fox jumps over the lazy dog",
        "4d741b6f1eb29cb2a9b9911c82f56fa8d73b04959d3d9d222895df6c0b28aa15",
    ),
    (
        "one million 'a' (multi-block)",
        b"a" * 1_000_000,
        "fadae6b49f129bbb812be8407b7b2894f34aecf6dbd1f9b0f0c7e9853098fc96",
    ),
    (
        "ERC-20 Transfer event topic",
        b"Transfer(address,address,uint256)",
        "ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef",
    ),
    (
        "ERC-20 Approval event topic",
        b"Approval(address,address,uint256)",
        "8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925",
    ),
)

# (description, label, expected slot) where slot == keccak256(label) - 1,
# exactly as EIP-1967 defines it.
SLOT_VECTORS: tuple[tuple[str, bytes, str], ...] = (
    (
        "EIP-1967 implementation slot",
        b"eip1967.proxy.implementation",
        "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc",
    ),
    (
        "EIP-1967 admin slot",
        b"eip1967.proxy.admin",
        "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103",
    ),
)

# (canonical signature, expected selector)
SELECTOR_VECTORS: tuple[tuple[str, str], ...] = (
    ("transfer(address,uint256)", "0xa9059cbb"),
    ("approve(address,uint256)", "0x095ea7b3"),
    ("balanceOf(address)", "0x70a08231"),
    ("owner()", "0x8da5cb5b"),
    ("totalSupply()", "0x18160ddd"),
    ("transferFrom(address,address,uint256)", "0x23b872dd"),
    ("supportsInterface(bytes4)", "0x01ffc9a7"),
    ("upgradeTo(address)", "0x3659cfe6"),
)

# (description, input bytes, expected digest) around the 136-byte rate.
BOUNDARY_VECTORS: tuple[tuple[str, bytes, str], ...] = (
    (
        "135 bytes (one byte of padding, so 0x01 and 0x80 merge into 0x81)",
        b"a" * 135,
        "34367dc248bbd832f4e3e69dfaac2f92638bd0bbd18f2912ba4ef454919cf446",
    ),
    (
        "136 bytes (a full rate, so padding occupies a whole second block)",
        b"a" * 136,
        "a6c4d403279fe3e0af03729caada8374b5ca54d8065329a3ebcaeb4b60aa386e",
    ),
)
