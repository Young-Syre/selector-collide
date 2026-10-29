"""Keccak-256 -- the pre-standardisation Keccak that the EVM uses.

This is deliberately *not* ``hashlib.sha3_256``. Keccak and SHA3-256 share the
Keccak-f[1600] permutation, the sponge construction and the rate (1088 bits,
136 bytes); they differ in one byte. Keccak appends the multi-rate padding
``pad10*1`` directly, so the first padding byte is ``0x01``. SHA3, as
standardised in FIPS 202, first appends the two-bit domain separator ``01``,
which turns that byte into ``0x06``. Ethereum froze on Keccak before FIPS 202
was published, so every EVM selector, event topic and storage slot is a Keccak
digest, and every SHA3-256 digest of the same input is a different number.

That single byte is the one thing most hand-written implementations get wrong,
which is why ``tests/test_keccak.py`` pins this module against published
vectors (including ``keccak256(b"") ==
c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470``), against
four selectors that anyone can check against a deployed ERC-20, and against an
independent spec-literal implementation in ``tests/reference_keccak.py`` over
every input length from 0 to 400 bytes.

The permutation is written out lane by lane rather than looped over indices:
the selector search in ``selector_collide.search`` runs it millions of times,
and in pure Python the index arithmetic costs more than the mixing does. The
lane assignments were machine-generated from the step mappings in the Keccak
reference specification and are checked against the reference implementation in
the tests.
"""

from __future__ import annotations

__all__ = [
    "keccak256",
    "keccak256_hex",
    "selector_bytes",
    "selector_int",
    "selector_hex",
]

M = (1 << 64) - 1

RATE = 136  # bytes; 1088 bits, the rate of Keccak-256
PAD = 0x01  # Keccak's pad10*1 start byte. SHA3-256 would use 0x06 here.

ROUND_CONSTANTS = (
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
    0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
    0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
    0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
    0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
    0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
)


def _permute(lanes: list[int]) -> list[int]:
    """Apply Keccak-f[1600]: 24 rounds of theta, rho, pi, chi, iota.

    ``lanes`` holds the 25 state lanes in the order the sponge reads them from
    the byte stream, that is lane ``x + 5 * y`` for sheet ``x`` and plane ``y``.
    """
    (a00, a10, a20, a30, a40,
     a01, a11, a21, a31, a41,
     a02, a12, a22, a32, a42,
     a03, a13, a23, a33, a43,
     a04, a14, a24, a34, a44) = lanes

    for rc in ROUND_CONSTANTS:
        c0 = a00 ^ a01 ^ a02 ^ a03 ^ a04
        c1 = a10 ^ a11 ^ a12 ^ a13 ^ a14
        c2 = a20 ^ a21 ^ a22 ^ a23 ^ a24
        c3 = a30 ^ a31 ^ a32 ^ a33 ^ a34
        c4 = a40 ^ a41 ^ a42 ^ a43 ^ a44

        d0 = c4 ^ (((c1 << 1) | (c1 >> 63)) & M)
        d1 = c0 ^ (((c2 << 1) | (c2 >> 63)) & M)
        d2 = c1 ^ (((c3 << 1) | (c3 >> 63)) & M)
        d3 = c2 ^ (((c4 << 1) | (c4 >> 63)) & M)
        d4 = c3 ^ (((c0 << 1) | (c0 >> 63)) & M)

        b00 = (a00 ^ d0)
        t = (a01 ^ d0)
        b13 = ((t << 36) | (t >> 28)) & M
        t = (a02 ^ d0)
        b21 = ((t << 3) | (t >> 61)) & M
        t = (a03 ^ d0)
        b34 = ((t << 41) | (t >> 23)) & M
        t = (a04 ^ d0)
        b42 = ((t << 18) | (t >> 46)) & M
        t = (a10 ^ d1)
        b02 = ((t << 1) | (t >> 63)) & M
        t = (a11 ^ d1)
        b10 = ((t << 44) | (t >> 20)) & M
        t = (a12 ^ d1)
        b23 = ((t << 10) | (t >> 54)) & M
        t = (a13 ^ d1)
        b31 = ((t << 45) | (t >> 19)) & M
        t = (a14 ^ d1)
        b44 = ((t << 2) | (t >> 62)) & M
        t = (a20 ^ d2)
        b04 = ((t << 62) | (t >> 2)) & M
        t = (a21 ^ d2)
        b12 = ((t << 6) | (t >> 58)) & M
        t = (a22 ^ d2)
        b20 = ((t << 43) | (t >> 21)) & M
        t = (a23 ^ d2)
        b33 = ((t << 15) | (t >> 49)) & M
        t = (a24 ^ d2)
        b41 = ((t << 61) | (t >> 3)) & M
        t = (a30 ^ d3)
        b01 = ((t << 28) | (t >> 36)) & M
        t = (a31 ^ d3)
        b14 = ((t << 55) | (t >> 9)) & M
        t = (a32 ^ d3)
        b22 = ((t << 25) | (t >> 39)) & M
        t = (a33 ^ d3)
        b30 = ((t << 21) | (t >> 43)) & M
        t = (a34 ^ d3)
        b43 = ((t << 56) | (t >> 8)) & M
        t = (a40 ^ d4)
        b03 = ((t << 27) | (t >> 37)) & M
        t = (a41 ^ d4)
        b11 = ((t << 20) | (t >> 44)) & M
        t = (a42 ^ d4)
        b24 = ((t << 39) | (t >> 25)) & M
        t = (a43 ^ d4)
        b32 = ((t << 8) | (t >> 56)) & M
        t = (a44 ^ d4)
        b40 = ((t << 14) | (t >> 50)) & M

        a00 = b00 ^ (~b10 & b20 & M)
        a01 = b01 ^ (~b11 & b21 & M)
        a02 = b02 ^ (~b12 & b22 & M)
        a03 = b03 ^ (~b13 & b23 & M)
        a04 = b04 ^ (~b14 & b24 & M)
        a10 = b10 ^ (~b20 & b30 & M)
        a11 = b11 ^ (~b21 & b31 & M)
        a12 = b12 ^ (~b22 & b32 & M)
        a13 = b13 ^ (~b23 & b33 & M)
        a14 = b14 ^ (~b24 & b34 & M)
        a20 = b20 ^ (~b30 & b40 & M)
        a21 = b21 ^ (~b31 & b41 & M)
        a22 = b22 ^ (~b32 & b42 & M)
        a23 = b23 ^ (~b33 & b43 & M)
        a24 = b24 ^ (~b34 & b44 & M)
        a30 = b30 ^ (~b40 & b00 & M)
        a31 = b31 ^ (~b41 & b01 & M)
        a32 = b32 ^ (~b42 & b02 & M)
        a33 = b33 ^ (~b43 & b03 & M)
        a34 = b34 ^ (~b44 & b04 & M)
        a40 = b40 ^ (~b00 & b10 & M)
        a41 = b41 ^ (~b01 & b11 & M)
        a42 = b42 ^ (~b02 & b12 & M)
        a43 = b43 ^ (~b03 & b13 & M)
        a44 = b44 ^ (~b04 & b14 & M)

        a00 ^= rc
    return [a00, a10, a20, a30, a40,
            a01, a11, a21, a31, a41,
            a02, a12, a22, a32, a42,
            a03, a13, a23, a33, a43,
            a04, a14, a24, a34, a44]


def _absorb_and_squeeze(data: bytes) -> bytes:
    """The sponge: pad to a multiple of the rate, absorb, squeeze 32 bytes.

    The output length (32 bytes) is below the rate, so exactly one squeeze is
    needed and the loop that a general sponge would run never iterates twice.
    """
    # pad10*1: a 0x01 start byte, zero fill, and 0x80 as the final bit. When
    # only one padding byte fits, the two collapse into a single 0x81.
    padded = bytearray(data)
    padded.append(PAD)
    while len(padded) % RATE != 0:
        padded.append(0x00)
    padded[-1] |= 0x80

    lanes = [0] * 25
    for offset in range(0, len(padded), RATE):
        block = padded[offset:offset + RATE]
        for i in range(17):  # RATE // 8 lanes per block
            lanes[i] ^= int.from_bytes(block[i * 8:i * 8 + 8], "little")
        lanes = _permute(lanes)

    out = bytearray()
    for i in range(4):  # 32 bytes of digest
        out += lanes[i].to_bytes(8, "little")
    return bytes(out)


def keccak256(data: bytes) -> bytes:
    """Return the 32-byte Keccak-256 digest of ``data``."""
    if isinstance(data, str):  # a common and silent mistake; refuse it loudly
        raise TypeError("keccak256 takes bytes, not str; encode it first")
    return _absorb_and_squeeze(bytes(data))


def keccak256_hex(data: bytes) -> str:
    """Return the Keccak-256 digest of ``data`` as 64 lowercase hex digits."""
    return keccak256(data).hex()


def selector_bytes(signature: str) -> bytes:
    """Return the 4-byte function selector of a canonical signature.

    ``signature`` must already be canonical, e.g. ``transfer(address,uint256)``
    with no parameter names, no spaces and no type aliases. Canonicalisation
    lives in :mod:`selector_collide.signature`.
    """
    return keccak256(signature.encode("utf-8"))[:4]


def selector_int(signature: str) -> int:
    """Return the function selector of a canonical signature as an integer."""
    return int.from_bytes(selector_bytes(signature), "big")


def selector_hex(signature: str) -> str:
    """Return the function selector of a canonical signature as ``0x`` hex."""
    return "0x" + selector_bytes(signature).hex()


def selector_int_of_bytes(data: bytes) -> int:
    """Selector of pre-encoded signature bytes, as a 32-bit integer.

    Used by the search loop, which builds candidate signatures as bytes and
    never needs the remaining 28 bytes of the digest.
    """
    return int.from_bytes(_absorb_and_squeeze(data)[:4], "big")
