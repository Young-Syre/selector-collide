"""An independent, spec-literal Keccak-256 for cross-checking the fast one.

This is written the obvious way -- a 25-element state indexed by x + 5y, every
step mapping as a pair of loops over x and y, a fresh list per step -- and is
far slower than ``selector_collide.keccak``. The point is that the two were
written differently: the production module unrolls the lanes into local
variables, so a transcription error there would not reproduce itself here.
If they agree on every input length from 0 to 400 bytes and on random data,
the unrolled lane assignments are right.
"""

from __future__ import annotations

MASK = (1 << 64) - 1

ROTATION = (
    (0, 36, 3, 41, 18),
    (1, 44, 10, 45, 2),
    (62, 6, 43, 15, 61),
    (28, 55, 25, 21, 56),
    (27, 20, 39, 8, 14),
)

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


def _rotl(value: int, shift: int) -> int:
    shift %= 64
    if shift == 0:
        return value & MASK
    return ((value << shift) | (value >> (64 - shift))) & MASK


def permute(state: list[int]) -> list[int]:
    for round_constant in ROUND_CONSTANTS:
        # theta
        columns = [
            state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20]
            for x in range(5)
        ]
        deltas = [
            columns[(x - 1) % 5] ^ _rotl(columns[(x + 1) % 5], 1)
            for x in range(5)
        ]
        state = [
            state[x + 5 * y] ^ deltas[x]
            for y in range(5) for x in range(5)
        ]

        # rho and pi
        moved = [0] * 25
        for x in range(5):
            for y in range(5):
                moved[y + 5 * ((2 * x + 3 * y) % 5)] = _rotl(state[x + 5 * y], ROTATION[x][y])
        state = moved

        # chi
        mixed = [0] * 25
        for y in range(5):
            for x in range(5):
                mixed[x + 5 * y] = state[x + 5 * y] ^ (
                    ~state[(x + 1) % 5 + 5 * y] & state[(x + 2) % 5 + 5 * y] & MASK
                )
        state = mixed

        # iota
        state[0] ^= round_constant
    return state


def keccak256(data: bytes) -> bytes:
    rate = 136
    block_count = len(data) // rate + 1
    padded = bytearray(data) + bytearray(block_count * rate - len(data))
    padded[len(data)] = 0x01       # Keccak's domain byte; SHA3-256 uses 0x06
    padded[-1] = padded[-1] | 0x80

    state = [0] * 25
    for offset in range(0, len(padded), rate):
        for lane in range(rate // 8):
            start = offset + lane * 8
            state[lane] ^= int.from_bytes(padded[start:start + 8], "little")
        state = permute(state)

    digest = bytearray()
    for lane in range(4):
        digest += state[lane].to_bytes(8, "little")
    return bytes(digest)
