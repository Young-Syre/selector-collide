"""Keccak-256 correctness: published vectors, SHA3 separation, and a cross-check."""

from __future__ import annotations

import hashlib
import random
import unittest

from selector_collide import keccak
from selector_collide.vectors import (
    BOUNDARY_VECTORS,
    DIGEST_VECTORS,
    SELECTOR_VECTORS,
    SLOT_VECTORS,
)
from tests import reference_keccak


class PublishedVectors(unittest.TestCase):
    def test_empty_string_digest(self):
        self.assertEqual(
            keccak.keccak256_hex(b""),
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
        )

    def test_digest_vectors(self):
        for description, data, expected in DIGEST_VECTORS:
            with self.subTest(description):
                self.assertEqual(keccak.keccak256_hex(data), expected)

    def test_boundary_vectors(self):
        for description, data, expected in BOUNDARY_VECTORS:
            with self.subTest(description):
                self.assertEqual(keccak.keccak256_hex(data), expected)

    def test_eip1967_slots(self):
        for description, label, expected in SLOT_VECTORS:
            with self.subTest(description):
                slot = int.from_bytes(keccak.keccak256(label), "big") - 1
                self.assertEqual(hex(slot), expected)

    def test_selector_vectors(self):
        for signature, expected in SELECTOR_VECTORS:
            with self.subTest(signature):
                self.assertEqual(keccak.selector_hex(signature), expected)

    def test_vector_tables_are_not_empty(self):
        self.assertGreaterEqual(len(DIGEST_VECTORS), 5)
        self.assertGreaterEqual(len(SELECTOR_VECTORS), 4)
        self.assertGreaterEqual(len(BOUNDARY_VECTORS), 2)
        self.assertGreaterEqual(len(SLOT_VECTORS), 2)


class NotSha3(unittest.TestCase):
    """The padding byte is the whole difference, so prove it is not SHA3-256."""

    def test_digests_differ_from_sha3(self):
        for data in (b"", b"abc", b"transfer(address,uint256)", b"a" * 200):
            with self.subTest(data=data[:20]):
                self.assertNotEqual(
                    keccak.keccak256(data), hashlib.sha3_256(data).digest()
                )

    def test_sha3_of_empty_string_is_the_other_well_known_digest(self):
        # If this module were accidentally SHA3, the empty digest would be this.
        self.assertEqual(
            hashlib.sha3_256(b"").hexdigest(),
            "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
        )
        self.assertNotEqual(keccak.keccak256_hex(b""), hashlib.sha3_256(b"").hexdigest())

    def test_padding_byte_is_keccak_not_sha3(self):
        self.assertEqual(keccak.PAD, 0x01)
        self.assertNotEqual(keccak.PAD, 0x06)


class AgainstReferenceImplementation(unittest.TestCase):
    def test_every_length_up_to_400_bytes(self):
        payload = bytes((i * 37 + 11) & 0xFF for i in range(400))
        for length in range(401):
            data = payload[:length]
            with self.subTest(length=length):
                self.assertEqual(keccak.keccak256(data), reference_keccak.keccak256(data))

    def test_rate_boundaries_exactly(self):
        for length in (0, 1, 134, 135, 136, 137, 271, 272, 273, 407, 408):
            data = bytes(range(256)) * 3
            with self.subTest(length=length):
                self.assertEqual(
                    keccak.keccak256(data[:length]),
                    reference_keccak.keccak256(data[:length]),
                )

    def test_random_inputs(self):
        rng = random.Random(20260101)  # fixed seed: the suite is deterministic
        for case in range(60):
            data = bytes(rng.randrange(256) for _ in range(rng.randrange(0, 300)))
            with self.subTest(case=case):
                self.assertEqual(keccak.keccak256(data), reference_keccak.keccak256(data))

    def test_reference_reproduces_the_empty_vector(self):
        self.assertEqual(
            reference_keccak.keccak256(b"").hex(),
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
        )


class Api(unittest.TestCase):
    def test_digest_is_32_bytes(self):
        for data in (b"", b"abc", b"a" * 500):
            with self.subTest(length=len(data)):
                self.assertEqual(len(keccak.keccak256(data)), 32)

    def test_hex_digest_is_64_characters(self):
        self.assertEqual(len(keccak.keccak256_hex(b"abc")), 64)

    def test_str_input_is_refused(self):
        with self.assertRaises(TypeError):
            keccak.keccak256("abc")  # type: ignore[arg-type]

    def test_bytearray_and_memoryview_are_accepted(self):
        self.assertEqual(keccak.keccak256(bytearray(b"abc")), keccak.keccak256(b"abc"))
        self.assertEqual(keccak.keccak256(memoryview(b"abc")), keccak.keccak256(b"abc"))

    def test_selector_bytes_is_four_bytes(self):
        self.assertEqual(len(keccak.selector_bytes("transfer(address,uint256)")), 4)

    def test_selector_int_matches_selector_hex(self):
        for signature, expected in SELECTOR_VECTORS:
            with self.subTest(signature):
                self.assertEqual(
                    keccak.selector_int(signature), int(expected[2:], 16)
                )

    def test_fast_path_agrees_with_the_public_api(self):
        for signature, _ in SELECTOR_VECTORS:
            with self.subTest(signature):
                self.assertEqual(
                    keccak.selector_int_of_bytes(signature.encode()),
                    keccak.selector_int(signature),
                )

    def test_fast_path_agrees_on_long_inputs(self):
        for length in (0, 135, 136, 300):
            data = b"z" * length
            with self.subTest(length=length):
                self.assertEqual(
                    keccak.selector_int_of_bytes(data),
                    int.from_bytes(keccak.keccak256(data)[:4], "big"),
                )

    def test_round_constants_and_rate(self):
        self.assertEqual(len(keccak.ROUND_CONSTANTS), 24)
        self.assertEqual(keccak.RATE, 136)
        self.assertEqual(keccak.M, (1 << 64) - 1)


if __name__ == "__main__":
    unittest.main()
