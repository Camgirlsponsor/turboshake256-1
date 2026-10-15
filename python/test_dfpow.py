"""Consensus checks for the DFPoW-256 draft."""

import unittest

import dfpow


CHAIN_ID = b"dfpow-test-v0.1\x00"
EPOCH = bytes(range(32))
PREV = bytes(32)
MERKLE = bytes([0x11]) * 32
TIMESTAMP = 1_700_000_000
DIFFICULTY = 20


def header(nonce: int, difficulty: int = DIFFICULTY, timestamp: int = TIMESTAMP) -> bytes:
    return dfpow.make_header(1, PREV, MERKLE, timestamp, difficulty, nonce)


class SizeTests(unittest.TestCase):
    def test_layout_constants(self):
        self.assertEqual(len(dfpow.DOMAIN_SEED), 16)
        self.assertEqual(len(dfpow.DOMAIN_DATA), 16)
        self.assertEqual(len(dfpow.DOMAIN_PROG), 16)
        self.assertEqual(len(dfpow.DOMAIN_FINAL), 16)
        self.assertEqual(len(dfpow.PARAMS), 12)
        self.assertEqual(dfpow.tape_bytes(), 255 + 256 * 12 + 32 * 7)
        self.assertEqual(len(header(1000)), 84)

    def test_target_probabilities(self):
        self.assertEqual(dfpow.target_for_difficulty(0), 2**256 - 1)
        self.assertEqual(dfpow.target_for_difficulty(1), 2**255 - 1)
        self.assertEqual(dfpow.target_for_difficulty(8), 2**248 - 1)
        self.assertEqual(dfpow.target_for_difficulty(256), 0)
        self.assertEqual(dfpow.block_work(0), 1)
        self.assertEqual(dfpow.block_work(20), 1 << 20)
        with self.assertRaises(ValueError):
            dfpow.target_for_difficulty(257)
        with self.assertRaises(ValueError):
            dfpow.block_work(-1)


class ProgramTests(unittest.TestCase):
    def test_program_is_total_and_balanced(self):
        program = dfpow.derive_program(CHAIN_ID, EPOCH, header(1000))
        self.assertEqual(len(program["seed"]), 32)
        self.assertEqual(sorted(program["sbox"]), list(range(256)))
        self.assertEqual(len(program["colors"]), dfpow.ROUNDS)
        self.assertEqual(len(set(program["sbox"])), 256)
        for name in dfpow.COLOR_NAMES:
            self.assertEqual(program["color_names"].count(name), dfpow.ROUNDS // 8)
        for constant, rotation, b0, b1, b2, multiplier in program["rounds"]:
            self.assertEqual(constant, constant & dfpow.MASK32)
            self.assertGreaterEqual(rotation, 1)
            self.assertLessEqual(rotation, 31)
            self.assertEqual(multiplier & 1, 1)
            self.assertEqual(multiplier & 0x80000000, 0x80000000)
            indices = dfpow.select_indices(0, b0, b1, b2)
            self.assertEqual(len(set(indices)), 4)
            self.assertEqual(indices[0], 0)

    def test_adjacent_nonces_diverge(self):
        first = dfpow.derive_program(CHAIN_ID, EPOCH, header(1000))
        second = dfpow.derive_program(CHAIN_ID, EPOCH, header(1001))
        third = dfpow.derive_program(CHAIN_ID, EPOCH, header(1002))
        self.assertNotEqual(first["seed"], second["seed"])
        self.assertNotEqual(first["colors"], second["colors"])
        self.assertNotEqual(second["colors"], third["colors"])
        self.assertNotEqual(first["sbox"], second["sbox"])
        self.assertEqual(first["color_names"][:8].count("XOR") +
                         first["color_names"][:8].count("ADD") +
                         first["color_names"][:8].count("ROT") +
                         first["color_names"][:8].count("MUL") +
                         first["color_names"][:8].count("SBOX") +
                         first["color_names"][:8].count("XORROT") +
                         first["color_names"][:8].count("ADDROT") +
                         first["color_names"][:8].count("MIX"), 8)
        self.assertEqual(sorted(first["color_names"][:8]), sorted(dfpow.COLOR_NAMES))

    def test_published_opening_schedules(self):
        expected = {
            1000: ["XOR", "XORROT", "ADDROT", "MUL", "ROT", "ADD", "MIX", "SBOX"],
            1001: ["XOR", "XORROT", "MUL", "ADDROT", "MIX", "ROT", "ADD", "SBOX"],
            1002: ["MIX", "SBOX", "MUL", "XOR", "ADD", "ROT", "ADDROT", "XORROT"],
            1003: ["MUL", "SBOX", "XORROT", "MIX", "ADDROT", "ADD", "XOR", "ROT"],
        }
        for nonce, names in expected.items():
            program = dfpow.derive_program(CHAIN_ID, EPOCH, header(nonce))
            self.assertEqual(program["color_names"][:8], names)
            self.assertEqual(sorted(program["color_names"][:8]), sorted(dfpow.COLOR_NAMES))


class HashTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dataset = dfpow.build_dataset(CHAIN_ID, EPOCH)

    def test_dataset_is_deterministic_and_read_only(self):
        again = dfpow.build_dataset(CHAIN_ID, EPOCH)
        self.assertEqual(self.dataset, again)
        snapshot = self.dataset.copy()
        digest = dfpow.pow_hash(CHAIN_ID, EPOCH, header(1000), dataset=self.dataset)
        self.assertEqual(len(digest), 32)
        self.assertEqual(self.dataset, snapshot)

    def test_dataset_word_depends_on_full_width(self):
        self.assertNotEqual(self.dataset[0], self.dataset[-1])
        other = dfpow.build_dataset(CHAIN_ID, bytes([0x02]) + EPOCH[1:])
        # A one-byte epoch change reaches both ends because of the two-pass mix.
        self.assertNotEqual(other[0], self.dataset[0])
        self.assertNotEqual(other[-1], self.dataset[-1])

    def test_cached_dataset_matches_internal_build(self):
        fresh = dfpow.pow_hash(CHAIN_ID, EPOCH, header(7))
        cached = dfpow.pow_hash(CHAIN_ID, EPOCH, header(7), dataset=self.dataset)
        self.assertEqual(fresh, cached)

    def test_inputs_reach_the_digest(self):
        base = dfpow.pow_hash(CHAIN_ID, EPOCH, header(1000), dataset=self.dataset)
        changed_nonce = dfpow.pow_hash(CHAIN_ID, EPOCH, header(1001), dataset=self.dataset)
        changed_time = dfpow.pow_hash(
            CHAIN_ID, EPOCH, header(1000, timestamp=TIMESTAMP + 1), dataset=self.dataset
        )
        changed_difficulty = dfpow.pow_hash(
            CHAIN_ID, EPOCH, header(1000, difficulty=21), dataset=self.dataset
        )
        changed_epoch = dfpow.pow_hash(
            CHAIN_ID, bytes([0x5A]) + EPOCH[1:], header(1000)
        )
        changed_chain = dfpow.pow_hash(b"OTHER-CHAIN-v01\x00", EPOCH, header(1000))
        self.assertEqual(len({base, changed_nonce, changed_time, changed_difficulty, changed_epoch, changed_chain}), 6)

    def test_flipping_dataset_changes_digest(self):
        base = dfpow.pow_hash(CHAIN_ID, EPOCH, header(1000), dataset=self.dataset)
        mutated = [word ^ 1 for word in self.dataset]
        other = dfpow.pow_hash(CHAIN_ID, EPOCH, header(1000), dataset=mutated)
        self.assertNotEqual(base, other)

    def test_scratch_fold_observes_every_word(self):
        base_state = list(range(8))
        scratch = [0] * dfpow.SCRATCH_WORDS
        left = base_state.copy()
        dfpow.fold_scratch(left, scratch, 0)
        scratch[123] ^= 1
        right = base_state.copy()
        dfpow.fold_scratch(right, scratch, 0)
        self.assertNotEqual(left, right)

    def test_scratch_is_written(self):
        _digest, trace = dfpow.pow_hash(
            CHAIN_ID, EPOCH, header(1000), dataset=self.dataset, trace=True
        )
        state = dfpow.init_state(trace["seed"], (1000).to_bytes(8, "little"))
        original = dfpow.init_scratch(self.dataset, state)
        self.assertNotEqual(trace["scratch_xor"], dfpow._xor_words(original))

    def test_difficulty_gate(self):
        digest = dfpow.pow_hash(CHAIN_ID, EPOCH, header(1000), dataset=self.dataset)
        self.assertTrue(dfpow.meets_target(digest, 0))
        self.assertFalse(dfpow.meets_target(digest, 256))
        self.assertFalse(dfpow.verify(CHAIN_ID, EPOCH, header(1000, difficulty=256), dataset=self.dataset))
        self.assertTrue(dfpow.verify(CHAIN_ID, EPOCH, header(1000, difficulty=0), dataset=self.dataset))
        # Difficulty is inside the preimage, so the difficulty-0 header is a different hash,
        # and that hash is still accepted because every digest meets difficulty 0.
        easy = header(1000, difficulty=0)
        self.assertTrue(dfpow.verify(CHAIN_ID, EPOCH, easy, dataset=self.dataset))

    def test_rejects_malformed(self):
        with self.assertRaises(ValueError):
            dfpow.pow_hash(b"short", EPOCH, header(1), dataset=self.dataset)
        with self.assertRaises(ValueError):
            dfpow.make_header(1, b"\x00" * 31, MERKLE, TIMESTAMP, 1, 1)
        self.assertFalse(dfpow.verify(CHAIN_ID, EPOCH, b"\x00" * 80))

    def test_frozen_vector(self):
        digest, trace = dfpow.pow_hash(
            CHAIN_ID, EPOCH, header(1000), dataset=self.dataset, trace=True
        )
        self.assertEqual(trace["seed"].hex(), FROZEN["1000"]["seed"])
        self.assertEqual(digest.hex(), FROZEN["1000"]["digest"])
        self.assertEqual(trace["color_names"][:16], FROZEN["1000"]["schedule"])
        self.assertEqual(trace["addr"], FROZEN["1000"]["addr"])
        other = dfpow.pow_hash(CHAIN_ID, EPOCH, header(1001), dataset=self.dataset)
        self.assertEqual(other.hex(), FROZEN["1001"]["digest"])
        delta = int.from_bytes(digest, "big") ^ int.from_bytes(other, "big")
        self.assertEqual(delta.bit_count(), 121)

    def test_mined_difficulty_8(self):
        mined = header(37, difficulty=8)
        digest = dfpow.pow_hash(CHAIN_ID, EPOCH, mined, dataset=self.dataset)
        self.assertEqual(digest.hex(), FROZEN["mined8"]["digest"])
        self.assertTrue(dfpow.meets_target(digest, 8))
        self.assertFalse(dfpow.meets_target(digest, 9))
        self.assertTrue(dfpow.verify(CHAIN_ID, EPOCH, mined, dataset=self.dataset))
        self.assertFalse(
            dfpow.verify(CHAIN_ID, EPOCH, header(37, difficulty=20), dataset=self.dataset)
        )


# Locked to python/dfpow.py. A consensus change updates these and docs/DFPoW-256.md together.
FROZEN = {
    "1000": {
        "seed": "2c2c49235865dacb38705af9f0aac7153f981861580369b144db23ec785ae7cb",
        "digest": "747c88f9f23c23a9636cfdc88e452c99e804905acd587a2b7e9bfcb3e7850640",
        "addr": 1106646132,
        "schedule": [
            "XOR", "XORROT", "ADDROT", "MUL", "ROT", "ADD", "MIX", "SBOX",
            "ADDROT", "ADD", "XORROT", "SBOX", "XOR", "MUL", "MIX", "ROT",
        ],
    },
    "1001": {
        "digest": "6408cb97b29fd2ca8ac52af08b806253af719d453fd866c2b5efb4b0b07c28cc",
    },
    "mined8": {
        "digest": "00a02a44532a21a5adc26d4a7041a0b7d28de0c222b55910f0c051fc34e3e978",
    },
}


if __name__ == "__main__":
    unittest.main()
