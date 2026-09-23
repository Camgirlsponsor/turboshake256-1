"""DFPoW-256 draft 0.1 reference.

Normative description: docs/DFPoW-256.md.
This module is a direct implementation of that draft. Integers are
unsigned 32-bit unless a product is explicitly widened to 64 bits.
"""

from __future__ import annotations

import struct
from blake3 import blake3

MASK32 = 0xFFFFFFFF

DATASET_BYTES = 1 << 20  # 1 MiB
SCRATCH_BYTES = 1 << 11  # 2 KiB
ROUNDS = 256

DATASET_WORDS = DATASET_BYTES // 4
SCRATCH_WORDS = SCRATCH_BYTES // 4
DATASET_MASK = DATASET_WORDS - 1
SCRATCH_MASK = SCRATCH_WORDS - 1

HEADER_BYTES = 84
PREFIX_BYTES = 76

COLOR_NAMES = (
    "XOR",
    "ADD",
    "ROT",
    "MUL",
    "SBOX",
    "XORROT",
    "ADDROT",
    "MIX",
)

PARAMS = struct.pack("<III", DATASET_BYTES, SCRATCH_BYTES, ROUNDS)


def _tag(label: str) -> bytes:
    raw = label.encode("ascii")
    if len(raw) > 16:
        raise ValueError(f"domain tag longer than 16 bytes: {label}")
    return raw.ljust(16, b"\x00")


DOMAIN_SEED = _tag("DFPW-SEED-v01")
DOMAIN_DATA = _tag("DFPW-DATA-v01")
DOMAIN_PROG = _tag("DFPW-PROG-v01")
DOMAIN_FINAL = _tag("DFPW-FINAL-v01")


def _check_sizes() -> None:
    if DATASET_BYTES < 8 or DATASET_BYTES & (DATASET_BYTES - 1):
        raise RuntimeError("DATASET_BYTES must be a power of two and at least 8")
    if SCRATCH_BYTES < 32 or SCRATCH_BYTES & (SCRATCH_BYTES - 1):
        raise RuntimeError("SCRATCH_BYTES must be a power of two and at least 32")
    if DATASET_BYTES > MASK32 or SCRATCH_BYTES > MASK32:
        raise RuntimeError("sizes must fit in a uint32 parameter word")
    if ROUNDS < 8 or ROUNDS % 8:
        raise RuntimeError("ROUNDS must be a positive multiple of 8")
    if DATASET_BYTES < SCRATCH_BYTES:
        raise RuntimeError("dataset must be at least as large as the scratchpad")


_check_sizes()


def rotl32(value: int, n: int) -> int:
    n &= 31
    value &= MASK32
    if n == 0:
        return value
    return ((value << n) | (value >> (32 - n))) & MASK32


def tape_bytes(rounds: int = ROUNDS) -> int:
    """Fixed program-tape length: 255 S-box bytes, 12 bytes per round, 7 per color group."""
    groups = rounds // 8
    return 255 + (rounds * 12) + (groups * 7)


def _as_bytes(name: str, value: bytes, length: int) -> bytes:
    if not isinstance(value, (bytes, bytearray)) or len(value) != length:
        raise ValueError(f"{name} must be exactly {length} bytes")
    return bytes(value)


def make_header(
    version: int,
    prev_hash: bytes,
    merkle_root: bytes,
    timestamp: int,
    difficulty: int,
    nonce: int,
) -> bytes:
    """Pack an 84-byte header. Every integer is little-endian."""
    prev_hash = _as_bytes("prev_hash", prev_hash, 32)
    merkle_root = _as_bytes("merkle_root", merkle_root, 32)
    for name, number, limit in (
        ("version", version, 32),
        ("timestamp", timestamp, 32),
        ("difficulty", difficulty, 32),
        ("nonce", nonce, 64),
    ):
        if not isinstance(number, int) or not 0 <= number < (1 << limit):
            raise ValueError(f"{name} out of range")
    return (
        struct.pack("<I", version)
        + prev_hash
        + merkle_root
        + struct.pack("<IIQ", timestamp, difficulty, nonce)
    )


def split_header(header: bytes) -> tuple[bytes, bytes, int]:
    header = _as_bytes("header", header, HEADER_BYTES)
    prefix = header[:PREFIX_BYTES]
    nonce = header[PREFIX_BYTES:]
    difficulty = struct.unpack_from("<I", header, 72)[0]
    return prefix, nonce, difficulty


def target_for_difficulty(difficulty: int) -> int:
    """Largest 256-bit value accepted at this difficulty.

    A uniform hash meets the target with probability exactly 2^(-difficulty).
    """
    if not isinstance(difficulty, int) or not 0 <= difficulty <= 256:
        raise ValueError("difficulty must be an integer in 0..256")
    return (1 << (256 - difficulty)) - 1


def hash_to_int(digest: bytes) -> int:
    """Interpret a 32-byte digest as a big-endian integer (byte 0 is the MSB)."""
    digest = _as_bytes("digest", digest, 32)
    return int.from_bytes(digest, "big")


def meets_target(digest: bytes, difficulty: int) -> bool:
    if not isinstance(difficulty, int) or difficulty > 256:
        return False
    if difficulty < 0:
        return False
    return hash_to_int(digest) <= target_for_difficulty(difficulty)


def block_work(difficulty: int) -> int:
    """Expected hash attempts represented by a block. Sum these, not the raw difficulties."""
    if not isinstance(difficulty, int) or not 0 <= difficulty <= 256:
        raise ValueError("difficulty must be an integer in 0..256")
    return 1 << difficulty


def _xof(preimage: bytes, length: int) -> bytes:
    return blake3(preimage).digest(length=length)


def build_dataset(chain_id: bytes, epoch_seed: bytes) -> list[int]:
    """Build the read-only epoch dataset.

    Word i of the finished dataset depends on every XOF output byte, so a
    caller cannot seek to a single word without computing the whole buffer.
    """
    chain_id = _as_bytes("chain_id", chain_id, 16)
    epoch_seed = _as_bytes("epoch_seed", epoch_seed, 32)
    raw = _xof(DOMAIN_DATA + chain_id + PARAMS + epoch_seed, DATASET_BYTES)
    words = DATASET_WORDS
    dataset = [0] * words
    mixed = int.from_bytes(epoch_seed[:4], "little") ^ int.from_bytes(
        epoch_seed[4:8], "little"
    )
    mul = 0x9E3779B9
    for i in range(words):
        entropy = int.from_bytes(raw[i * 4 : (i + 1) * 4], "little")
        mixed = (rotl32(mixed ^ entropy, 7) * mul) & MASK32
        dataset[i] = mixed
    for i in range(words - 2, -1, -1):
        dataset[i] = (dataset[i] ^ rotl32(dataset[i + 1], 5)) & MASK32
    return dataset


def make_seed(chain_id: bytes, epoch_seed: bytes, prefix: bytes, nonce: bytes) -> bytes:
    chain_id = _as_bytes("chain_id", chain_id, 16)
    epoch_seed = _as_bytes("epoch_seed", epoch_seed, 32)
    prefix = _as_bytes("prefix", prefix, PREFIX_BYTES)
    nonce = _as_bytes("nonce", nonce, 8)
    return blake3(DOMAIN_SEED + chain_id + PARAMS + epoch_seed + prefix + nonce).digest()


def make_tape(chain_id: bytes, seed: bytes) -> bytes:
    chain_id = _as_bytes("chain_id", chain_id, 16)
    seed = _as_bytes("seed", seed, 32)
    return _xof(DOMAIN_PROG + chain_id + PARAMS + seed, tape_bytes())


class _Stream:
    def __init__(self, data: bytes):
        self.data = data
        self.i = 0

    def pull(self, n: int) -> bytes:
        nxt = self.i + n
        if nxt > len(self.data):
            raise RuntimeError("program tape ended early")
        chunk = self.data[self.i : nxt]
        self.i = nxt
        return chunk

    def u8(self) -> int:
        return self.pull(1)[0]

    def u32(self) -> int:
        return int.from_bytes(self.pull(4), "little")


def _fisher_yates(items: list[int], stream: _Stream) -> list[int]:
    """Biased, fixed-length Fisher-Yates. Always a permutation, never loops."""
    for i in range(len(items) - 1, 0, -1):
        j = stream.u8() % (i + 1)
        items[i], items[j] = items[j], items[i]
    return items


def parse_tape(tape: bytes) -> tuple[list[int], list[tuple[int, int, int, int, int, int]], list[int]]:
    stream = _Stream(tape)
    sbox = _fisher_yates(list(range(256)), stream)
    rounds: list[tuple[int, int, int, int, int, int]] = []
    for _ in range(ROUNDS):
        constant = stream.u32()
        rotation = (stream.u8() % 31) + 1
        b0 = stream.u8()
        b1 = stream.u8()
        b2 = stream.u8()
        multiplier = stream.u32() | 0x80000001
        rounds.append((constant, rotation, b0, b1, b2, multiplier))
    colors: list[int] = []
    for _ in range(ROUNDS // 8):
        colors.extend(_fisher_yates(list(range(8)), stream))
    if stream.i != len(tape):
        raise RuntimeError("program tape was not fully consumed")
    return sbox, rounds, colors


def select_indices(pinned: int, b0: int, b1: int, b2: int) -> tuple[int, int, int, int]:
    """Four distinct registers. Index 0 of the result is always `pinned`."""
    pool = [i for i in range(8) if i != pinned]
    i1 = pool.pop(b0 % 7)
    i2 = pool.pop(b1 % 6)
    i3 = pool.pop(b2 % 5)
    return pinned, i1, i2, i3


def apply_sbox(sbox: list[int], word: int) -> int:
    return (
        sbox[word & 0xFF]
        | (sbox[(word >> 8) & 0xFF] << 8)
        | (sbox[(word >> 16) & 0xFF] << 16)
        | (sbox[(word >> 24) & 0xFF] << 24)
    )


def quarter_round(state: list[int], i0: int, i1: int, i2: int, i3: int) -> None:
    """ChaCha quarter round. Rotations stay fixed so a schedule cannot weaken them."""
    a = state[i0]
    b = state[i1]
    c = state[i2]
    d = state[i3]
    a = (a + b) & MASK32
    d = rotl32(d ^ a, 16)
    c = (c + d) & MASK32
    b = rotl32(b ^ c, 12)
    a = (a + b) & MASK32
    d = rotl32(d ^ a, 8)
    c = (c + d) & MASK32
    b = rotl32(b ^ c, 7)
    state[i0] = a
    state[i1] = b
    state[i2] = c
    state[i3] = d


def apply_accent(
    op: int,
    state: list[int],
    i0: int,
    i1: int,
    i2: int,
    i3: int,
    sbox: list[int],
    multiplier: int,
    rotation: int,
    dataset: list[int],
    addr: int,
) -> int:
    a = state[i0]
    b = state[i1]
    c = state[i2]
    d = state[i3]
    if op == 0:  # XOR
        c ^= a ^ b
        d ^= rotl32(c, rotation)
    elif op == 1:  # ADD
        c = (c + a + b) & MASK32
        d ^= c
    elif op == 2:  # ROT
        c = rotl32(a, rotation) ^ b
        d ^= rotl32(c, 8)
    elif op == 3:  # MUL
        product = b * multiplier
        lo = product & MASK32
        hi = (product >> 32) & MASK32
        b = lo
        c ^= lo
        d ^= hi
    elif op == 4:  # SBOX
        c ^= apply_sbox(sbox, a)
        d ^= apply_sbox(sbox, b)
    elif op == 5:  # XORROT
        c ^= a ^ rotl32(b, rotation)
        d = (d + c) & MASK32
    elif op == 6:  # ADDROT
        c = (a + rotl32(b, rotation)) & MASK32
        d ^= rotl32(c, 8)
    elif op == 7:  # MIX
        value = dataset[(addr + a + c) & DATASET_MASK]
        a ^= value
        b = (b + value) & MASK32
        c ^= rotl32(value, rotation)
        d ^= value
        addr = (addr + value + b) & MASK32
    else:
        raise RuntimeError(f"unknown accent {op}")
    state[i0] = a & MASK32
    state[i1] = b & MASK32
    state[i2] = c & MASK32
    state[i3] = d & MASK32
    return addr


def memory_step(
    state: list[int],
    i0: int,
    i1: int,
    i2: int,
    i3: int,
    constant: int,
    rotation: int,
    dataset: list[int],
    scratch: list[int],
    addr: int,
) -> int:
    a = state[i0]
    b = state[i1]
    c = state[i2]
    d = state[i3]
    value = dataset[(addr + c) & DATASET_MASK]
    scratch_index = (a ^ value) & SCRATCH_MASK
    saved = scratch[scratch_index]
    b ^= saved
    d = (d + value) & MASK32
    scratch[scratch_index] = rotl32(((saved ^ a ^ constant) + value) & MASK32, 5)
    addr = (b + rotl32(value ^ saved, 3)) & MASK32
    a ^= rotl32(value, rotation)
    state[i0] = a & MASK32
    state[i1] = b & MASK32
    state[i2] = c & MASK32
    state[i3] = d & MASK32
    return addr


def init_state(seed: bytes, nonce: bytes) -> list[int]:
    state = [int.from_bytes(seed[i * 4 : (i + 1) * 4], "little") for i in range(8)]
    state[0] ^= int.from_bytes(nonce[:4], "little")
    state[1] ^= int.from_bytes(nonce[4:], "little")
    return state


def init_scratch(dataset: list[int], state: list[int]) -> list[int]:
    scratch = [0] * SCRATCH_WORDS
    origin = state[3] & DATASET_MASK
    tumbler = state[5] | 1
    for i in range(SCRATCH_WORDS):
        scratch[i] = (
            dataset[(origin + i) & DATASET_MASK] ^ rotl32(tumbler, i & 31) ^ (i & MASK32)
        ) & MASK32
    return scratch


def fold_scratch(state: list[int], scratch: list[int], addr: int) -> int:
    """Commit every scratch word.

    Rounds touch only some of the pad. Without this sweep, a caller could
    skip the initialisation of unread words and still match the digest.
    """
    acc = addr & MASK32
    for i, word in enumerate(scratch):
        acc = (
            rotl32((acc + word) & MASK32, 5) ^ ((i * 0x9E3779B9) & MASK32)
        ) & MASK32
    for i in range(8):
        state[i] = (state[i] ^ rotl32(acc, (i * 4 + 1) & 31)) & MASK32
        acc = rotl32(acc ^ state[i], 3)
    return acc


def execute_program(
    dataset: list[int],
    sbox: list[int],
    rounds: list[tuple[int, int, int, int, int, int]],
    colors: list[int],
    state: list[int],
    scratch: list[int],
) -> int:
    addr = state[7]
    for index in range(ROUNDS):
        constant, rotation, b0, b1, b2, multiplier = rounds[index]
        i0, i1, i2, i3 = select_indices(index & 7, b0, b1, b2)
        constant_eff = (constant ^ index) & MASK32
        state[i0] = (state[i0] ^ constant_eff) & MASK32
        quarter_round(state, i0, i1, i2, i3)
        addr = apply_accent(
            colors[index],
            state,
            i0,
            i1,
            i2,
            i3,
            sbox,
            multiplier,
            rotation,
            dataset,
            addr,
        )
        addr = memory_step(
            state,
            i0,
            i1,
            i2,
            i3,
            constant_eff,
            rotation,
            dataset,
            scratch,
            addr,
        )
    return fold_scratch(state, scratch, addr)


def finalize(
    chain_id: bytes,
    epoch_seed: bytes,
    seed: bytes,
    state: list[int],
    addr: int,
    scratch: list[int],
    dataset: list[int],
) -> bytes:
    out = bytearray()
    out += DOMAIN_FINAL
    out += chain_id
    out += PARAMS
    out += epoch_seed
    out += seed
    for word in state:
        out += struct.pack("<I", word & MASK32)
    out += struct.pack("<I", addr & MASK32)
    for i in range(8):
        idx = (state[i] + (i * 0x9E3779B9)) & SCRATCH_MASK
        out += struct.pack("<I", scratch[idx])
    for i in range(8):
        idx = (state[i] ^ addr ^ (i * 0x85EBCA6B)) & DATASET_MASK
        out += struct.pack("<I", dataset[idx])
    if len(out) != 208:
        raise RuntimeError(f"finalizer preimage is {len(out)} bytes, expected 208")
    return blake3(bytes(out)).digest()


def derive_program(chain_id: bytes, epoch_seed: bytes, header: bytes) -> dict:
    """Derive the nonce-specific program without executing it."""
    chain_id = _as_bytes("chain_id", chain_id, 16)
    epoch_seed = _as_bytes("epoch_seed", epoch_seed, 32)
    prefix, nonce, difficulty = split_header(header)
    seed = make_seed(chain_id, epoch_seed, prefix, nonce)
    sbox, rounds, colors = parse_tape(make_tape(chain_id, seed))
    return {
        "seed": seed,
        "difficulty": difficulty,
        "sbox": sbox,
        "rounds": rounds,
        "colors": colors,
        "color_names": [COLOR_NAMES[c] for c in colors],
    }


def pow_hash(
    chain_id: bytes,
    epoch_seed: bytes,
    header: bytes,
    dataset: list[int] | None = None,
    trace: bool = False,
):
    """Compute the 32-byte PoW digest of one header.

    `dataset` may be the cached result of build_dataset(chain_id, epoch_seed).
    Passing a dataset built from different inputs is a caller bug and yields
    a digest the network will reject.
    """
    chain_id = _as_bytes("chain_id", chain_id, 16)
    epoch_seed = _as_bytes("epoch_seed", epoch_seed, 32)
    prefix, nonce, _difficulty = split_header(header)
    if dataset is None:
        dataset = build_dataset(chain_id, epoch_seed)
    elif len(dataset) != DATASET_WORDS:
        raise ValueError("dataset has the wrong length")
    seed = make_seed(chain_id, epoch_seed, prefix, nonce)
    sbox, rounds, colors = parse_tape(make_tape(chain_id, seed))
    state = init_state(seed, nonce)
    scratch = init_scratch(dataset, state)
    addr = execute_program(dataset, sbox, rounds, colors, state, scratch)
    digest = finalize(chain_id, epoch_seed, seed, state, addr, scratch, dataset)
    if not trace:
        return digest
    return digest, {
        "seed": seed,
        "colors": colors,
        "color_names": [COLOR_NAMES[c] for c in colors],
        "sbox": sbox,
        "state": state.copy(),
        "addr": addr,
        "multipliers": [item[5] for item in rounds],
        "rotations": [item[1] for item in rounds],
        "scratch_xor": _xor_words(scratch),
    }


def _xor_words(words: list[int]) -> int:
    folded = 0
    for word in words:
        folded ^= word
    return folded


def verify(
    chain_id: bytes,
    epoch_seed: bytes,
    header: bytes,
    dataset: list[int] | None = None,
) -> bool:
    """Recompute the digest and compare it with the header's difficulty."""
    try:
        _prefix, _nonce, difficulty = split_header(header)
    except ValueError:
        return False
    if difficulty > 256:
        return False
    digest = pow_hash(chain_id, epoch_seed, header, dataset=dataset)
    return meets_target(digest, difficulty)


def mine(
    chain_id: bytes,
    epoch_seed: bytes,
    version: int,
    prev_hash: bytes,
    merkle_root: bytes,
    timestamp: int,
    difficulty: int,
    start_nonce: int = 0,
    limit: int = 1_000_000,
    dataset: list[int] | None = None,
) -> tuple[int, bytes] | None:
    """Search a nonce range. Returns (nonce, digest) or None if the range is exhausted."""
    if dataset is None:
        dataset = build_dataset(chain_id, epoch_seed)
    for nonce in range(start_nonce, start_nonce + limit):
        header = make_header(version, prev_hash, merkle_root, timestamp, difficulty, nonce)
        digest = pow_hash(chain_id, epoch_seed, header, dataset=dataset)
        if meets_target(digest, difficulty):
            return nonce, digest
    return None
