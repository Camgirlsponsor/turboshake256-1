/* DFPoW-256 draft 0.1, one nonce per work-item.
 *
 * The epoch dataset is built on the host and uploaded. Each work-item mixes
 * its own nonce into a BLAKE3 seed, expands that seed into the 256-round
 * program, and walks a private 512-word scratchpad. Digests are the same
 * bytes as python/dfpow.py and internal/dfpow.
 *
 * Every BLAKE3 preimage in this construction is at most 208 bytes, so the
 * hasher only implements a single-chunk unkeyed BLAKE3. The 1 MiB dataset
 * is an XOF of a 76-byte preimage, not a hash of a 1 MiB message.
 */

#ifndef DFPOW_GPU_CL_INCLUDED
#define DFPOW_GPU_CL_INCLUDED

#ifdef __OPENCL_VERSION__
typedef uchar u8;
typedef uint u32;
typedef ulong u64;
#define PRIV __private
#define GLOB __global
#define CST __constant
#else
#include <stddef.h>
#include <stdint.h>
typedef uint8_t u8;
typedef uint32_t u32;
typedef uint64_t u64;
#define PRIV
#define GLOB
#define CST static const
#endif

#define DFPOW_DATASET_BYTES 1048576u
#define DFPOW_DATASET_WORDS 262144u
#define DFPOW_SCRATCH_WORDS 512u
#define DFPOW_ROUNDS 256u
#define DFPOW_TAPE_BYTES 3551u
#define DFPOW_DATASET_MASK 262143u
#define DFPOW_SCRATCH_MASK 511u

#define BLAKE3_CHUNK_START 1u
#define BLAKE3_CHUNK_END 2u
#define BLAKE3_ROOT 8u

CST u32 BLAKE3_IV[8] = {
    0x6A09E667u, 0xBB67AE85u, 0x3C6EF372u, 0xA54FF53Au,
    0x510E527Fu, 0x9B05688Cu, 0x1F83D9ABu, 0x5BE0CD19u};

/* 16-byte domain tags, NUL-padded. 0 seed, 1 data, 2 program, 3 finalizer. */
CST u8 DFPOW_DOMAIN[4][16] = {
    {'D', 'F', 'P', 'W', '-', 'S', 'E', 'E', 'D', '-', 'v', '0', '1', 0, 0, 0},
    {'D', 'F', 'P', 'W', '-', 'D', 'A', 'T', 'A', '-', 'v', '0', '1', 0, 0, 0},
    {'D', 'F', 'P', 'W', '-', 'P', 'R', 'O', 'G', '-', 'v', '0', '1', 0, 0, 0},
    {'D', 'F', 'P', 'W', '-', 'F', 'I', 'N', 'A', 'L', '-', 'v', '0', '1', 0, 0}};

/* Standard BLAKE3 message schedule. Row r+1 is the fixed permutation of row r. */
CST u8 BLAKE3_MSG_SCHEDULE[7][16] = {
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
    {2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8},
    {3, 4, 10, 12, 13, 2, 7, 14, 6, 5, 9, 0, 11, 15, 8, 1},
    {10, 7, 12, 9, 14, 3, 13, 15, 4, 0, 11, 2, 5, 8, 1, 6},
    {12, 13, 9, 11, 15, 10, 14, 8, 7, 2, 5, 3, 0, 1, 6, 4},
    {9, 14, 11, 5, 8, 12, 15, 1, 13, 3, 0, 10, 2, 6, 4, 7},
    {11, 15, 5, 0, 1, 9, 8, 6, 14, 10, 2, 12, 3, 4, 7, 13}};

static u32 load32(PRIV const u8 *p) {
    return (u32)p[0] | ((u32)p[1] << 8) | ((u32)p[2] << 16) | ((u32)p[3] << 24);
}

static void store32(PRIV u8 *p, u32 v) {
    p[0] = (u8)v;
    p[1] = (u8)(v >> 8);
    p[2] = (u8)(v >> 16);
    p[3] = (u8)(v >> 24);
}

/* A zero count must return x unchanged. `i & 31` is zero every 32 scratch words,
 * and a shift of 32 is undefined in both C and OpenCL. */
static u32 rotl32(u32 x, u32 n) {
    n &= 31u;
    if (n == 0u) {
        return x;
    }
    return (x << n) | (x >> (32u - n));
}

static u32 rotr32(u32 x, u32 n) {
    return (x >> n) | (x << (32u - n));
}

static void blake3_g(PRIV u32 *st, int a, int b, int c, int d, u32 mx, u32 my) {
    st[a] = st[a] + st[b] + mx;
    st[d] = rotr32(st[d] ^ st[a], 16u);
    st[c] = st[c] + st[d];
    st[b] = rotr32(st[b] ^ st[c], 12u);
    st[a] = st[a] + st[b] + my;
    st[d] = rotr32(st[d] ^ st[a], 8u);
    st[c] = st[c] + st[d];
    st[b] = rotr32(st[b] ^ st[c], 7u);
}

static void blake3_compress(PRIV const u32 *cv, PRIV const u8 *block, u32 block_len,
                            u64 counter, u32 flags, PRIV u32 *st) {
    int i;
    u32 m[16];
    for (i = 0; i < 8; i++) {
        st[i] = cv[i];
    }
    st[8] = BLAKE3_IV[0];
    st[9] = BLAKE3_IV[1];
    st[10] = BLAKE3_IV[2];
    st[11] = BLAKE3_IV[3];
    st[12] = (u32)counter;
    st[13] = (u32)(counter >> 32);
    st[14] = block_len;
    st[15] = flags;
    for (i = 0; i < 16; i++) {
        m[i] = load32(block + i * 4);
    }
    for (i = 0; i < 7; i++) {
        blake3_g(st, 0, 4, 8, 12, m[BLAKE3_MSG_SCHEDULE[i][0]], m[BLAKE3_MSG_SCHEDULE[i][1]]);
        blake3_g(st, 1, 5, 9, 13, m[BLAKE3_MSG_SCHEDULE[i][2]], m[BLAKE3_MSG_SCHEDULE[i][3]]);
        blake3_g(st, 2, 6, 10, 14, m[BLAKE3_MSG_SCHEDULE[i][4]], m[BLAKE3_MSG_SCHEDULE[i][5]]);
        blake3_g(st, 3, 7, 11, 15, m[BLAKE3_MSG_SCHEDULE[i][6]], m[BLAKE3_MSG_SCHEDULE[i][7]]);
        blake3_g(st, 0, 5, 10, 15, m[BLAKE3_MSG_SCHEDULE[i][8]], m[BLAKE3_MSG_SCHEDULE[i][9]]);
        blake3_g(st, 1, 6, 11, 12, m[BLAKE3_MSG_SCHEDULE[i][10]], m[BLAKE3_MSG_SCHEDULE[i][11]]);
        blake3_g(st, 2, 7, 8, 13, m[BLAKE3_MSG_SCHEDULE[i][12]], m[BLAKE3_MSG_SCHEDULE[i][13]]);
        blake3_g(st, 3, 4, 9, 14, m[BLAKE3_MSG_SCHEDULE[i][14]], m[BLAKE3_MSG_SCHEDULE[i][15]]);
    }
}

static void blake3_compress_inplace(PRIV u32 *cv, PRIV const u8 *block, u32 block_len,
                                    u64 counter, u32 flags) {
    u32 st[16];
    int i;
    blake3_compress(cv, block, block_len, counter, flags, st);
    for (i = 0; i < 8; i++) {
        cv[i] = st[i] ^ st[i + 8];
    }
}

static void blake3_compress_xof(PRIV const u32 *cv, PRIV const u8 *block, u32 block_len,
                                u64 counter, u32 flags, PRIV u8 *out) {
    u32 st[16];
    int i;
    blake3_compress(cv, block, block_len, counter, flags, st);
    for (i = 0; i < 8; i++) {
        u32 lo = st[i] ^ st[i + 8];
        u32 hi = st[i + 8] ^ cv[i];
        store32(out + i * 4, lo);
        store32(out + 32 + i * 4, hi);
    }
}

/* Unkeyed XOF of one chunk. input_len must be <= 1024. */
void dfpow_blake3_xof(PRIV const u8 *input, u32 input_len, PRIV u8 *out, u32 out_len) {
    u32 cv[8];
    u8 block[64];
    u32 block_len = 0;
    u32 blocks_compressed = 0;
    u32 off = 0;
    u32 produced = 0;
    u64 counter = 0;
    u32 flags;
    int i;

    for (i = 0; i < 8; i++) {
        cv[i] = BLAKE3_IV[i];
    }
    for (i = 0; i < 64; i++) {
        block[i] = 0;
    }
    while (off < input_len) {
        u32 take = 64u - block_len;
        if (take > input_len - off) {
            take = input_len - off;
        }
        for (i = 0; i < (int)take; i++) {
            block[block_len + (u32)i] = input[off + (u32)i];
        }
        block_len += take;
        off += take;
        /* The last block stays buffered so the root output can re-compress it
         * with an output counter. A full block is absorbed only when more
         * input follows. */
        if (block_len == 64u && off < input_len) {
            flags = (blocks_compressed == 0u) ? BLAKE3_CHUNK_START : 0u;
            blake3_compress_inplace(cv, block, 64u, 0, flags);
            blocks_compressed++;
            block_len = 0;
            for (i = 0; i < 64; i++) {
                block[i] = 0;
            }
        }
    }
    flags = BLAKE3_CHUNK_END | BLAKE3_ROOT;
    if (blocks_compressed == 0u) {
        flags |= BLAKE3_CHUNK_START;
    }
    while (produced < out_len) {
        u8 wide[64];
        u32 n = out_len - produced;
        blake3_compress_xof(cv, block, block_len, counter, flags, wide);
        if (n > 64u) {
            n = 64u;
        }
        for (i = 0; i < (int)n; i++) {
            out[produced + (u32)i] = wide[i];
        }
        produced += n;
        counter++;
    }
}

static void write_domain(PRIV u8 *dst, u32 kind) {
    int i;
    for (i = 0; i < 16; i++) {
        dst[i] = DFPOW_DOMAIN[kind][i];
    }
}

static void write_params(PRIV u8 *dst) {
    store32(dst, DFPOW_DATASET_BYTES);
    store32(dst + 4, DFPOW_SCRATCH_WORDS * 4u);
    store32(dst + 8, DFPOW_ROUNDS);
}

static void select_indices(u32 pinned, u32 b0, u32 b1, u32 b2, PRIV int *i0, PRIV int *i1,
                           PRIV int *i2, PRIV int *i3) {
    int pool[7];
    int n = 0;
    int i;
    u32 idx;
    u32 j;
    for (i = 0; i < 8; i++) {
        if ((u32)i != pinned) {
            pool[n++] = i;
        }
    }
    *i0 = (int)pinned;
    idx = b0 % 7u;
    *i1 = pool[idx];
    for (j = idx; j < 6u; j++) {
        pool[j] = pool[j + 1u];
    }
    idx = b1 % 6u;
    *i2 = pool[idx];
    for (j = idx; j < 5u; j++) {
        pool[j] = pool[j + 1u];
    }
    *i3 = pool[b2 % 5u];
}

static void quarter_round(PRIV u32 *state, int i0, int i1, int i2, int i3) {
    u32 a = state[i0];
    u32 b = state[i1];
    u32 c = state[i2];
    u32 d = state[i3];
    a += b;
    d = rotl32(d ^ a, 16u);
    c += d;
    b = rotl32(b ^ c, 12u);
    a += b;
    d = rotl32(d ^ a, 8u);
    c += d;
    b = rotl32(b ^ c, 7u);
    state[i0] = a;
    state[i1] = b;
    state[i2] = c;
    state[i3] = d;
}

static u32 apply_sbox(PRIV const u8 *sbox, u32 word) {
    return (u32)sbox[word & 0xffu] | ((u32)sbox[(word >> 8) & 0xffu] << 8) |
           ((u32)sbox[(word >> 16) & 0xffu] << 16) | ((u32)sbox[(word >> 24) & 0xffu] << 24);
}

static u32 apply_accent(u32 op, PRIV u32 *state, int i0, int i1, int i2, int i3,
                        PRIV const u8 *sbox, u32 multiplier, u32 rotation,
                        GLOB const u32 *dataset, u32 addr) {
    u32 a = state[i0];
    u32 b = state[i1];
    u32 c = state[i2];
    u32 d = state[i3];
    if (op == 0u) {
        c ^= a ^ b;
        d ^= rotl32(c, rotation);
    } else if (op == 1u) {
        c += a + b;
        d ^= c;
    } else if (op == 2u) {
        c = rotl32(a, rotation) ^ b;
        d ^= rotl32(c, 8u);
    } else if (op == 3u) {
        u64 product = (u64)b * (u64)multiplier;
        u32 lo = (u32)product;
        u32 hi = (u32)(product >> 32);
        b = lo;
        c ^= lo;
        d ^= hi;
    } else if (op == 4u) {
        c ^= apply_sbox(sbox, a);
        d ^= apply_sbox(sbox, b);
    } else if (op == 5u) {
        c ^= a ^ rotl32(b, rotation);
        d += c;
    } else if (op == 6u) {
        c = a + rotl32(b, rotation);
        d ^= rotl32(c, 8u);
    } else if (op == 7u) {
        u32 value = dataset[(addr + a + c) & DFPOW_DATASET_MASK];
        a ^= value;
        b += value;
        c ^= rotl32(value, rotation);
        d ^= value;
        addr = addr + value + b;
    }
    state[i0] = a;
    state[i1] = b;
    state[i2] = c;
    state[i3] = d;
    return addr;
}

static u32 memory_step(PRIV u32 *state, int i0, int i1, int i2, int i3, u32 kword,
                       u32 rotation, GLOB const u32 *dataset, PRIV u32 *scratch, u32 addr) {
    u32 a = state[i0];
    u32 b = state[i1];
    u32 c = state[i2];
    u32 d = state[i3];
    u32 value = dataset[(addr + c) & DFPOW_DATASET_MASK];
    u32 sidx = (a ^ value) & DFPOW_SCRATCH_MASK;
    u32 saved = scratch[sidx];
    b ^= saved;
    d += value;
    scratch[sidx] = rotl32((saved ^ a ^ kword) + value, 5u);
    addr = b + rotl32(value ^ saved, 3u);
    a ^= rotl32(value, rotation);
    state[i0] = a;
    state[i1] = b;
    state[i2] = c;
    state[i3] = d;
    return addr;
}

static u32 fold_scratch(PRIV u32 *state, PRIV const u32 *scratch, u32 addr) {
    u32 acc = addr;
    u32 i;
    for (i = 0; i < DFPOW_SCRATCH_WORDS; i++) {
        acc = rotl32(acc + scratch[i], 5u) ^ (u32)((u64)i * 0x9E3779B9u);
    }
    for (i = 0; i < 8u; i++) {
        state[i] ^= rotl32(acc, (i * 4u + 1u) & 31u);
        acc = rotl32(acc ^ state[i], 3u);
    }
    return acc;
}

void dfpow_eval(GLOB const u32 *dataset, PRIV const u8 *chain, PRIV const u8 *epoch,
                PRIV const u8 *prefix, u64 nonce, PRIV u8 *digest, PRIV u8 *seed_out,
                PRIV u32 *addr_out, PRIV u8 *opening) {
    u8 pre[208];
    u8 seed[32];
    u8 tape[DFPOW_TAPE_BYTES];
    u8 sbox[256];
    u8 colors[DFPOW_ROUNDS];
    u32 scratch[DFPOW_SCRATCH_WORDS];
    u32 state[8];
    u32 addr;
    u32 origin;
    u32 tumbler;
    int i;
    int ti;
    int ci;
    u32 r;

    for (i = 0; i < 208; i++) {
        pre[i] = 0;
    }
    write_domain(pre, 0u);
    for (i = 0; i < 16; i++) {
        pre[16 + i] = chain[i];
    }
    write_params(pre + 32);
    for (i = 0; i < 32; i++) {
        pre[44 + i] = epoch[i];
    }
    for (i = 0; i < 76; i++) {
        pre[76 + i] = prefix[i];
    }
    store32(pre + 152, (u32)nonce);
    store32(pre + 156, (u32)(nonce >> 32));
    dfpow_blake3_xof(pre, 160u, seed, 32u);
    for (i = 0; i < 32; i++) {
        seed_out[i] = seed[i];
    }

    write_domain(pre, 2u);
    for (i = 0; i < 16; i++) {
        pre[16 + i] = chain[i];
    }
    write_params(pre + 32);
    for (i = 0; i < 32; i++) {
        pre[44 + i] = seed[i];
    }
    dfpow_blake3_xof(pre, 76u, tape, DFPOW_TAPE_BYTES);

    for (i = 0; i < 256; i++) {
        sbox[i] = (u8)i;
    }
    ti = 0;
    for (i = 255; i >= 1; i--) {
        int j = (int)((u32)tape[ti] % (u32)(i + 1));
        u8 tmp = sbox[i];
        ti++;
        sbox[i] = sbox[j];
        sbox[j] = tmp;
    }
    ci = 255 + (int)DFPOW_ROUNDS * 12;
    for (i = 0; i < (int)DFPOW_ROUNDS / 8; i++) {
        u8 order[8];
        int n;
        for (n = 0; n < 8; n++) {
            order[n] = (u8)n;
        }
        for (n = 7; n >= 1; n--) {
            int j = (int)((u32)tape[ci] % (u32)(n + 1));
            u8 tmp = order[n];
            ci++;
            order[n] = order[j];
            order[j] = tmp;
        }
        for (n = 0; n < 8; n++) {
            colors[i * 8 + n] = order[n];
        }
    }
    for (i = 0; i < 8; i++) {
        opening[i] = colors[i];
    }

    for (i = 0; i < 8; i++) {
        state[i] = load32(seed + i * 4);
    }
    state[0] ^= (u32)nonce;
    state[1] ^= (u32)(nonce >> 32);
    origin = state[3] & DFPOW_DATASET_MASK;
    tumbler = state[5] | 1u;
    for (r = 0; r < DFPOW_SCRATCH_WORDS; r++) {
        scratch[r] = dataset[(origin + r) & DFPOW_DATASET_MASK] ^ rotl32(tumbler, r & 31u) ^ r;
    }
    addr = state[7];
    for (r = 0; r < DFPOW_ROUNDS; r++) {
        PRIV const u8 *rec = tape + 255 + r * 12u;
        u32 kword = load32(rec);
        u32 rotation = ((u32)rec[4] % 31u) + 1u;
        u32 multiplier = load32(rec + 8) | 0x80000001u;
        u32 k = kword ^ r;
        int i0, i1, i2, i3;
        select_indices(r & 7u, rec[5], rec[6], rec[7], &i0, &i1, &i2, &i3);
        state[i0] ^= k;
        quarter_round(state, i0, i1, i2, i3);
        addr = apply_accent(colors[r], state, i0, i1, i2, i3, sbox, multiplier, rotation, dataset, addr);
        addr = memory_step(state, i0, i1, i2, i3, k, rotation, dataset, scratch, addr);
    }
    addr = fold_scratch(state, scratch, addr);
    *addr_out = addr;

    write_domain(pre, 3u);
    for (i = 0; i < 16; i++) {
        pre[16 + i] = chain[i];
    }
    write_params(pre + 32);
    for (i = 0; i < 32; i++) {
        pre[44 + i] = epoch[i];
    }
    for (i = 0; i < 32; i++) {
        pre[76 + i] = seed[i];
    }
    for (i = 0; i < 8; i++) {
        store32(pre + 108 + i * 4, state[i]);
    }
    store32(pre + 140, addr);
    for (i = 0; i < 8; i++) {
        u32 idx = (state[i] + (u32)i * 0x9E3779B9u) & DFPOW_SCRATCH_MASK;
        store32(pre + 144 + i * 4, scratch[idx]);
    }
    for (i = 0; i < 8; i++) {
        u32 idx = (state[i] ^ addr ^ ((u32)i * 0x85EBCA6Bu)) & DFPOW_DATASET_MASK;
        store32(pre + 176 + i * 4, dataset[idx]);
    }
    dfpow_blake3_xof(pre, 208u, digest, 32u);
}

#ifndef __OPENCL_VERSION__
void dfpow_make_prefix(u8 prefix[76], u32 version, const u8 prev[32], const u8 merkle[32],
                       u32 timestamp, u32 difficulty) {
    int i;
    for (i = 0; i < 76; i++) {
        prefix[i] = 0;
    }
    store32(prefix, version);
    for (i = 0; i < 32; i++) {
        prefix[4 + i] = prev[i];
    }
    for (i = 0; i < 32; i++) {
        prefix[36 + i] = merkle[i];
    }
    store32(prefix + 68, timestamp);
    store32(prefix + 72, difficulty);
}

void dfpow_dataset_preimage(const u8 chain[16], const u8 epoch[32], u8 out[76]) {
    int i;
    write_domain(out, 1u);
    for (i = 0; i < 16; i++) {
        out[16 + i] = chain[i];
    }
    write_params(out + 32);
    for (i = 0; i < 32; i++) {
        out[44 + i] = epoch[i];
    }
}

void dfpow_expand_dataset(u32 *dataset, const u8 *raw, const u8 *epoch) {
    u32 mixed = load32(epoch) ^ load32(epoch + 4);
    u32 i;
    int j;
    for (i = 0; i < DFPOW_DATASET_WORDS; i++) {
        u32 entropy = load32(raw + i * 4u);
        mixed = rotl32(mixed ^ entropy, 7u) * 0x9E3779B9u;
        dataset[i] = mixed;
    }
    for (j = (int)DFPOW_DATASET_WORDS - 2; j >= 0; j--) {
        dataset[j] ^= rotl32(dataset[j + 1], 5u);
    }
}
#endif

#ifdef __OPENCL_VERSION__
/* prefix is the first 76 header bytes. The difficulty word stays inside it.
 * The nonce is start_nonce + global id, and it is not written back into prefix. */
__kernel void dfpow_batch(__global const u32 *dataset, __global const u8 *chain,
                          __global const u8 *epoch, __global const u8 *prefix, u64 start_nonce,
                          __global u8 *digests) {
    size_t gid = get_global_id(0);
    u8 c[16];
    u8 e[32];
    u8 p[76];
    u8 digest[32];
    u8 seed[32];
    u8 opening[8];
    u32 addr = 0;
    int i;
    __global u8 *out;
    for (i = 0; i < 16; i++) {
        c[i] = chain[i];
    }
    for (i = 0; i < 32; i++) {
        e[i] = epoch[i];
    }
    for (i = 0; i < 76; i++) {
        p[i] = prefix[i];
    }
    dfpow_eval(dataset, c, e, p, start_nonce + (u64)gid, digest, seed, &addr, opening);
    out = digests + gid * 32u;
    for (i = 0; i < 32; i++) {
        out[i] = digest[i];
    }
}
#endif

#endif
