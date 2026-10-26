/* Copyright (c) 2026 Jurjen Stellingwerff
 * SPDX-License-Identifier: LGPL-3.0-or-later
 *
 * The random library's native part, in C99: one PCG64 stream (PCG XSL RR 128/64, the
 * `Lcg128Xsl64` of rand_pcg 0.9), seeded as rand_core's `seed_from_u64` seeds it, so a
 * program seeded under the earlier Rust crate draws the same sequence here.  Built by loft
 * itself (`[c] shim`, with `cc`); bound by the `#c` declarations in src/random.loft.
 *
 * C99 has no threads, so the stream is one per process.  The Rust part kept one per thread,
 * each starting from the default seed; a `par` worker drawing here under `--native` shares
 * this stream with the others and the sequence it sees is not reproducible. */
#include <stdint.h>

typedef struct { uint64_t lo, hi; } lr_u128;

static lr_u128 lr_state;
static lr_u128 lr_incr;
static int lr_seeded = 0;

/* The low 128 bits of a * b. */
static lr_u128 lr_mul(lr_u128 a, lr_u128 b) {
    uint64_t a0 = a.lo & 0xFFFFFFFFu, a1 = a.lo >> 32;
    uint64_t b0 = b.lo & 0xFFFFFFFFu, b1 = b.lo >> 32;
    uint64_t p00 = a0 * b0, p01 = a0 * b1, p10 = a1 * b0, p11 = a1 * b1;
    uint64_t mid = (p00 >> 32) + (p01 & 0xFFFFFFFFu) + (p10 & 0xFFFFFFFFu);
    lr_u128 r;
    r.lo = (p00 & 0xFFFFFFFFu) | (mid << 32);
    r.hi = p11 + (p01 >> 32) + (p10 >> 32) + (mid >> 32);
    r.hi += a.lo * b.hi + a.hi * b.lo;
    return r;
}

static lr_u128 lr_add(lr_u128 a, lr_u128 b) {
    lr_u128 r;
    r.lo = a.lo + b.lo;
    r.hi = a.hi + b.hi + (r.lo < a.lo ? 1u : 0u);
    return r;
}

/* Lcg128Xsl64::step: state = state * MULTIPLIER + increment. */
static void lr_step(void) {
    lr_u128 mul;
    mul.hi = UINT64_C(0x2360ED051FC65DA4);
    mul.lo = UINT64_C(0x4385DF649FCCF645);
    lr_state = lr_add(lr_mul(lr_state, mul), lr_incr);
}

static uint64_t lr_rotr64(uint64_t x, unsigned r) {
    r &= 63u;
    return r ? (x >> r) | (x << (64u - r)) : x;
}

static uint32_t lr_rotr32(uint32_t x, unsigned r) {
    r &= 31u;
    return r ? (x >> r) | (x << (32u - r)) : x;
}

/* Lcg128Xsl64::from_state_incr. */
static void lr_from_state_incr(lr_u128 state, lr_u128 incr) {
    lr_state = state;
    lr_incr = incr;
    lr_state = lr_add(lr_state, lr_incr);
    lr_step();
}

/* SeedableRng::seed_from_u64 (rand_core 0.9): the 32 seed bytes from a PCG32 over the seed,
 * then Lcg128Xsl64::from_seed — state the first 16 bytes little-endian, increment the next
 * 16 with its low bit set. */
static void lr_seed_u64(uint64_t seed) {
    uint64_t words[8];
    uint64_t s = seed;
    int i;
    for (i = 0; i < 8; i++) {
        uint32_t xorshifted, rot;
        s = s * UINT64_C(6364136223846793005) + UINT64_C(11634580027462260723);
        xorshifted = (uint32_t) (((s >> 18) ^ s) >> 27);
        rot = (uint32_t) (s >> 59);
        words[i] = lr_rotr32(xorshifted, rot);
    }
    {
        lr_u128 state, incr;
        state.lo = words[0] | (words[1] << 32);
        state.hi = words[2] | (words[3] << 32);
        incr.lo = (words[4] | (words[5] << 32)) | 1u;
        incr.hi = words[6] | (words[7] << 32);
        lr_from_state_incr(state, incr);
    }
    lr_seeded = 1;
}

/* RngCore::next_u64 (rand_pcg's Lcg128Xsl64): the step, then XSL RR over the new state. */
static uint64_t lr_next_u64(void) {
    unsigned rot;
    uint64_t xsl;
    if (!lr_seeded) lr_seed_u64(12345u);
    lr_step();
    rot = (unsigned) (lr_state.hi >> 58);
    xsl = lr_state.hi ^ lr_state.lo;
    return lr_rotr64(xsl, rot);
}

int64_t lr_rand(int64_t lo, int64_t hi);
void lr_rand_seed(int64_t seed);
int64_t lr_rand_below(int64_t m);

/* rand(lo, hi): a draw in [lo, hi]; null (INT64_MIN) for an empty range. */
int64_t lr_rand(int64_t lo, int64_t hi) {
    uint64_t range, r;
    if (lo == INT64_MIN || hi == INT64_MIN || lo > hi) return INT64_MIN;
    range = (uint64_t) hi - (uint64_t) lo + 1u;
    r = lr_next_u64();
    if (range == 0) return (int64_t) r;
    return (int64_t) ((uint64_t) lo + r % range);
}

void lr_rand_seed(int64_t seed) {
    lr_seed_u64((uint64_t) seed);
}

/* The next draw reduced modulo m — the shuffle's step; 0 for m < 1. */
int64_t lr_rand_below(int64_t m) {
    uint64_t r = lr_next_u64();
    if (m <= 0) return 0;
    return (int64_t) (r % (uint64_t) m);
}
